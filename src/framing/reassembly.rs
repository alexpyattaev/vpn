use crate::counters::COUNTERS;
use crate::framing::{MsgKind, TrustedMessage};
use bytes::BytesMut;
use color_eyre::{eyre::eyre, Result};
use std::fmt::Debug;
use std::sync::atomic::Ordering;

use tracing::{debug, error, warn};

///Represents the piece of the reassembly pipeline
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Fragment {
    seq: u64,
    bytes: BytesMut,
}

impl Debug for Fragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fragment")
            .field("seq", &self.seq)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

impl From<TrustedMessage> for Fragment {
    fn from(m: TrustedMessage) -> Self {
        Fragment {
            seq: m.outer_header.seq,
            bytes: m.body,
        }
    }
}

#[derive(Default, Debug)]
pub struct Pipeline {
    seq_first: u64,
    seq_last: Option<u64>,
    pub creation_time: u64,
    fragments: sorted_vec::SortedSet<Fragment>,
    is_complete: bool,
}

impl Pipeline {
    pub fn seq_last(&self) -> Option<u64> {
        debug_assert!(!self.is_empty());
        self.seq_last
    }
    pub fn seq_first(&self) -> u64 {
        debug_assert!(!self.is_empty());
        self.seq_first
    }

    ///pushes a trusted message into the pipeline
    pub fn add_msg(&mut self, m: TrustedMessage) -> Result<Option<u64>> {
        COUNTERS.fragments_rx.pkt(m.body.len());
        if self.is_empty() {
            self.creation_time = crate::keepalive::CURRENT_PACKET_TIME.load(Ordering::SeqCst);
        }
        match m.inner_header.msgkind {
            MsgKind::FirstFragment(len) => {
                self.seq_first = m.outer_header.seq;
                self.seq_last = Some(self.seq_first + len as u64);
                self.fragments.push(Fragment::from(m));
            }
            MsgKind::Fragment(offset) => {
                let start_seq = m.outer_header.seq - offset as u64;
                if self.is_empty() {
                    self.seq_first = start_seq;
                } else if self.seq_first != start_seq {
                    unreachable!("This should not be possible if this is called correctly");
                    //return Err(eyre!("Sequence mismatch"));
                }
                self.fragments.push(Fragment::from(m));
            }
            MsgKind::Keepalive => unreachable!(),
        }
        self.check_complete();
        if self.is_complete() {
            Ok(Some(self.seq_first))
        } else {
            Ok(None)
        }
    }

    ///Extracts assembled frame from the pipeline
    pub fn extract_and_clear(&mut self) -> BytesMut {
        debug_assert!(self.is_complete());
        let mut res = BytesMut::new();
        for p in self.fragments.iter() {
            res.extend_from_slice(&p.bytes)
        }
        self.clear();
        res
    }

    pub fn clear(&mut self) {
        self.fragments.clear();
        self.seq_last = None;
        self.seq_first = 0;
        self.creation_time = 0;
        self.is_complete = false;
    }

    pub fn is_empty(&self) -> bool {
        self.fragments.is_empty()
    }
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    pub fn check_complete(&mut self) {
        let seq_last = match self.seq_last {
            None => {
                self.is_complete = false;
                return;
            }
            Some(x) => x,
        };

        let mut need_seq = self.seq_first;
        for f in self.fragments.as_slice() {
            if f.seq != need_seq {
                break;
            }
            need_seq += f.bytes.len() as u64;
        }
        self.is_complete = need_seq == seq_last;
    }
}

/// Reconstructs the frames sent from the peer. Keeps track of sequence numbers and fragmentation.
pub struct Reassembler<const N: usize> {
    seq_assembled: u64,
    pipelines: [Pipeline; N],
}

impl<const N: usize> Reassembler<N> {
    pub fn new(init_seq: u64) -> Self {
        Reassembler {
            seq_assembled: init_seq,
            pipelines: std::array::from_fn(|_| Default::default()),
        }
    }
    pub fn min_seq(&self) -> u64 {
        self.seq_assembled
    }

    pub fn add_msg(&mut self, m: TrustedMessage) -> Result<Option<()>> {
        let first_seq = match m.inner_header.msgkind {
            MsgKind::FirstFragment(_o) => m.outer_header.seq,
            MsgKind::Fragment(o) => m.outer_header.seq - o as u64,
            MsgKind::Keepalive => unreachable!(),
        };

        if let Some(seq) = self.add_frag(first_seq, m)? {
            // deal with having a fully assembled frame ready to go
            if seq < self.seq_assembled {
                //TODO: deal with this securely somehow
                warn!("Decoded packet with sequence number below current sequence number, assuming peer reset");
                self.seq_assembled = seq;
            }
            // there is at least one packet "ready to go"
            if seq == self.seq_assembled {
                return Ok(Some(()));
            }
        }
        Ok(None)
    }

    // check if any pipeline has a packet that can be released
    pub fn poll(&mut self) -> Option<(u64, BytesMut)> {
        //self.free_pipelines();
        for pl in self.pipelines.iter_mut().filter(|p| p.is_complete()) {
            let seq = pl.seq_first();
            if seq == self.seq_assembled {
                let msg = pl.extract_and_clear();
                self.seq_assembled += msg.len() as u64;
                /*debug!(
                "Extracting packet at seq {}, new seq is {} ",
                seq, self.seq_assembled
                );*/
                return Some((seq, msg));
            }
        }
        None
    }

    pub fn free_pipelines(&self) {
        let mut empty = 0;
        let mut partial = 0;
        let mut complete = 0;
        for pl in self.pipelines.iter() {
            if pl.is_empty() {
                empty += 1;
            } else if pl.is_complete() {
                complete += 1;
            } else {
                partial += 1;
            }
        }
        debug!("Pipelines: Empty {empty} Partial {partial} Complete {complete}");
    }

    fn add_frag(&mut self, first_seq: u64, m: TrustedMessage) -> Result<Option<u64>> {
        //self.free_pipelines();
        //Look for non-empty pipelines first
        for pl in self.pipelines.iter_mut().filter(|p| !p.is_empty()) {
            if pl.seq_first() == first_seq {
                return pl.add_msg(m);
            }
        }
        //Look for any empty pipeline
        if let Some(pl) = self.pipelines.iter_mut().find(|p| p.is_empty()) {
            return pl.add_msg(m);
        }
        error!("No empty pipelines, clearing out!");
        //self.free_pipelines();
        panic!();
        for pl in self.pipelines.iter_mut().filter(|p| !p.is_empty()) {
            pl.clear();
        }
        self.seq_assembled = first_seq;
        //Look for any empty pipeline again
        if let Some(pl) = self.pipelines.iter_mut().find(|p| p.is_empty()) {
            return pl.add_msg(m);
        }
        // self.free_pipelines();
        // dbg!(first_seq, &m);
        // dbg!(self.seq_assembled);
        // dbg!(&self.pipelines);
        //panic!("WAAAAA");
        Err(eyre!("No pipeline for reassembly found!"))
    }

    pub fn kill_oldest(&mut self) {
        /*     let mut seq_min = u64::MAX;
        let mut idx = 0;
        for (i, pl) in self
            .pipelines
            .iter_mut()
            .enumerate()
            .filter(|(_, p)| !p.is_empty())
        {
            if pl.seq_first() < seq_min {
                seq_min = pl.seq_first();
                idx = i;
            }
        }
        if seq_min == u64::MAX {
            panic!("WAT");
        }
        self.pipelines[idx].clear();

        let mut seq_min = u64::MAX;
        for pl in self.pipelines.iter().filter(|p| !p.is_empty()) {
            if pl.seq_first() < seq_min {
                seq_min = pl.seq_first();
            }
        }
        self.seq_assembled = seq_min;*/
    }

    pub fn check_stale(&mut self, timestamp_min: u64) {
        let mut seq_min = self.seq_assembled;
        for pl in self.pipelines.iter_mut().filter(|p| !p.is_empty()) {
            seq_min = seq_min.max(pl.seq_first());
            if pl.creation_time < timestamp_min {
                dbg!(&pl);
                debug!(
                    "Stale assembly pipeline with creation time {} for seq {} detected, clearing",
                    pl.creation_time,
                    pl.seq_first()
                );
                pl.clear();
            }
        }

        for pl in self.pipelines.iter_mut().filter(|p| !p.is_empty()) {
            seq_min = pl.seq_first().min(seq_min);
        }
        self.seq_assembled = seq_min;
    }
}
