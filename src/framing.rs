use std::sync::atomic::AtomicU64;

use crate::counters::COUNTERS;
use bincode::config::{BigEndian, Configuration, Fixint, Limit};
use bincode::{Decode, Encode};
use bytes::{Bytes, BytesMut};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use tracing::{debug, error, warn};

#[derive(Encode, Decode, PartialEq, Debug)]
pub enum MsgKind {
    /// First fragment of a packet with given length
    FirstFragment(u16),
    /// Fragment of a packet that starts at this many bytes back from now.
    Fragment(u16),
    /// Message with explicitly no data in it, the body will be set to the complete nonce of the sender
    Keepalive,
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct OuterHeader {
    /// Rolling counter of sent packets, when this wraps the world explodes
    pub seq: u64,
    // A signature that allows the crypto engine to reject obviously invalid packets
    //pub signature: u16,
}

//TODO: add magic number to InnerHeader
#[derive(Encode, Decode, PartialEq, Debug)]
pub struct InnerHeader {
    /// Message type selector
    pub msgkind: MsgKind,
}

#[derive(Debug)]
pub struct UntrustedMessage {
    pub header: OuterHeader,
    pub body: BytesMut,
}

impl UntrustedMessage {
    /// Parse a raw untrusted UDP frame so it can be passed off to decryptor thread.
    /// At this point we have no idea if the frame is valid or not, obviously.
    pub fn from_buffer(mut buf: bytes::BytesMut) -> Result<UntrustedMessage> {
        let config = BinCodeConfig::default();

        let (header, len): (OuterHeader, usize) = bincode::decode_from_slice(&buf, config)?;
        if header.seq == 0 {
            return Err(eyre!("Null sequence number is not allowed"));
        }
        let body = buf.split_off(len);
        Ok(UntrustedMessage { header, body })
    }
}

#[derive(Debug)]
pub struct TrustedMessage {
    pub outer_header: OuterHeader,
    pub inner_header: InnerHeader,
    pub body: BytesMut,
}

impl TrustedMessage {
    pub fn from_untrusted_msg<F>(mut msg: UntrustedMessage, decrypt: F) -> Result<Self>
    where
        F: FnOnce(&mut [u8]),
    {
        decrypt(&mut msg.body);

        let config = BinCodeConfig::default();

        let (inner_header, len): (InnerHeader, usize) =
            bincode::decode_from_slice(&msg.body, config)?;

        let body = msg.body.split_off(len);

        Ok(TrustedMessage {
            outer_header: msg.header,
            inner_header,
            body,
        })
    }
    ///Serialize all headers and form a completed payload for UDP transmission
    pub fn serialize<F>(self, mut buf: BytesMut, encrypt: F) -> Result<Bytes>
    where
        F: FnOnce(&mut [u8]),
    {
        let config = BinCodeConfig::default();
        let inner_header_start = bincode::encode_into_slice(self.outer_header, &mut buf, config)?;
        let body_start = inner_header_start
            + bincode::encode_into_slice(
                self.inner_header,
                &mut buf[inner_header_start..],
                config,
            )?;
        let end = body_start + self.body.len();
        buf[body_start..end].copy_from_slice(&self.body);
        encrypt(&mut buf[inner_header_start..end]);
        buf.truncate(end);
        Ok(buf.freeze())
    }

    pub fn buffer_len(&self) -> usize {
        self.body.len() + 64
    }
}

pub struct PacketFragmenter {
    // current remaining packet data
    raw_packet_data: BytesMut,
    // how many bytes precede this fragment's start in the packet
    frag_backptr: usize,
    // desired fragment size for this packet. This will always ensure that the fragments are smaller than MTU, and will try to keep them same length
    fragsize: usize,
    // sequence for next fragment
    seq: u64,
    // total number of fragments left to make
    fragments_left: usize,
}

impl PacketFragmenter {
    pub fn new(pkt: BytesMut, mtu: usize, base_seq: &AtomicU64) -> Self {
        let base_seq = base_seq.fetch_add(pkt.len() as u64, std::sync::atomic::Ordering::SeqCst);
        let nfrag = pkt.len().div_ceil(mtu);
        let fragsize = pkt.len().div_ceil(nfrag).min(mtu);
        Self {
            raw_packet_data: pkt,
            fragsize,
            frag_backptr: 0,
            seq: base_seq,
            fragments_left: nfrag,
        }
    }
}

impl Iterator for PacketFragmenter {
    type Item = TrustedMessage;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fragments_left == 0 {
            return None;
        }
        self.fragments_left -= 1;
        let next_len = self.raw_packet_data.len().min(self.fragsize);

        let msgkind = match self.frag_backptr {
            // first fragment, indicate full length of the entire packet
            0 => MsgKind::FirstFragment(self.raw_packet_data.len() as u16),
            //other fragments, indicate the backoffset to the beginning of the packet
            _ => {
                COUNTERS.fragments_tx.pkt(next_len);
                MsgKind::Fragment(self.frag_backptr as u16)
            }
        };
        self.frag_backptr += next_len;

        let msg = TrustedMessage {
            outer_header: OuterHeader { seq: self.seq },
            inner_header: InnerHeader { msgkind },
            body: self.raw_packet_data.split_to(next_len),
        };
        self.seq += next_len as u64;
        Some(msg)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.fragments_left, Some(self.fragments_left))
    }
}

impl std::iter::ExactSizeIterator for PacketFragmenter {
    fn len(&self) -> usize {
        self.fragments_left
    }
}

type BinCodeConfig = Configuration<BigEndian, Fixint, Limit<128>>;

mod pipeline {
    use crate::counters::COUNTERS;
    use crate::framing::{MsgKind, TrustedMessage};
    use bytes::BytesMut;
    use color_eyre::Result;
    use std::fmt::Debug;
    use std::sync::atomic::Ordering;
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    pub struct Fragment {
        pub seq: u64,
        pub bytes: BytesMut,
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
}
use pipeline::Pipeline;
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

#[allow(clippy::all)]
#[cfg(test)]
mod tests {

    use super::*;
    use rand::prelude::*;

    #[test]
    fn fragmented_packet() -> Result<()> {
        let mtu = 10;
        let initial_seq = 42;
        for n in [9, 10, 12, 20, 21, 30, 35] {
            let seq = AtomicU64::new(initial_seq);
            let test_data = BytesMut::from_iter(('a' as u8..='z' as u8).cycle().take(n));
            let mut fragmenter = PacketFragmenter::new(test_data.clone(), mtu, &seq);
            let mut assembler = Reassembler::<5>::new(initial_seq);
            loop {
                let m = fragmenter.next().unwrap();
                println!("Formed fragment {:?}", &m);
                match assembler.add_msg(m) {
                    Ok(Some(m)) => break,
                    Ok(None) => {
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            let (rs, assembled) = assembler.poll().unwrap();
            dbg!(rs);
            assert_eq!(
                rs, initial_seq,
                "Sequence number of recovered packet at length {n}"
            );
            assert_eq!(
                assembled, test_data,
                "Assembled data does not match sent at length {n}"
            );
        }
        Ok(())
    }

    #[test]
    fn out_of_order_fragmented() -> Result<()> {
        let mtu = 10;
        let initial_seq = 42;

        for n in [9, 10, 12, 20, 21, 30, 35] {
            let seq = AtomicU64::new(initial_seq);
            let test_data1 = BytesMut::from_iter(('a' as u8..='z' as u8).cycle().take(n));
            let test_data2 = BytesMut::from_iter(('A' as u8..='Z' as u8).cycle().take(n));

            let mut fragments: Vec<TrustedMessage> =
                PacketFragmenter::new(test_data1.clone(), mtu, &seq).collect();
            fragments.extend(PacketFragmenter::new(test_data2.clone(), mtu, &seq));

            {
                let mut rng = rand::thread_rng();
                fragments.shuffle(&mut rng);
            }

            let mut assembler = Reassembler::<4>::new(initial_seq);
            let mut assembled = vec![];
            for f in fragments {
                match assembler.add_msg(f) {
                    Ok(Some(_)) => {
                        let m = assembler.poll().unwrap();
                        assembled.push(m);
                    }
                    Ok(None) => {
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            loop {
                match assembler.poll() {
                    Some(msg) => assembled.push(msg),
                    None => break,
                }
            }
            dbg!(&assembled);
            for (rx, tx) in assembled.iter().zip([test_data1, test_data2]) {
                assert_eq!(tx, rx.1, "mismatch at seq {}", rx.0);
            }
        }
        Ok(())
    }
}
