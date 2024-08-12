/// Machinery for cutting packets before transmission for MTU alignment
use super::{InnerHeader, MsgKind, OuterHeader, TrustedMessage};
use crate::counters::COUNTERS;
use bytes::BytesMut;
use std::sync::atomic::AtomicU64;

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
    /// Constructs a fragmenter from a raw network packet for a given target MTU
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
