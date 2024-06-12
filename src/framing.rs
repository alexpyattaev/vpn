use crate::counters::COUNTERS;
use bincode::config::{BigEndian, Configuration, Fixint, Limit};
use bincode::{Decode, Encode};
use bytes::{Bytes, BytesMut};
use color_eyre::eyre::eyre;
use color_eyre::Result;

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
    //pub signature:u8,
}

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
    // MTU for fragmentation
    mtu: usize,
}

impl PacketFragmenter {
    pub fn new(pkt: BytesMut, mtu: usize) -> Self {
        Self {
            raw_packet_data: pkt,
            mtu,
            frag_backptr: 0,
        }
    }

    fn next_fragment_len(&self) -> usize {
        if self.raw_packet_data.len() > self.mtu {
            return self.mtu;
        }
        return self.raw_packet_data.len();
    }
}

impl Iterator for PacketFragmenter {
    type Item = TrustedMessage;

    fn next(&mut self) -> Option<Self::Item> {
        let next_len = self.next_fragment_len();
        if next_len == 0 {
            return None;
        }

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
            outer_header: OuterHeader { seq: 0 },
            inner_header: InnerHeader { msgkind },
            body: self.raw_packet_data.split_to(next_len),
        };
        Some(msg)
    }
}

type BinCodeConfig = Configuration<BigEndian, Fixint, Limit<128>>;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Fragment {
    pub seq: u64,
    pub bytes: BytesMut,
}

impl From<TrustedMessage> for Fragment {
    fn from(m: TrustedMessage) -> Self {
        Fragment {
            seq: m.outer_header.seq,
            bytes: m.body,
        }
    }
}

#[derive(Default)]
struct Pipeline {
    seq_first: u64,
    seq_last: Option<u64>,
    fragments: sorted_vec::SortedSet<Fragment>,
}

impl Pipeline {
    pub fn add_msg(&mut self, m: TrustedMessage) -> Result<Option<Vec<Fragment>>> {
        match m.inner_header.msgkind {
            MsgKind::FirstFragment(o) => {
                self.seq_first = m.outer_header.seq;
                self.seq_last = Some(self.seq_first + o as u64);
                self.fragments.push(Fragment::from(m));
            }
            MsgKind::Fragment(o) => {
                COUNTERS.fragments_rx.pkt(m.body.len());
                if self.fragments.is_empty() {
                    self.seq_first = m.outer_header.seq;
                } else if self.seq_first != (m.outer_header.seq - o as u64) {
                    return Err(eyre!("Sequence mismatch"));
                }
                self.fragments.push(Fragment::from(m));
            }
            MsgKind::Keepalive => unreachable!(),
        }
        if self.is_complete() {
            let mut x = sorted_vec::SortedSet::new();
            std::mem::swap(&mut self.fragments, &mut x);
            let res = Some(x.into_vec());
            self.clear();
            Ok(res)
        } else {
            Ok(None)
        }
    }

    pub fn clear(&mut self) {
        self.fragments.clear();
        self.seq_last = None;
        self.seq_first = 0;
    }
    pub fn is_empty(&self) -> bool {
        return self.fragments.is_empty();
    }

    pub fn is_complete(&self) -> bool {
        let seq_last = match self.seq_last {
            None => return false,
            Some(x) => x,
        };

        let mut need_seq = self.seq_first;
        for f in self.fragments.as_slice() {
            if f.seq != need_seq {
                break;
            }
            need_seq += f.bytes.len() as u64;
        }
        return need_seq == seq_last;
    }
}

/// Reconstructs the frames sent from the peer. Keeps track of sequence numbers and fragmentation.
pub struct Reassembler<const N: usize> {
    pipelines: [Pipeline; N],
}

impl<const N: usize> Reassembler<N> {
    pub fn new() -> Self {
        Reassembler {
            pipelines: std::array::from_fn(|_| Default::default()),
        }
    }

    pub fn add_msg(&mut self, m: TrustedMessage) -> Result<Option<Vec<Fragment>>> {
        let first_seq = match m.inner_header.msgkind {
            MsgKind::FirstFragment(_o) => m.outer_header.seq,
            MsgKind::Fragment(o) => m.outer_header.seq - o as u64,
            MsgKind::Keepalive => unreachable!(),
        };

        //Look for non-empty pipelines first
        for pl in self.pipelines.iter_mut() {
            if !pl.is_empty() && pl.seq_first == first_seq {
                return pl.add_msg(m);
            }
        }
        //Look for any empty pipeline
        for pl in self.pipelines.iter_mut() {
            if pl.is_empty() {
                return pl.add_msg(m);
            }
        }

        Err(eyre!("No pipeline for reassembly found!"))
    }
}
