use bincode::config::{BigEndian, Configuration, Fixint, Limit};
use bincode::{Decode, Encode};
use bytes::{Bytes, BytesMut};
use color_eyre::eyre::eyre;
use color_eyre::Result;
mod fragmentation;
pub use fragmentation::PacketFragmenter;

mod reassembly;
pub use reassembly::Reassembler;

#[derive(Encode, Decode, PartialEq, Debug)]
pub enum MsgKind {
    /// First fragment of a packet with given length
    FirstFragment(u16),
    /// Fragment of a packet that starts at this many bytes back from now.
    Fragment(u16),
    /// Message with explicitly no data in it, the body will be set to the complete nonce of the sender
    Keepalive,
}

/// Outer header of the messages, this is sent in plain text always
#[derive(Encode, Decode, PartialEq, Debug)]
pub struct OuterHeader {
    /// Rolling counter of sent packets, when this wraps the world explodes
    pub seq: u64,
    // A signature that allows the crypto engine to reject obviously invalid packets
    //pub signature: u16,
}

//TODO: add magic number to InnerHeader
///The inner header of messages is protected same as payload data by the same keystream, and is used for reassembly
#[derive(Encode, Decode, PartialEq, Debug)]
pub struct InnerHeader {
    /// Message type selector
    pub msgkind: MsgKind,
}

/// This is to represent the content of the messages prior to validation. Basically, any random bytes should be safe here, and
///  all fields should be considered to contain data specially crafted by cyberdemons.
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

/// Represents message that we actually have validated to be authentic, or have just formed ourselves.
/// SAFETY: while you could build this struct any time, doing so should be done with care as no validation of its content will be done.
#[derive(Debug)]
pub struct TrustedMessage {
    pub outer_header: OuterHeader,
    pub inner_header: InnerHeader,
    pub body: BytesMut,
}

impl TrustedMessage {
    /// This does all necessary validations needed to turn an untrusted msg into trusted one.
    /// This will also remove all encryption layers from the message using the decrypt function provided.
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
    /// Serialize all headers and form a completed payload for UDP transmission. This will apply encryption as well.
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

/// Bincode config for the serialization
type BinCodeConfig = Configuration<BigEndian, Fixint, Limit<128>>;

#[allow(clippy::all)]
#[cfg(test)]
mod tests {

    use super::*;
    use rand::prelude::*;
    use std::sync::atomic::AtomicU64;

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
