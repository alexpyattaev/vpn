use crate::framing::{TrustedMessage, UntrustedMessage};
use crate::util::flatten;
use async_channel::{bounded, Receiver, Sender};
use bytes::{Bytes, BytesMut};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use color_eyre::eyre::{eyre, Context, Result};

pub fn decode_key_base64<const N: usize>(input: &str) -> Result<[u8; N]> {
    use base64::prelude::BASE64_STANDARD;

    use base64::Engine;
    let d = BASE64_STANDARD
        .decode(input)
        .wrap_err("Invalid base64 value provided")?;

    let (k, tail) = d
        .as_slice()
        .split_first_chunk::<N>()
        .ok_or_else(|| eyre!("Not enough bytes provided, got {} expected {N}", d.len()))?;

    if !tail.is_empty() {
        return Err(eyre!(
            "Too many bytes provided, got {} expected {N}",
            d.len()
        ));
    }
    Ok(*k)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum CryptoMode {
    Encrypt,
    Sign,
}

#[derive(Clone, Debug)]
pub struct ChaChaParams {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub mode: CryptoMode,
}

pub struct Encryptor {
    params: ChaChaParams,
    pub input: Sender<TrustedMessage>,
    pub output: Receiver<Bytes>,
    worker_input: Receiver<TrustedMessage>,
    worker_output: Sender<Bytes>,
}
impl Encryptor {
    pub fn new(params: ChaChaParams) -> Self {
        let input_chan = bounded(64);
        let output_chan = bounded(64);
        Self {
            params,
            input: input_chan.0,
            output: output_chan.1,
            worker_input: input_chan.1,
            worker_output: output_chan.0,
        }
    }

    pub async fn spawn(&self) -> Result<()> {
        let i = self.worker_input.clone();
        let o = self.worker_output.clone();
        let p = self.params.clone();
        flatten(tokio::task::spawn_blocking(move || Self::work(p, i, o))).await
    }

    fn work(
        params: ChaChaParams,
        input: async_channel::Receiver<TrustedMessage>,
        output: async_channel::Sender<Bytes>,
    ) -> Result<()> {
        let mut cipher = ChaCha20::new(params.key.as_ref().into(), &params.nonce.into());

        let enc = match params.mode {
            CryptoMode::Encrypt => apply_keystream_full,
            CryptoMode::Sign => apply_keystream_partial::<32>,
        };

        loop {
            let msg = match input.recv_blocking() {
                Err(_) => {
                    tracing::debug!("No more data fo encryptor to receive, exiting thread");
                    break;
                }
                Ok(msg) => msg,
            };

            cipher.seek(msg.outer_header.seq);

            //dbg!("Encrypting buffer with {} bytes", b.len());
            let buf = BytesMut::zeroed(msg.buffer_len());
            let buf = msg
                .serialize(buf, |b| enc(b, &mut cipher))
                .wrap_err("Serialization should never fail")?;

            output
                .send_blocking(buf)
                .wrap_err("Encryptor thread could not send frame into channel")?;
        }
        Ok(())
    }
}

fn apply_keystream_full(b: &mut [u8], c: &mut ChaCha20) {
    c.apply_keystream(b);
}

fn apply_keystream_partial<const N: usize>(b: &mut [u8], c: &mut ChaCha20) {
    let l = b.len().min(N);
    c.apply_keystream(&mut b[..l]);
}

pub struct Decryptor {
    params: ChaChaParams,
    pub input: Sender<UntrustedMessage>,
    pub output: Receiver<TrustedMessage>,
    pub worker_input: Receiver<UntrustedMessage>,
    pub worker_output: Sender<TrustedMessage>,
}
impl Decryptor {
    pub fn new(params: ChaChaParams) -> Self {
        let input_chan = bounded(64);
        let output_chan = bounded(64);
        Self {
            params,
            input: input_chan.0,
            output: output_chan.1,
            worker_input: input_chan.1,
            worker_output: output_chan.0,
        }
    }
    pub async fn spawn(&self) -> Result<()> {
        let i = self.worker_input.clone();
        let o = self.worker_output.clone();
        let p = self.params.clone();
        flatten(tokio::task::spawn_blocking(move || Self::work(p, i, o))).await
    }

    fn work(
        params: ChaChaParams,
        input: Receiver<UntrustedMessage>,
        output: Sender<TrustedMessage>,
    ) -> Result<()> {
        let mut cipher = ChaCha20::new(params.key.as_ref().into(), &params.nonce.into());
        let dec = match params.mode {
            CryptoMode::Encrypt => apply_keystream_full,
            CryptoMode::Sign => apply_keystream_partial::<32>,
        };
        loop {
            let msg = match input.recv_blocking() {
                Err(_) => {
                    tracing::debug!("No more packets for decryptor to consume, exiting");
                    break;
                }
                Ok(msg) => msg,
            };
            cipher.seek(msg.header.seq);

            let msg = match TrustedMessage::from_untrusted_msg(msg, |b| dec(b, &mut cipher)) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::error!("Deserialization failed with {e}");
                    if cfg!(test) {
                        panic!("Deserialization failed");
                    }
                    continue;
                }
            };

            output
                .send_blocking(msg)
                .wrap_err("Decryptor thread could not send frame to channel")?;
        }
        Ok(())
    }
}
#[allow(clippy::all)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{InnerHeader, MsgKind, OuterHeader};

    fn make_crypto_pair() -> (Encryptor, Decryptor) {
        let params = ChaChaParams {
            key: [0x42; 32],
            nonce: [0x42; 12],
            mode: CryptoMode::Encrypt,
        };

        (
            Encryptor::new(params.clone()),
            Decryptor::new(params.clone()),
        )
    }

    #[tokio::test]
    async fn one_small_packet() {
        let test_data = BytesMut::from_iter('a' as u8..='z' as u8);
        let test_msg = TrustedMessage {
            outer_header: OuterHeader { seq: 1 },
            inner_header: InnerHeader {
                msgkind: MsgKind::FirstFragment(test_data.len() as u16),
            },
            body: test_data.clone(),
        };
        dbg!(&test_data);
        let (enc, dec) = make_crypto_pair();

        let _ejh = enc.spawn();
        let _djh = dec.spawn();

        enc.input.send(test_msg).await.unwrap();
        let encrypted = enc.output.recv().await.unwrap();
        dbg!(&encrypted);

        let parsed = UntrustedMessage::from_buffer(BytesMut::from_iter(encrypted.iter())).unwrap();
        dbg!(&parsed);
        dec.input.send(parsed).await.unwrap();
        let decrypted = dec.output.recv().await.unwrap();
        dbg!(&decrypted);
        assert_eq!(decrypted.body, test_data);
    }
}
