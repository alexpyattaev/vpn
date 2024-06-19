use crate::framing::{TrustedMessage, UntrustedMessage};
use bytes::{Bytes, BytesMut};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use color_eyre::eyre::Result;
use std::sync::Arc;

pub fn decode_key_base64<const N: usize>(input: &str) -> Result<[u8; N]> {
    use base64::prelude::BASE64_STANDARD;

    use base64::Engine;
    let d = BASE64_STANDARD.decode(input)?;
    let k = <&[u8; N]>::try_from(&d[0..N])?;
    Ok(*k)
}
pub struct ChaChaParams {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

//#[instrument]
pub fn crypto_encryptor(
    params: Arc<ChaChaParams>,
    input: async_channel::Receiver<TrustedMessage>,
    output: async_channel::Sender<Bytes>,
) {
    let mut cipher = ChaCha20::new(params.key.as_ref().into(), &params.nonce.into());

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
            .serialize(buf, |b| cipher.apply_keystream(b))
            .expect("Serialization should never fail");

        match output.send_blocking(buf) {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Encryptor thread could not send frame, error {}", &e);
                return;
            }
        }
    }
}

pub fn crypto_decryptor(
    params: Arc<ChaChaParams>,
    input: async_channel::Receiver<UntrustedMessage>,
    output: async_channel::Sender<TrustedMessage>,
) {
    let mut cipher = ChaCha20::new(params.key.as_ref().into(), &params.nonce.into());
    loop {
        let msg = match input.recv_blocking() {
            Err(_) => {
                tracing::debug!("No more packets for decryptor to consume, exiting");
                break;
            }
            Ok(msg) => msg,
        };
        cipher.seek(msg.header.seq);

        let msg = match TrustedMessage::from_untrusted_msg(msg, |b| cipher.apply_keystream(b)) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::error!("Deserialization failed with {e}");
                if cfg!(test) {
                    panic!("Deserialization failed");
                }
                continue;
            }
        };

        match output.send_blocking(msg) {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Decryptor thread could not send frame, error {}", &e);
                return;
            }
        }
    }
}

#[allow(clippy::all)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{InnerHeader, MsgKind, OuterHeader};
    use async_channel::{bounded, Receiver, Sender};

    fn make_crypto_pair() -> (
        (
            Sender<TrustedMessage>,
            Receiver<Bytes>,
            tokio::task::JoinHandle<()>,
        ),
        (
            Sender<UntrustedMessage>,
            Receiver<TrustedMessage>,
            tokio::task::JoinHandle<()>,
        ),
    ) {
        let chachaparams = Arc::new(ChaChaParams {
            key: [0x42; 32],
            nonce: [0x42; 12],
        });

        let encryptor = {
            let input_chan = bounded(64);
            let output_chan = bounded(64);
            let kp = chachaparams.clone();
            let jh = tokio::task::spawn_blocking(move || {
                crypto_encryptor(kp, input_chan.1, output_chan.0);
            });
            (input_chan.0, output_chan.1, jh)
        };

        let decryptor = {
            let input_chan = bounded(64);
            let output_chan = bounded(64);
            let kp = chachaparams.clone();
            let jh = tokio::task::spawn_blocking(move || {
                crypto_decryptor(kp, input_chan.1, output_chan.0);
            });
            (input_chan.0, output_chan.1, jh)
        };
        (encryptor, decryptor)
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
        enc.0.send(test_msg).await.unwrap();
        let encrypted = enc.1.recv().await.unwrap();
        dbg!(&encrypted);

        let parsed = UntrustedMessage::from_buffer(BytesMut::from_iter(encrypted.iter())).unwrap();
        dbg!(&parsed);
        dec.0.send(parsed).await.unwrap();
        let decrypted = dec.1.recv().await.unwrap();
        dbg!(&decrypted);
        assert_eq!(decrypted.body, test_data);
    }
}
