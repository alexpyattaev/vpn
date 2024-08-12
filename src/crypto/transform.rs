use crate::framing::{TrustedMessage, UntrustedMessage};
use async_channel::{Receiver, Sender};
use bytes::{Bytes, BytesMut};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use color_eyre::eyre::{Context, Result};

use super::{ChaChaParams, CryptoMode};

pub(super) fn work_encrypt(
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

pub(super) fn work_decrypt(
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

fn apply_keystream_full(b: &mut [u8], c: &mut ChaCha20) {
    c.apply_keystream(b);
}

fn apply_keystream_partial<const N: usize>(b: &mut [u8], c: &mut ChaCha20) {
    let l = b.len().min(N);
    c.apply_keystream(&mut b[..l]);
}
