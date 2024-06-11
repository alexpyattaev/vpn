use crate::framing::{PacketFragmenter, TrustedMessage, UntrustedMessage};
use bytes::{Bytes, BytesMut};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use std::sync::Arc;

pub struct ChaChaParams {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

//#[instrument]
pub fn crypto_encryptor(
    params: Arc<ChaChaParams>,
    mut input: tokio::sync::mpsc::Receiver<BytesMut>,
    output: tokio::sync::mpsc::Sender<Bytes>,
) {
    let mut cipher = ChaCha20::new(params.key.as_ref().into(), &params.nonce.into());
    let mut seq = std::num::Wrapping(0u64);

    loop {
        let msg = match input.blocking_recv() {
            None => break,
            Some(msg) => msg,
        };

        for mut msg in PacketFragmenter::new(msg, 1300) {
            {
                msg.outer_header.seq = seq.0;
                cipher.seek(msg.outer_header.seq);
                seq += 1;
            }

            //dbg!("Encrypting buffer with {} bytes", b.len());
            let buf = BytesMut::zeroed(msg.buffer_len());
            let buf = msg
                .serialize(buf, |b| cipher.apply_keystream(b))
                .expect("Serialization should never fail");

            match output.blocking_send(buf) {
                Ok(_) => {}
                Err(e) => {
                    dbg!(&e);
                    println!("{}", &e.to_string());
                    //panic!("WAAA");
                    return;
                }
            }
        }
    }
}

pub fn crypto_decryptor(
    params: Arc<ChaChaParams>,
    mut input: tokio::sync::mpsc::Receiver<UntrustedMessage>,
    output: tokio::sync::mpsc::Sender<TrustedMessage>,
) {
    let mut cipher = ChaCha20::new(params.key.as_ref().into(), &params.nonce.into());
    loop {
        let msg = match input.blocking_recv() {
            None => break,
            Some(msg) => msg,
        };

        //dbg!("Encrypting buffer with {} bytes", b.len());
        cipher.seek(msg.header.seq);

        let msg = match TrustedMessage::from_untrusted_msg(msg, |b| cipher.apply_keystream(b)) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("Deserialization failed with {e}");
                if cfg!(test) {
                    panic!("Deserialization failed");
                }
                continue;
            }
        };

        match output.blocking_send(msg) {
            Ok(_) => {}
            Err(e) => {
                dbg!(&e);
                println!("{}", &e.to_string());
                //panic!("WAAA");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_crypto_pair() -> (
        (
            tokio::sync::mpsc::Sender<BytesMut>,
            tokio::sync::mpsc::Receiver<Bytes>,
            tokio::task::JoinHandle<()>,
        ),
        (
            tokio::sync::mpsc::Sender<UntrustedMessage>,
            tokio::sync::mpsc::Receiver<TrustedMessage>,
            tokio::task::JoinHandle<()>,
        ),
    ) {
        let chachaparams = Arc::new(ChaChaParams {
            key: [0x42; 32],
            nonce: [0x42; 12],
        });

        let encryptor = {
            let input_chan = tokio::sync::mpsc::channel(64);
            let output_chan = tokio::sync::mpsc::channel(64);
            let kp = chachaparams.clone();
            let jh = tokio::task::spawn_blocking(move || {
                crypto_encryptor(kp, input_chan.1, output_chan.0);
            });
            (input_chan.0, output_chan.1, jh)
        };

        let decryptor = {
            let input_chan = tokio::sync::mpsc::channel(64);
            let output_chan = tokio::sync::mpsc::channel(64);
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
        dbg!(&test_data);
        let (mut enc, mut dec) = make_crypto_pair();
        enc.0.send(test_data.clone()).await.unwrap();
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
