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
