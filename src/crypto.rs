use crate::framing::TrustedMessage;
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
    mut input: tokio::sync::mpsc::Receiver<TrustedMessage>,
    output: tokio::sync::mpsc::Sender<Bytes>,
) {
    let mut cipher = ChaCha20::new(params.key.as_ref().into(), &params.nonce.into());
    let mut seq = std::num::Wrapping(0u64);
    loop {
        let mut b = match input.blocking_recv() {
            None => break,
            Some(b) => b,
        };

        //dbg!("Encrypting buffer with {} bytes", b.len());
        cipher.seek(seq.into());

        cipher.apply_keystream(b.as_mut());
        match output.blocking_send(b) {
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
