use bytes::BytesMut;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use std::sync::Arc;

//#[instrument]
pub fn crypto_worker(
    key: Arc<[u8; 32]>,
    mut input: tokio::sync::mpsc::Receiver<BytesMut>,
    output: tokio::sync::mpsc::Sender<BytesMut>,
) {
    loop {
        let mut b = match input.blocking_recv() {
            None => break,
            Some(b) => b,
        };
        //dbg!("Encrypting buffer with {} bytes", b.len());
        //Todo fetch nonce from packet body
        let nonce = [0x24; 12];
        let mut cipher = ChaCha20::new(key.as_ref().into(), &nonce.into());
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
