use bytes::BytesMut;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use std::sync::Arc;


pub fn apply_decryption(key:[u8; 32], nonce:u64, mut buf:BytesMut){
    let mut full_nonce = [0x24u8; 12];
    full_nonce[0..8].copy_from_slice( &nonce.to_be_bytes());
    let mut cipher = ChaCha20::new(key.as_ref().into(), &full_nonce.into());
    cipher.seek(32u64);
    cipher.apply_keystream(buf.as_mut());
    
}

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
