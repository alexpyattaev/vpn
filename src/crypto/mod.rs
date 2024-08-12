use crate::framing::{TrustedMessage, UntrustedMessage};
use bytes::Bytes;
use std::num::NonZeroUsize;

mod key_material;
mod transform;
mod work_pool;
pub use key_material::{ChaChaParams, CryptoMode};
use work_pool::{ThreadWorkPool, WorkPool};

pub type Encryptor = WorkPool<TrustedMessage, Bytes>;
pub fn make_encryptor(
    params: ChaChaParams,
    num_threads: NonZeroUsize,
) -> ThreadWorkPool<TrustedMessage, Bytes> {
    ThreadWorkPool::new(params, num_threads, transform::work_encrypt)
}

pub fn make_decryptor(
    params: ChaChaParams,
    num_threads: NonZeroUsize,
) -> ThreadWorkPool<UntrustedMessage, TrustedMessage> {
    ThreadWorkPool::new(params, num_threads, transform::work_decrypt)
}

pub type Decryptor = WorkPool<UntrustedMessage, TrustedMessage>;

#[allow(clippy::all)]
#[cfg(test)]
mod tests {

    use super::*;
    use crate::framing::{InnerHeader, MsgKind, OuterHeader};
    use bytes::BytesMut;
    fn make_bogus_params() -> ChaChaParams {
        ChaChaParams {
            key: [0x42; 32],
            nonce: [0x42; 12],
            mode: CryptoMode::Encrypt,
        }
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
        let params = make_bogus_params();

        let encpool = make_encryptor(params.clone(), NonZeroUsize::new(1).unwrap());
        let enc = encpool.workpool.clone();
        let decpool = make_decryptor(params.clone(), NonZeroUsize::new(1).unwrap());
        let dec = decpool.workpool.clone();

        enc.process(test_msg).await.unwrap();
        dbg!("sent");
        let encrypted = enc.get_ready_pkt().await.unwrap();
        dbg!(&encrypted);

        let parsed = UntrustedMessage::from_buffer(BytesMut::from_iter(encrypted.iter())).unwrap();
        dbg!(&parsed);
        dec.process(parsed).await.unwrap();
        let decrypted = dec.get_ready_pkt().await.unwrap();
        dbg!(&decrypted);
        assert_eq!(decrypted.body, test_data);
    }
}
