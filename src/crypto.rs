use crate::framing::{TrustedMessage, UntrustedMessage};
use async_channel::{bounded, Receiver, Sender};
use bytes::{Bytes, BytesMut};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use color_eyre::eyre::{eyre, Context, Result};
use std::num::{NonZeroU8, NonZeroUsize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

struct EncWorkerChannels {
    input_tx: Sender<TrustedMessage>,
    output_rx: Receiver<Bytes>,
}

struct DecWorkerChannels {
    input_tx: Sender<UntrustedMessage>,
    output_rx: Receiver<TrustedMessage>,
}

struct EncryptorInner {
    worker_channels: Vec<EncWorkerChannels>,
    chan_in_idx: AtomicUsize,
    chan_out_idx: AtomicUsize,
}

#[derive(Clone)]
pub struct Encryptor {
    inner: Arc<EncryptorInner>,
}

impl Encryptor {
    pub async fn encrypt(&self, msg: TrustedMessage) -> Result<()> {
        let c = self.inner.chan_in_idx.fetch_add(1, Ordering::SeqCst);
        let c = c % self.inner.worker_channels.len();
        //println!("Sending pkt to thread {c}");
        self.inner.worker_channels[c].input_tx.send(msg).await?;
        Ok(())
    }

    pub async fn get_ready_pkt(&self) -> Result<Bytes> {
        let c = self.inner.chan_out_idx.fetch_add(1, Ordering::SeqCst);
        let c = c % self.inner.worker_channels.len();
        //println!("Fetching pkt from thread {c}");
        Ok(self.inner.worker_channels[c].output_rx.recv().await?)
    }
}

pub struct EncryptorPool {
    pub encryptor: Encryptor,
    workers: Vec<std::thread::JoinHandle<Result<()>>>,
}

impl Drop for EncryptorPool {
    fn drop(&mut self) {
        for wc in self.encryptor.inner.worker_channels.iter() {
            wc.input_tx.close();
            wc.output_rx.close();
        }

        for w in self.workers.drain(..) {
            let r = w
                .join()
                .expect("Encryptor thread panicked please report bug");
            if let Err(m) = r {
                tracing::error!("Thread crashed with error {m}");
            }
        }
    }
}

//TODO: deal with thread limits gracefully
impl EncryptorPool {
    pub fn new(params: ChaChaParams, num_threads: NonZeroUsize) -> Self {
        let mut worker_channels = Vec::with_capacity(num_threads.get());
        let mut workers = Vec::with_capacity(num_threads.get());
        for _ in 0..num_threads.get() {
            let input_chan = bounded(1);
            let output_chan = bounded(1);
            let wc = EncWorkerChannels {
                input_tx: input_chan.0,
                output_rx: output_chan.1,
            };
            worker_channels.push(wc);
            let p = params.clone();
            let jh = std::thread::spawn(|| Self::work(p, input_chan.1, output_chan.0));
            workers.push(jh);
        }

        Self {
            workers,
            encryptor: Encryptor {
                inner: Arc::new(EncryptorInner {
                    chan_in_idx: AtomicUsize::new(0),
                    chan_out_idx: AtomicUsize::new(0),
                    worker_channels,
                }),
            },
        }
    }

    async fn watch_threads(mut self) -> Result<()> {
        'outer: loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            for wt in self.workers.iter_mut() {
                if wt.is_finished() {
                    break 'outer;
                }
            }
        }
        for wc in self.encryptor.inner.worker_channels.iter() {
            wc.input_tx.close();
            wc.output_rx.close();
        }

        for wt in self.workers.drain(..) {
            match wt.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!("{e}");
                }
                Err(e) => {
                    tracing::error!("e");
                }
            }
        }
        Ok(())
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
    pub input: Sender<UntrustedMessage>,
    pub output: Receiver<TrustedMessage>,
    pub worker_input: Receiver<UntrustedMessage>,
    pub worker_output: Sender<TrustedMessage>,
    workers: Vec<std::thread::JoinHandle<Result<()>>>,
}
impl Drop for Decryptor {
    fn drop(&mut self) {
        for w in self.workers.drain(..) {
            let r = w
                .join()
                .expect("Decryptor thread panicked please report bug");
            if let Err(m) = r {
                tracing::error!("Thread crashed with error {m}");
            }
        }
    }
}

impl Decryptor {
    pub fn new(params: ChaChaParams, num_threads: NonZeroUsize) -> Self {
        let input_chan = bounded(num_threads.get());
        let output_chan = bounded(num_threads.get());
        let mut s = Self {
            input: input_chan.0,
            output: output_chan.1,
            worker_input: input_chan.1,
            worker_output: output_chan.0,
            workers: Vec::new(),
        };
        for _ in 0..num_threads.get() {
            let i = s.worker_input.clone();
            let o = s.worker_output.clone();
            let p = params.clone();
            let jh = std::thread::spawn(|| Self::work(p, i, o));
            s.workers.push(jh);
        }
        s
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
    use futures::FutureExt;

    use super::*;
    use crate::framing::{InnerHeader, MsgKind, OuterHeader};

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

        let encpool = EncryptorPool::new(params.clone(), 1);
        let enc = encpool.encryptor.clone();
        let dec = Decryptor::new(params.clone(), 1);

        /*async_scoped::TokioScope::scope_and_block(|s| {
        s.spawn(async {
            enc.spawn().await.unwrap();
        });
        s.spawn(async {
            dec.spawn().await.unwrap();
        });

        s.spawn(async {
            enc.input.send(test_msg).await.unwrap();
            dbg!("sent");
            let encrypted = enc.output.recv().await.unwrap();
            dbg!(&encrypted);

            let parsed =
                UntrustedMessage::from_buffer(BytesMut::from_iter(encrypted.iter())).unwrap();
            dbg!(&parsed);
            dec.input.send(parsed).await.unwrap();
            let decrypted = dec.output.recv().await.unwrap();
            dbg!(&decrypted);
            assert_eq!(decrypted.body, test_data);
        });
        });*/
    }
}
