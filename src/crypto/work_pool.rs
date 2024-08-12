use super::key_material::ChaChaParams;
use async_channel::{bounded, Receiver, Sender};
use color_eyre::eyre::{eyre, Result};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct WorkerChannels<I, O> {
    input_tx: Sender<I>,
    output_rx: Receiver<O>,
}
impl<I, O> Clone for WorkerChannels<I, O> {
    fn clone(&self) -> Self {
        WorkerChannels {
            input_tx: self.input_tx.clone(),
            output_rx: self.output_rx.clone(),
        }
    }
}

struct PoolInner<T: Clone> {
    worker_channels: Vec<T>,
    chan_in_idx: AtomicUsize,
    chan_out_idx: AtomicUsize,
}

//#[derive(Clone)]
pub struct WorkPool<I: Send, O: Send> {
    inner: Arc<PoolInner<WorkerChannels<I, O>>>,
}
impl<I: Send, O: Send> Clone for WorkPool<I, O> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<I: Send, O: Send> WorkPool<I, O> {
    pub async fn process(&self, msg: I) -> Result<()> {
        let c = self.inner.chan_in_idx.fetch_add(1, Ordering::SeqCst);
        let c = c % self.inner.worker_channels.len();
        //println!("Sending pkt to thread {c}");
        self.inner.worker_channels[c]
            .input_tx
            .send(msg)
            .await
            .map_err(|e| {
                eyre!(
                    "Encountered error while sending msg across threads: {}",
                    e.to_string()
                )
            })?;
        Ok(())
    }

    pub async fn get_ready_pkt(&self) -> Result<O> {
        let c = self.inner.chan_out_idx.fetch_add(1, Ordering::SeqCst);
        let c = c % self.inner.worker_channels.len();
        //println!("Fetching pkt from thread {c}");
        Ok(self.inner.worker_channels[c].output_rx.recv().await?)
    }
}

pub struct ThreadWorkPool<I: Send, O: Send> {
    pub workpool: WorkPool<I, O>,
    workers: Vec<std::thread::JoinHandle<Result<()>>>,
}

impl<I: Send, O: Send> Drop for ThreadWorkPool<I, O> {
    fn drop(&mut self) {
        for wc in self.workpool.inner.worker_channels.iter() {
            wc.input_tx.close();
            wc.output_rx.close();
        }

        for w in self.workers.drain(..) {
            let r = w.join().expect("Worker thread panicked please report bug");
            if let Err(m) = r {
                tracing::error!("Thread crashed with error {m}");
            }
        }
    }
}

//TODO: deal with thread limits gracefully
impl<I: Send + 'static, O: Send + 'static> ThreadWorkPool<I, O> {
    pub fn new<W>(params: ChaChaParams, num_threads: NonZeroUsize, work_fn: W) -> Self
    where
        W: Clone + Send + Sync + Fn(ChaChaParams, Receiver<I>, Sender<O>) -> Result<()> + 'static,
    {
        let mut worker_channels = Vec::with_capacity(num_threads.get());
        let mut workers = Vec::with_capacity(num_threads.get());
        for _ in 0..num_threads.get() {
            let input_chan = bounded(1);
            let output_chan = bounded(1);
            let wc = WorkerChannels {
                input_tx: input_chan.0,
                output_rx: output_chan.1,
            };
            worker_channels.push(wc);
            {
                let p = params.clone();
                let i = input_chan.1.clone();
                let o = output_chan.0.clone();
                let w = work_fn.clone();
                let jh = std::thread::spawn(move || w(p, i, o));
                workers.push(jh);
            }
        }

        Self {
            workers,
            workpool: WorkPool {
                inner: Arc::new(PoolInner {
                    chan_in_idx: AtomicUsize::new(0),
                    chan_out_idx: AtomicUsize::new(0),
                    worker_channels,
                }),
            },
        }
    }

    pub async fn watch_threads(mut self) -> Result<()> {
        'outer: loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            for wt in self.workers.iter_mut() {
                if wt.is_finished() {
                    break 'outer;
                }
            }
        }
        for wc in self.workpool.inner.worker_channels.iter() {
            wc.input_tx.close();
            wc.output_rx.close();
        }

        for wt in self.workers.drain(..) {
            match wt.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!("{e}");
                }
                Err(_e) => {
                    tracing::error!("Error joining");
                }
            }
        }
        Ok(())
    }
}
