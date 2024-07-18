use std::sync::atomic::Ordering;
use std::time::Duration;
use std::{io::ErrorKind, sync::atomic::AtomicU64};

use crate::traits::{ExtranetPacketInterface, IntranetPacketInterface};
use bytes::Bytes;
pub struct TrafGen {
    pub packet_size: usize,
    pub max_backlog: usize,
    pub seq_sent: AtomicU64,
    pub seq_recv: AtomicU64,
}

impl TrafGen {
    pub fn new(packet_size: usize, max_backlog: usize) -> Self {
        Self {
            packet_size,
            max_backlog,
            seq_recv: AtomicU64::new(0),
            seq_sent: AtomicU64::new(0),
        }
    }
}
impl IntranetPacketInterface for TrafGen {
    //called when we try to read a packet to be sent into VPN
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        if cfg!(feature = "packet_tracing") {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let seq = self
            .seq_sent
            .fetch_add(self.packet_size as u64, Ordering::SeqCst);
        buf[0..8].copy_from_slice(&seq.to_be_bytes());
        assert!(
            buf.len() > self.packet_size,
            "Insufficient buffer for packet size specified"
        );
        let rx_seq = self.seq_recv.load(Ordering::SeqCst);
        if seq < rx_seq {
            panic!("WAT");
        }

        if seq - rx_seq > (self.packet_size * self.max_backlog) as u64 {
            //tokio::task::yield_now().await;
            tokio::time::sleep(tokio::time::Duration::from_nanos(100)).await;
        }
        /*if seq > self.packet_size as u64 * 10000 {
        panic!("OMG");
        }*/
        Ok(self.packet_size)
    }

    // Called when we have a packet to be sent into internal network
    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let tx_seq = self.seq_sent.load(Ordering::SeqCst);
        let pkt_seq = {
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[0..8]);
            u64::from_be_bytes(b)
        };
        let rx_seq = self
            .seq_recv
            .fetch_add(self.packet_size as u64, Ordering::SeqCst);

        assert!(
            rx_seq <= tx_seq,
            "Can not receive packets that were never sent!"
        );
        /*assert_eq!(
        rx_seq, pkt_seq,
        "Received packet sequence number must match expected value, reordering detected!"
        );*/

        Ok(self.packet_size)
    }
}

pub struct WireEmulator {
    tx: async_channel::Sender<Bytes>,
    rx: async_channel::Receiver<Bytes>,
}

impl WireEmulator {
    pub fn new(max_pkts: usize) -> Self {
        let (tx, rx) = async_channel::bounded(max_pkts);
        Self { tx, rx }
    }
}

impl ExtranetPacketInterface for WireEmulator {
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes = self
            .rx
            .recv()
            .await
            .map_err(|_e| std::io::Error::new(ErrorKind::Other, "Stuff died"))?;
        buf[..bytes.len()].copy_from_slice(bytes.as_ref());
        Ok(bytes.len())
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes = Bytes::copy_from_slice(buf);
        self.tx
            .send(bytes)
            .await
            .map_err(|_e| std::io::Error::new(ErrorKind::Other, "Stuff died"))?;
        Ok(buf.len())
    }
}
