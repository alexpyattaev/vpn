use bytes::BytesMut;

use crate::crypto::Encryptor;
use crate::framing::{InnerHeader, MsgKind};
use crate::framing::{OuterHeader, TrustedMessage};
use tracing::{debug, error, info, warn};

use std::sync::atomic::Ordering;

use tokio::time::Instant;

use color_eyre::Result;

use std::sync::atomic::AtomicBool;

use std::sync::atomic::AtomicU64;

pub static CURRENT_PACKET_TIME: AtomicU64 = AtomicU64::new(0);

pub static LAST_TX_PACKET_TIME: AtomicU64 = AtomicU64::new(0);

pub static LAST_RX_PACKET_TIME: AtomicU64 = AtomicU64::new(0);

pub static CONNECTION_BROKEN: AtomicBool = AtomicBool::new(false);

pub async fn keepalive_ticks(
    tick: tokio::time::Duration,
    timeout: tokio::time::Duration,
    sender: Encryptor,
) -> Result<()> {
    let start = Instant::now();
    let mut interval = tokio::time::interval_at(start, tick);
    let tick_ms = tick.as_millis() as u64;
    let timeout_ticks = timeout.as_millis() as u64 / tick_ms;
    loop {
        let cur_time = CURRENT_PACKET_TIME.fetch_add(1, Ordering::SeqCst) + 1;
        interval.tick().await;
        //dbg!(cur_time, LAST_TX_PACKET_TIME.load(Ordering::SeqCst));
        let since_last_tx = cur_time - LAST_TX_PACKET_TIME.load(Ordering::SeqCst);
        //dbg!(since_last_tx, cur_time, timeout_ticks, tick_ms);
        if since_last_tx > timeout_ticks {
            debug!(
                "Sending keepalive packet, {} ms since last UDP tx",
                since_last_tx * tick_ms
            );
            let msg = TrustedMessage {
                outer_header: OuterHeader {
                    //seq: crate::TX_SEQUENCE_ALLOCATOR.fetch_add(1, Ordering::SeqCst),
                    seq: crate::TX_SEQUENCE_ALLOCATOR.load(Ordering::SeqCst),
                },
                inner_header: InnerHeader {
                    msgkind: MsgKind::Keepalive,
                },
                body: BytesMut::new(),
            };

            sender.process(msg).await?;
        }

        let since_last_rx = cur_time - LAST_RX_PACKET_TIME.load(Ordering::SeqCst);
        let missing_windows = since_last_rx / timeout_ticks;
        match missing_windows {
            0..=2 => {
                let was_broken = CONNECTION_BROKEN.swap(false, Ordering::SeqCst);
                if was_broken {
                    info!("Connection established");
                }
            }
            3..=5 => {
                warn!("Missing keepalives for {} ms", since_last_rx * tick_ms);
            }
            6 => {
                let was_broken = CONNECTION_BROKEN.swap(true, Ordering::SeqCst);
                if !was_broken {
                    error!(
                        "Missing keepalives for {} ms, link broken",
                        since_last_rx * tick_ms
                    );
                }
            }
            7.. => {}
        }
    }
}

pub fn packet_rx() {
    LAST_RX_PACKET_TIME.store(
        CURRENT_PACKET_TIME.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
}

pub fn packet_tx() {
    LAST_TX_PACKET_TIME.store(
        CURRENT_PACKET_TIME.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
}
