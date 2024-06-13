use color_eyre::Result;
use std::sync::atomic::AtomicUsize;
use tokio::time::{Duration, Instant, Interval};

#[derive(Default, Debug)]
pub struct Counters {
    pub pkt: AtomicUsize,
    pub bytes: AtomicUsize,
}

impl std::fmt::Display for Counters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Packets: {:#?}, Bytes: {:#?}", self.pkt, self.bytes)
    }
}

mod unit_fmt {
    pub use si_scale::helpers::bytes;
    use si_scale::scale_fn;
    // defines the `bits_per_sec()` function
    scale_fn!(bits_per_sec,
              base: B1000,
              constraint: UnitAndAbove,
              mantissa_fmt: "{:.3}",
              groupings: '_',
              unit: "bit/s",
              doc: "Return a string with the value and its si-scaled unit of bit/s.");
}

impl Counters {
    const fn new() -> Self {
        Self {
            pkt: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
        }
    }

    pub fn pkt(&self, size: usize) {
        self.pkt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.bytes
            .fetch_add(size, std::sync::atomic::Ordering::Relaxed);
    }
    fn prep_display(&self, elapsed: Duration) -> impl std::fmt::Display {
        struct CountersDispl {
            d: Duration,
            pkt: usize,
            bytes: usize,
        }

        impl std::fmt::Display for CountersDispl {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let t = self.d.as_secs_f32();

                write!(
                    f,
                    "Packets: {:#?} ({:#?}/s), Data: {} ({})",
                    self.pkt,
                    self.pkt as f32 / t,
                    unit_fmt::bytes(self.bytes as f64),
                    unit_fmt::bits_per_sec(self.bytes as f32 * 8.0 / t)
                )
            }
        }

        let pkt = self.pkt.load(std::sync::atomic::Ordering::Relaxed);
        let bytes = self.bytes.load(std::sync::atomic::Ordering::Relaxed);
        CountersDispl {
            d: elapsed,
            pkt: pkt,
            bytes: bytes,
        }
    }
}

#[derive(Debug, Default)]
pub struct CountersAll {
    pub tap_tx: Counters,
    pub tap_rx: Counters,
    pub udp_rx: Counters,
    pub udp_tx: Counters,

    pub udp_invalid: Counters,

    pub fragments_tx: Counters,
    pub fragments_rx: Counters,
}

pub trait Wtf: tokio::io::AsyncWriteExt + Unpin {}
impl<T> Wtf for T where T: tokio::io::AsyncWriteExt + Unpin {}
impl CountersAll {
    pub const fn new() -> Self {
        Self {
            udp_tx: Counters::new(),
            tap_tx: Counters::new(),
            tap_rx: Counters::new(),
            udp_rx: Counters::new(),
            udp_invalid: Counters::new(),
            fragments_tx: Counters::new(),
            fragments_rx: Counters::new(),
        }
    }
    pub async fn write_as_text(
        &self,
        elapsed: tokio::time::Duration,
        f: &mut impl Wtf,
    ) -> Result<()> {
        let state =
            if crate::keepalive::CONNECTION_BROKEN.load(std::sync::atomic::Ordering::Relaxed) {
                "DOWN"
            } else {
                "UP"
            };
        let s = format!(
            r"Uptime {elapsed:#?} Link {state}
UDP TX {}
UDP RX {}
TAP TX {}
TAP RX {}
",
            self.udp_tx.prep_display(elapsed),
            self.udp_rx.prep_display(elapsed),
            self.tap_tx.prep_display(elapsed),
            self.tap_rx.prep_display(elapsed)
        );
        f.write_all(s.as_bytes()).await?;

        Ok(())
    }
}

pub static COUNTERS: CountersAll = CountersAll::new();

pub async fn watch_counters(mut interval: Interval) -> Result<()> {
    let start = Instant::now();
    loop {
        interval.tick().await;
        let mut so = tokio::io::stdout();
        COUNTERS.write_as_text(start.elapsed(), &mut so).await?;
    }
}
