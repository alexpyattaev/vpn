use std::{
    fmt::Debug, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::atomic::AtomicUsize
};

use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};

use tokio::{    
    net::UdpSocket,
    time::{Duration, Instant, Interval},
};

use tokio_util::udp::UdpFramed;
// use tun_tap::{Iface, Mode};
//use tun_tap::r#async::Async;
use bytes::{Bytes, BytesMut};

use std::sync::Arc;

use tokio_util::codec::LengthDelimitedCodec;

use clap::Parser;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use tokio_tun::Tun;
/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long,default_value_t = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 6666) )]
    local_address: SocketAddr,

    /// Number of times to greet
    #[arg(short, long)]
    remote_address: SocketAddr,
}

mod framing;
use framing::*;
pub async fn receive_pipeline_pseudocode()->Result<()>{
    let buf = BytesMut::new();// packet with stuff from UDP
    let parsed = UntrustedMessage::from_buffer(buf)?;
    crypto::apply_decryption([42;32], parsed.header.seq, parsed.body);
    
    Ok(())
}

//use tracing::{span, Level};
use tracing_attributes::instrument;
//TODO: https://crates.io/crates/tracing-coz or https://crates.io/crates/tracing-tracy

use tracing::{debug, info};
// Import relevant traits

//use hex_literal::hex;
mod crypto;
use crypto::crypto_worker;

async fn flatten<T>(handle: tokio::task::JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(eyre!("handling of future failed with error {}", err)),
    }
}
#[derive(Default, Debug)]
struct Counters {
    pkt: AtomicUsize,
    bytes: AtomicUsize,
}

impl std::fmt::Display for Counters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Packets: {:#?}, Bytes: {:#?}", self.pkt, self.bytes)
    }
}
mod unit_fmt {
    use si_scale::scale_fn;    
    pub use si_scale::helpers::bytes;
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

    fn pkt(&self, size: usize) {
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
                
                let t =self.d.as_secs_f32();                 
                
                write!(f, "Packets: {:#?} ({:#?}/s), Data: {} ({})", self.pkt,self.pkt as f32/t , unit_fmt::bytes(self.bytes as f64), unit_fmt::bits_per_sec(self.bytes as f32 *8.0 / t))
            }
        }

        let pkt = self.pkt.load(std::sync::atomic::Ordering::Relaxed);
        let bytes = self.bytes.load(std::sync::atomic::Ordering::Relaxed);
        CountersDispl{d:elapsed, pkt:pkt, bytes:bytes}        
    }
}

#[derive(Debug)]
struct CountersAll {
    tap_tx: Counters,
    tap_rx: Counters,
    udp_rx: Counters,
    udp_tx: Counters,
}



pub trait Wtf: tokio::io::AsyncWriteExt + Unpin {}
impl<T> Wtf for T where T: tokio::io::AsyncWriteExt + Unpin {}
impl CountersAll {
    const fn new() -> Self {
        Self {
            udp_tx: Counters::new(),
            tap_tx: Counters::new(),
            tap_rx: Counters::new(),
            udp_rx: Counters::new(),
        }
    }
    async fn write_as_text(&self, elapsed: tokio::time::Duration, f: &mut impl Wtf) -> Result<()> {
        
        let s = format!(r"Uptime {elapsed:#?}
UDP TX {}
UDP RX {}
TAP TX {}
TAP RX {}
", self.udp_tx.prep_display(elapsed), self.udp_rx.prep_display(elapsed), self.tap_tx.prep_display(elapsed), self.tap_rx.prep_display(elapsed));            
        f.write_all(s.as_bytes()).await?;

        Ok(())
    }
}
async fn watch_counters(mut interval: Interval) -> Result<()> {
    let start = Instant::now();
    loop {
        interval.tick().await;
        let mut so = tokio::io::stdout();
        COUNTERS.write_as_text(start.elapsed(), &mut so).await?;
    }
}

static COUNTERS: CountersAll = CountersAll::new();

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    debug!("Arguments are {:?}", &args);

    let socket = UdpSocket::bind(&args.local_address).await?;

    info!("UDP bind successful");
    socket.connect(args.remote_address).await?;
    info!("UDP connect successful");
    
    let codec = LengthDelimitedCodec::new();
    let framed_socket = UdpFramed::new(socket, codec);

    let (sender, receiver) = framed_socket.split();
    debug!("Setting up TAP interface");
    let tun = Arc::new(
        Tun::builder()
            .name("") // if name is empty, then it is set by kernel.
            .tap(true) // false (default): TUN, true: TAP.
            .packet_info(false) // false: IFF_NO_PI, default is true.
            .up() // or set it up manually using `sudo ip link set <tun-name> up`.
            .try_build() // or `.try_build_mq(queues)` for multi-queue support.
            .expect("Could not register TAP interface, are you root?"),
    );

    info!("TAP created, name: {}", tun.name());

    let key = Arc::new([0x42; 32]);

    // Key and IV must be references to the `GenericArray` type.
    let interval = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(1),
        Duration::from_millis(1000),
    );

    let watch_counters = flatten(tokio::spawn(watch_counters(interval)));
    let mut crypto_workers = (0..2).map(|e| {
        let input_chan = tokio::sync::mpsc::channel(64);
        let output_chan = tokio::sync::mpsc::channel(64);
        let key = key.clone();
        let jh = tokio::task::spawn_blocking(move || {
            crypto_worker(key, input_chan.1, output_chan.0);
            debug!("Crypto worker {e} exited");
        });
        (input_chan.0, output_chan.1, jh)
    });
    let encryptor = crypto_workers.next().unwrap();
    let decryptor = crypto_workers.next().unwrap();
    info!("Crypto thread setup complete");

    let udp_reader = flatten(tokio::spawn(read_udp(receiver, decryptor.0)));
    let udp_writer = flatten(tokio::spawn(feed_udp(
        encryptor.1,
        sender,
        args.remote_address.clone(),
    )));
    // TAP Reader
    let tap_reader = flatten(tokio::spawn(read_tap(tun.clone(), encryptor.0)));
    let tap_writer = flatten(tokio::spawn(feed_tap(decryptor.1, tun.clone())));

    tokio::try_join!(
        udp_reader,
        udp_writer,
        tap_reader,
        tap_writer,
        watch_counters
    )?;

    Ok(())
}

fn read_tap_blocking() -> Result<()> {
    loop {
        std::thread::sleep(Duration::from_nanos(10));
    }
    Ok(())
}

#[instrument(skip(tun))]
async fn read_tap(tun: Arc<Tun>, output: tokio::sync::mpsc::Sender<BytesMut>) -> Result<()> {
    //let mut interval = tokio::time::interval(Duration::from_nanos(10));
    loop {
        let mut buf = BytesMut::with_capacity(1800);
        //TODO: deal with excessive malloc's here

        //assume buf is initialized, not like we trust incoming data anywau
        unsafe {
            buf.set_len(buf.capacity());
        }

        let n = match cfg!(feature = "bench_tap_rx") {
            true => 1500,
            false => tun.recv(&mut buf).await?,
        };

        COUNTERS.tap_rx.pkt(n);

        unsafe {
            buf.set_len(n);
        }
        //println!("reading {} bytes: {:?}", n, &buf[..n]);
        output.send(buf).await?;
    }
}

#[instrument]
async fn feed_udp(
    mut input: tokio::sync::mpsc::Receiver<BytesMut>,
    mut udp: SplitSink<UdpFramed<LengthDelimitedCodec>, (Bytes, SocketAddr)>,
    peer: SocketAddr,
) -> Result<()> {
    loop {
        let b = match input.recv().await {
            Some(b) => b,
            None => {
                return Err(eyre!("Peer disconnected"));
            }
        };
        COUNTERS.udp_tx.pkt(b.len());
        //println!("feeding {} bytes to UDP peer {:?}", b.len(), &peer);
        if cfg!(not(feature = "bench_tap_rx")) {
            match udp.feed((Bytes::from(b), peer)).await {
                Ok(_) => {}
                Err(e) => return Err(eyre!("UDP send error {}", e)),
            }
        }
    }
}

#[instrument]
async fn read_udp(
    mut udp: SplitStream<UdpFramed<LengthDelimitedCodec>>,
    output: tokio::sync::mpsc::Sender<BytesMut>,
) -> Result<()> {
    loop {
        let (pkt, _peer) = match cfg!(feature = "bench_udp_rx") {
            true => (
                BytesMut::zeroed(1500),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            ),
            false => match udp.next().await {
                Some(p) => p?,
                None => {
                    return Err(eyre!("UDP Peer Disconnected"));
                } //
            },
        };

        COUNTERS.udp_rx.pkt(pkt.len());
        //dbg!("Receiverd  {} bytes from UDP peer {}", pkt.len(), peer);
        output.send(pkt).await?;
    }
}

#[instrument(skip(tun))]
async fn feed_tap(mut input: tokio::sync::mpsc::Receiver<BytesMut>, tun: Arc<Tun>) -> Result<()> {
    loop {
        let pkt = match input.recv().await {
            Some(p) => p,
            None => {
                return Err(eyre!("No more data to feed TAP"));
            } //
        };
        let n = tun.send(&pkt).await?;
        COUNTERS.tap_tx.pkt(n);
        //dbg!("Forwarded  {} bytes to TAP", n);
    }
}
