use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, sync::atomic::AtomicUsize};

use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};

use tokio::{net::UdpSocket, time::{Interval, Instant, Duration}};

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

//use tracing::{span, Level};
use tracing_attributes::instrument;
//TODO: https://crates.io/crates/tracing-coz or https://crates.io/crates/tracing-tracy
use chacha20::ChaCha20;
use tracing::{info,debug};
// Import relevant traits
use chacha20::cipher::{KeyIvInit, StreamCipher};
//use hex_literal::hex;

async fn flatten<T>(handle: tokio::task::JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(eyre!("handling of future failed with error {}", err)),
    }
}
#[derive(Default, Debug)]
struct Counters{
    pkt: AtomicUsize,
    bytes: AtomicUsize,
}

impl std::fmt::Display for Counters{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"Packets: {:#?}, Bytes: {:#?}", self.pkt, self.bytes)
    }
}

#[derive(Debug)]
struct CountersAll{
   tap_tx:Counters,
   tap_rx:Counters,
   udp_rx: Counters,
   udp_tx:Counters,
}

impl Counters{      
    const fn new()  ->Self{
        Self{pkt:AtomicUsize::new(0), bytes:AtomicUsize::new(0)}
    }
    
    fn pkt(&self, size:usize){
        self.pkt.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
        self.bytes.fetch_add(size,std::sync::atomic::Ordering::Relaxed);
    }
}

impl std::fmt::Display for CountersAll{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f,"UDP TX {}", self.udp_tx)?;
        writeln!(f,"UDP RX {}", self.udp_rx)?;
        writeln!(f,"TAP TX {}", self.tap_tx)?;
        writeln!(f,"TAP RX {}", self.tap_rx)
    }
}

impl CountersAll{
    const fn new()  ->Self{
        Self{udp_tx:Counters::new(), tap_tx: Counters::new(), tap_rx: Counters::new(), udp_rx: Counters::new() }
    }
}
async fn watch_counters(mut interval:Interval)->Result<()>{
    loop{    
      interval.tick().await;
      println!("{}", &COUNTERS);
    }    
}

static COUNTERS:CountersAll = CountersAll::new();

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
    let interval =  tokio::time::interval_at(Instant::now() + Duration::from_secs(1), Duration::from_millis(1000));
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
    // tokio::select!{
    //     r=udp_reader=>{r?},
    //     r=udp_writer=>{r?},
    //     r=tap_reader=>{r?},
    //     r=tap_writer=>{r?},
    // }?;

    tokio::try_join!(udp_reader, udp_writer, tap_reader, tap_writer, watch_counters)?;

    Ok(())
}

#[instrument]
fn crypto_worker(
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

#[instrument(skip(tun))]
async fn read_tap(tun: Arc<Tun>, output: tokio::sync::mpsc::Sender<BytesMut>) -> Result<()> {
    loop {
        //TODO: deal with excessive malloc's here
        let mut buf = BytesMut::with_capacity(2048);
        //assume buf is initialized, not like we trust incoming data anywau
        unsafe {
            buf.set_len(buf.capacity());
        }

        let n = tun.recv(&mut buf).await?;
        COUNTERS.tap_rx.pkt(n);
        let buf = buf.split_to(n);
        //let mut rg=tun.readable().await?;
        //let res = rg.try_io(|inner|{read_raw_fd(inner.get_ref(),&mut buf)});
        //dbg!(res);
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
        // match udp.feed((Bytes::from(b), peer)).await {
        //     Ok(_) => {}
        //     Err(e) =>{/* return Err(eyre!("UDP send error {}", e))*/},
        // }
    }
}

#[instrument]
async fn read_udp(
    mut udp: SplitStream<UdpFramed<LengthDelimitedCodec>>,
    output: tokio::sync::mpsc::Sender<BytesMut>,
) -> Result<()> {
    loop {
        let (pkt, peer) = match udp.next().await {
            Some(p) => p?,
            None => {
                return Err(eyre!("UDP Peer Disconnected"));
            } //
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
