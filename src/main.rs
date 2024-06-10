mod crypto;
mod framing;
use crypto::{crypto_decryptor, crypto_encryptor};
use framing::{TrustedMessage, UntrustedMessage};
mod counters;

use counters::{watch_counters, COUNTERS};
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use tokio::{
    net::UdpSocket,
    time::{Duration, Instant},
};

// use tun_tap::{Iface, Mode};
//use tun_tap::r#async::Async;
use bytes::{Bytes, BytesMut};

use std::sync::Arc;

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

    /// The Maximum Transfer Unit to use for the UDP side of the VPN
    #[arg(short, long, default_value_t = 1500)]
    udp_mtu: usize,
}

//use tracing::{span, Level};
use tracing_attributes::instrument;
//TODO: https://crates.io/crates/tracing-coz or https://crates.io/crates/tracing-tracy

use tracing::{debug, info};
// Import relevant traits

//use hex_literal::hex;

async fn flatten<T>(handle: tokio::task::JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(eyre!("handling of future failed with error {}", err)),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    debug!("Arguments are {:?}", &args);

    let socket = UdpSocket::bind(&args.local_address).await?;

    info!("UDP bind successful");
    socket.connect(args.remote_address).await?;
    info!("UDP connect successful");

    //let codec = LengthDelimitedCodec::new();
    //let framed_socket = UdpFramed::new(socket, codec);

    let socket = Arc::new(socket);
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

    let chachaparams = Arc::new(crypto::ChaChaParams {
        key: [0x42; 32],
        nonce: [0x42; 12],
    });

    // Key and IV must be references to the `GenericArray` type.
    let interval = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(1),
        Duration::from_millis(1000),
    );

    let watch_counters = flatten(tokio::spawn(watch_counters(interval)));
    //TODO have a pool of these around
    let encryptor = {
        let input_chan = tokio::sync::mpsc::channel(64);
        let output_chan = tokio::sync::mpsc::channel(64);
        let kp = chachaparams.clone();
        let jh = tokio::task::spawn_blocking(move || {
            crypto_encryptor(kp, input_chan.1, output_chan.0);
            debug!("Crypto encryptor thread exited");
        });
        (input_chan.0, output_chan.1, jh)
    };
    let decryptor = {
        let input_chan = tokio::sync::mpsc::channel(64);
        let output_chan = tokio::sync::mpsc::channel(64);
        let kp = chachaparams.clone();
        let jh = tokio::task::spawn_blocking(move || {
            crypto_decryptor(kp, input_chan.1, output_chan.0);
            debug!("Crypto decryptor thread exited");
        });
        (input_chan.0, output_chan.1, jh)
    };
    info!("Crypto thread setup complete");

    let udp_reader = flatten(tokio::spawn(read_udp(
        socket.clone(),
        decryptor.0,
        args.udp_mtu,
    )));
    let udp_writer = flatten(tokio::spawn(feed_udp(
        encryptor.1,
        socket.clone(),
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

fn bytes_mut_uninit(size: usize) -> BytesMut {
    //TODO: deal with excessive malloc's here
    let mut buf = BytesMut::with_capacity(size);
    //assume buf is initialized, not like we trust incoming data anyway
    unsafe {
        buf.set_len(buf.capacity());
    }
    buf
}

#[instrument(skip(tun))]
async fn read_tap(tun: Arc<Tun>, output: tokio::sync::mpsc::Sender<BytesMut>) -> Result<()> {
    //let mut interval = tokio::time::interval(Duration::from_nanos(10));
    loop {
        let mut buf = bytes_mut_uninit(1800);
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
    mut input: tokio::sync::mpsc::Receiver<Bytes>,
    udp: Arc<UdpSocket>,
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
            let sent = udp.send(&b).await?;
            if b.len() != sent {
                return Err(eyre!(
                    "UDP send could not send the whole frame, check your MTU config"
                ));
            }
        }
    }
}

#[instrument]
async fn read_udp(
    udp: Arc<UdpSocket>,
    output: tokio::sync::mpsc::Sender<UntrustedMessage>,
    mtu: usize,
) -> Result<()> {
    loop {
        let buf = match cfg!(feature = "bench_udp_rx") {
            true => bytes_mut_uninit(mtu),
            false => {
                let mut buf = bytes_mut_uninit(mtu);
                let n = udp.recv(buf.as_mut()).await?;
                buf.truncate(n);
                buf
            }
        };
        let len = buf.len();

        //dbg!("Receiverd  {} bytes from UDP peer {}", pkt.len(), peer);

        let pkt = match UntrustedMessage::from_buffer(buf) {
            Ok(pkt) => pkt,
            Err(e) => {
                tracing::debug!("Could not decode header in packet {:?}", e);
                COUNTERS.udp_invalid.pkt(len);
                continue;
            }
        };
        COUNTERS.udp_rx.pkt(len);
        output.send(pkt).await?;
    }
}

#[instrument(skip(tun))]
async fn feed_tap(
    mut input: tokio::sync::mpsc::Receiver<TrustedMessage>,
    tun: Arc<Tun>,
) -> Result<()> {
    loop {
        let pkt = match input.recv().await {
            Some(p) => p,
            None => {
                return Err(eyre!("No more data to feed TAP"));
            } //
        };
        match pkt.inner_header.msgkind {
            framing::MsgKind::FirstFragment(s) => {
                println!("Got data packet of size {s}");
            }
            framing::MsgKind::Fragment(bp) => {
                println!(
                    "Got fragment with backpointer {bp}, no idea how to reassemble, dropping it"
                );
                continue;
            }
            framing::MsgKind::Keepalive => {
                println!("Got keepalive");
            }
        }

        let pkt = pkt.body; //TODO: implement proper reassembly of fragmented packets

        let n = tun.send(&pkt).await?;
        COUNTERS.tap_tx.pkt(n);
        //dbg!("Forwarded  {} bytes to TAP", n);
    }
}
