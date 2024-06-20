mod crypto;
mod framing;
mod keepalive;
mod util;
use crypto::{decode_key_base64, CryptoMode, Decryptor, Encryptor};
use framing::{PacketFragmenter, Reassembler, TrustedMessage, UntrustedMessage};
mod counters;
use counters::{watch_counters, COUNTERS};
use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::AtomicU64,
};
use util::{flatten, merge};

use tokio::{
    net::UdpSocket,
    time::{Duration, Instant},
};

// use tun_tap::{Iface, Mode};
//use tun_tap::r#async::Async;
use bytes::{Bytes, BytesMut};

use std::sync::Arc;

use clap::Parser;
use color_eyre::{
    eyre::{eyre, Context, Report},
    Result,
};
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

    /// Number of encoder threads for encryption of packets
    #[arg(short, long, default_value_t = 3)]
    encoder_threads: usize,

    /// Number of decoder threads for decrpytion of packets
    #[arg(short, long, default_value_t = 3)]
    decoder_threads: usize,

    // Encryption key, base64 (RFC 4648) encoded, must be 32 bytes long.
    #[arg(short, long, default_value_t = String::from("MDEwMjAzMDQwNTA2MDcwODA5MTAxMTEyMTMxNDE1Cg=="))]
    key: String,

    // CHACHA20 nonce, base64 (RFC 4648) encoded, must be 12 bytes.
    #[arg(short, long, default_value_t = String::from("MDEwMjAzMDQwNTA2Cg=="))]
    nonce: String,

    // Encryption mode. Sign only encrypts first 32 bytes of every packet to avoid injection of junk.
    #[arg(short, long, default_value_t = CryptoMode::Encrypt, value_enum)]
    crypto_mode: CryptoMode,
}

//use tracing::{span, Level};
use tracing_attributes::instrument;
//TODO: https://crates.io/crates/tracing-coz or https://crates.io/crates/tracing-tracy

use tracing::{debug, info, warn};
// Import relevant traits

//use hex_literal::hex;

pub static TX_SEQUENCE_ALLOCATOR: AtomicU64 = AtomicU64::new(1);

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    //let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    //tracing_subscriber::fmt().with_writer(non_blocking).init();
    {
        // install global collector configured based on RUST_LOG env var.

        use tracing_subscriber::filter::{EnvFilter, LevelFilter};
        let filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::ERROR.into())
            .with_env_var("TRACE_LOG")
            .from_env()?;

        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            // Use a more compact, abbreviated log format
            .compact()
            // Display source code file paths
            .with_file(true)
            // Display source code line numbers
            .with_line_number(true)
            // Build the subscriber
            .finish();

        // use that subscriber to process traces emitted after this point
        tracing::subscriber::set_global_default(subscriber)?;
    }
    let args = Args::parse();
    debug!("Arguments are {:?}", &args);

    let socket = {
        let s = UdpSocket::bind(args.local_address)
            .await
            .wrap_err_with(|| format!("Can not bind to local address {}", args.local_address))?;
        info!("UDP local bind successful");
        s.connect(args.remote_address).await.wrap_err_with(|| {
            format!(
                "Can not find path to remote address {}",
                args.remote_address
            )
        })?;
        Arc::new(s)
    };
    info!("UDP route check successful");

    debug!("Setting up TAP interface");
    let tun = Arc::new(
        Tun::builder()
            .name("") // if name is empty, then it is set by kernel.
            .tap(true) // false (default): TUN, true: TAP.
            .packet_info(false) // false: IFF_NO_PI, default is true.
            .up() // or set it up manually using `sudo ip link set <tun-name> up`.
            .try_build() // or `.try_build_mq(queues)` for multi-queue support.
            .wrap_err("Could not register TAP interface, are you root?")?,
    );

    info!("TAP interface created, name: {}", tun.name());
    // Key and IV must be references to the `GenericArray` type.
    let chachaparams = crypto::ChaChaParams {
        key: decode_key_base64(&args.key)?,
        nonce: decode_key_base64(&args.nonce)?,
        mode: args.crypto_mode,
    };

    let watch_counters = {
        let interval = tokio::time::interval_at(
            Instant::now() + Duration::from_secs(1),
            Duration::from_millis(1000),
        );
        flatten(tokio::spawn(watch_counters(interval)))
    };

    let encryptor = Encryptor::new(chachaparams.clone());
    let encryptors_jh = {
        let a = (0..args.encoder_threads).map(|_| encryptor.spawn());
        futures_util::future::join_all(a)
    };

    let decryptor = Decryptor::new(chachaparams.clone());
    let decryptors_jh = {
        let a = (0..args.encoder_threads).map(|_| decryptor.spawn());
        futures_util::future::join_all(a)
    };

    info!("Worker thread setup complete");

    let timeout_ticks = {
        let tick = Duration::from_millis(100);
        let timeout = Duration::from_millis(1000);
        let s = encryptor.input.clone();
        flatten(tokio::spawn(keepalive::keepalive_ticks(tick, timeout, s)))
    };
    let udp_reader = flatten(tokio::spawn(read_udp(
        socket.clone(),
        decryptor.input.clone(),
        args.udp_mtu,
    )));

    let udp_writer = flatten(tokio::spawn(feed_udp(
        encryptor.output.clone(),
        socket.clone(),
        args.remote_address,
    )));

    let tap_reader = flatten(tokio::spawn(read_tap(tun.clone(), encryptor.input.clone())));

    let tap_writer = flatten(tokio::spawn(feed_tap(
        decryptor.output.clone(),
        tun.clone(),
    )));

    info!("Init sequence completed, VPN ready");

    //Wait for any thread to quit
    tokio::try_join!(
        udp_reader,
        udp_writer,
        tap_reader,
        tap_writer,
        watch_counters,
        timeout_ticks,
        merge(encryptors_jh),
        merge(decryptors_jh),
    )
    .wrap_err("Fatal error in VPN operation, exiting")?;

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

#[instrument(skip(tun, output))]
async fn read_tap(tun: Arc<Tun>, output: async_channel::Sender<TrustedMessage>) -> Result<()> {
    loop {
        let mut buf = bytes_mut_uninit(1800);

        let n = match cfg!(feature = "bench_tap_rx") {
            true => 1500,
            false => tun.recv(&mut buf).await?,
        };
        //SAFETY this is okay since we've just read exactly that many bytes,
        //recv can not write past end of buffer,
        //and we do not trust this data anyway;
        unsafe {
            buf.set_len(n);
        }

        COUNTERS.tap_rx.pkt(n);

        // prepare fragmenter & update sequence numbers
        let pf = PacketFragmenter::new(buf, 1300, &TX_SEQUENCE_ALLOCATOR);
        if cfg!(feature = "packet_tracing") {
            debug!(
                "Received {} bytes from tap, fragmented into {} packets",
                n,
                pf.len()
            );
        }
        for f in pf {
            output.send(f).await?;
        }
        /*
        // block pipe for needed number of messages (to avoid re-syncing for each)
        let permit = output.reserve_many(pf.len()).await?;
        // dump all fragments in order into the pipe
        for (p, m) in permit.zip(pf) {
            p.send(m);
        }
        */
    }
}

#[instrument(skip(input, udp, peer))]
async fn feed_udp(
    input: async_channel::Receiver<Bytes>,
    udp: Arc<UdpSocket>,
    peer: SocketAddr,
) -> Result<()> {
    loop {
        let b = input.recv().await.wrap_err("Peer disconnected")?;
        COUNTERS.udp_tx.pkt(b.len());
        keepalive::packet_tx();
        if cfg!(feature = "packet_tracing") {
            debug!("feeding {} bytes to UDP peer {:?}", b.len(), &peer);
        }
        if cfg!(not(feature = "bench_tap_rx")) {
            let sent = match udp.send(&b).await {
                Ok(s) => s,
                Err(e) => match e.kind() {
                    ErrorKind::ConnectionRefused | ErrorKind::Interrupted => continue,
                    _ => return Err(Report::new(e).wrap_err("UDP send encountered a fatal error")),
                },
            };
            if b.len() != sent {
                return Err(eyre!(
                    "UDP send could not send the whole frame, check your MTU config"
                ));
            }
        }
    }
}

//#[instrument(skip(output, udp, mtu))]
async fn read_udp(
    udp: Arc<UdpSocket>,
    output: async_channel::Sender<UntrustedMessage>,
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

        if cfg!(feature = "packet_tracing") {
            debug!("Receiverd  {} bytes from UDP", buf.len());
        }

        let pkt = match UntrustedMessage::from_buffer(buf) {
            Ok(pkt) => pkt,
            Err(e) => {
                warn!("Could not decode header in packet {:?}", e);
                COUNTERS.udp_invalid.pkt(len);
                continue;
            }
        };
        COUNTERS.udp_rx.pkt(len);
        output.send(pkt).await?;
    }
}

//#[instrument(skip(input, tun))]
async fn feed_tap(input: async_channel::Receiver<TrustedMessage>, tun: Arc<Tun>) -> Result<()> {
    // max amount of bytes for possible packet reorderings
    let max_lookback_seq = 5000;
    let mut assembler = Reassembler::<8>::new();
    //Todo: move logic around rx_seq_max to reassembler
    let mut rx_seq_max = 0;
    loop {
        let pkt = input
            .recv()
            .await
            .wrap_err("No more data for TAP availabe")?;

        rx_seq_max = rx_seq_max.max(pkt.outer_header.seq);

        if pkt.outer_header.seq < rx_seq_max {
            let d = rx_seq_max - pkt.outer_header.seq;
            if d > max_lookback_seq {
                warn!(
                    "Got stale packet with seq {}, relevant seq {}, dropping",
                    pkt.outer_header.seq, rx_seq_max
                );
            }
        }

        keepalive::packet_rx();
        let pkt = match pkt.inner_header.msgkind {
            framing::MsgKind::Keepalive => {
                if cfg!(feature = "packet_tracing") {
                    debug!("Got keepalive");
                }
                continue;
            }
            _ => {
                if cfg!(feature = "packet_tracing") {
                    debug!("Got data fragment of size {}", pkt.body.len());
                }
                match assembler.add_msg(pkt) {
                    Ok(None) => {
                        if cfg!(feature = "packet_tracing") {
                            debug!("Not enough to assemble full packet");
                        }
                        continue;
                    }
                    Ok(Some((s, p))) => {
                        if cfg!(feature = "packet_tracing") {
                            debug!("Assembled packet with seq {} length {}", s, p.len());
                        }
                        p
                    }
                    Err(e) => {
                        warn!("Reassembly failed with error {e}");
                        continue;
                    }
                }
            }
        };

        let n = tun.send(&pkt).await?;
        COUNTERS.tap_tx.pkt(n);
        // prevent junk from accumulating in reassembly buffer
        assembler.check_stale(rx_seq_max - max_lookback_seq);
    }
}
