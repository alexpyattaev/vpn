mod crypto;
mod framing;
mod keepalive;
mod util;
use crypto::{decode_key_base64, make_decryptor, make_encryptor, CryptoMode, Decryptor, Encryptor};
use framing::{PacketFragmenter, Reassembler, TrustedMessage, UntrustedMessage};
mod counters;
mod selfcheck;
mod traits;
use counters::{watch_counters, COUNTERS};
use keepalive::CURRENT_PACKET_TIME;
use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::atomic::{AtomicU64, Ordering},
};
use traits::{ExtranetPacketInterface, IntranetPacketInterface};
use util::{flatten, merge};

use tokio::time::{Duration, Instant};

// use tun_tap::{Iface, Mode};
//use tun_tap::r#async::Async;
use bytes::{Bytes, BytesMut};

use std::sync::Arc;

use clap::Parser;
use color_eyre::{
    eyre::{eyre, Context, Report},
    Result,
};

#[cfg(not(feature = "bench_loopback"))]
use tokio::net::UdpSocket;
#[cfg(not(feature = "bench_loopback"))]
use tokio_tun::Tun;

#[cfg(feature = "bench_loopback")]
use selfcheck::{TrafGen, WireEmulator};

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
    #[arg(short, long, default_value_t = NonZeroUsize::new(2).unwrap())]
    encoder_threads: NonZeroUsize,

    /// Number of decoder threads for decrpytion of packets
    #[arg(short, long, default_value_t = NonZeroUsize::new(2).unwrap())]
    decoder_threads: NonZeroUsize,

    // Encryption key, base64 (RFC 4648) encoded, must be 32 bytes long.
    #[arg(short, long, default_value_t = String::from("MDEwMjAzMDQwNTA2MDcwODA5MTAxMTEyMTMxNDE1MTY="))]
    key: String,

    // CHACHA20 nonce, base64 (RFC 4648) encoded, must be 12 bytes.
    #[arg(short, long, default_value_t = String::from("MDEwMjAzMDQwNTA2"))]
    nonce: String,

    // Encryption mode. Sign only encrypts first 32 bytes of every packet to avoid injection of junk.
    #[arg(short, long, default_value_t = CryptoMode::Encrypt, value_enum)]
    crypto_mode: CryptoMode,
}

//use tracing::{span, Level};
//use tracing_attributes::instrument;
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
        #[cfg(feature = "bench_loopback")]
        let s = {
            info!("UDP emulation enabled");
            WireEmulator::new(8)
        };

        #[cfg(not(feature = "bench_loopback"))]
        let s = {
            let s = UdpSocket::bind(args.local_address)
                .await
                .wrap_err_with(|| {
                    format!("Can not bind to local address {}", args.local_address)
                })?;
            info!("UDP local bind successful");
            s.connect(args.remote_address).await.wrap_err_with(|| {
                format!(
                    "Can not find path to remote address {}",
                    args.remote_address
                )
            })?;
            info!("UDP route check successful");
            s
        };
        Arc::new(s)
    };
    let tun = {
        #[cfg(feature = "bench_loopback")]
        let a = {
            debug!("Setting up traffic generation interface");
            TrafGen::new(1500, 16)
        };

        #[cfg(not(feature = "bench_loopback"))]
        let a = {
            debug!("Setting up TAP interface");
            let a = Tun::builder()
                .name("") // if name is empty, then it is set by kernel.
                .tap(true) // false (default): TUN, true: TAP.
                .packet_info(false) // false: IFF_NO_PI, default is true.
                .up() // or set it up manually using `sudo ip link set <tun-name> up`.
                .try_build() // or `.try_build_mq(queues)` for multi-queue support.
                .wrap_err("Could not register TAP interface, are you root?")?;
            info!("TAP interface created, name: {}", a.name());
            a
        };
        Arc::new(a)
    };

    // Key and IV must be references to the `GenericArray` type.

    let chachaparams = {
        let key = decode_key_base64(&args.key).wrap_err("Could not parse key")?;
        let nonce = decode_key_base64(&args.nonce).wrap_err("Could not parse nonce")?;
        crypto::ChaChaParams {
            key,
            nonce,
            mode: args.crypto_mode,
        }
    };

    let watch_counters = {
        let interval = tokio::time::interval_at(
            Instant::now() + Duration::from_secs(1),
            Duration::from_millis(1000),
        );
        flatten(tokio::spawn(watch_counters(interval)))
    };

    let encryptor_pool = make_encryptor(chachaparams.clone(), args.encoder_threads);
    let decryptor_pool = make_decryptor(chachaparams.clone(), args.decoder_threads);
    let encryptor = encryptor_pool.workpool.clone();
    let decryptor = decryptor_pool.workpool.clone();

    info!("Worker thread setup complete");

    let timeout_ticks = {
        let tick = Duration::from_millis(100);
        let timeout = Duration::from_millis(1000);
        let s = encryptor.clone();
        flatten(tokio::spawn(keepalive::keepalive_ticks(tick, timeout, s)))
    };
    let udp_reader = flatten(tokio::spawn(read_udp(
        socket.clone(),
        decryptor.clone(),
        args.udp_mtu,
    )));

    let udp_writer = flatten(tokio::spawn(feed_udp(
        encryptor.clone(),
        socket.clone(),
        args.remote_address,
    )));

    let tap_reader = flatten(tokio::spawn(read_tap(tun.clone(), encryptor.clone())));

    let tap_writer = flatten(tokio::spawn(feed_tap(decryptor.clone(), tun.clone())));

    info!("Init sequence completed, VPN ready");

    //Wait for any thread to quit
    tokio::try_join!(
        udp_reader,
        udp_writer,
        tap_reader,
        tap_writer,
        watch_counters,
        timeout_ticks,
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

//#[instrument(skip(tun, output))]

async fn read_tap(tun: Arc<impl traits::IntranetPacketInterface>, output: Encryptor) -> Result<()> {
    loop {
        let mut buf = bytes_mut_uninit(1800);
        let n = tun.recv(&mut buf).await?;
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
            output.process(f).await?;
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

//#[instrument(skip(input, udp, peer))]
async fn feed_udp(
    input: Encryptor,
    udp: Arc<impl ExtranetPacketInterface>,
    peer: SocketAddr,
) -> Result<()> {
    loop {
        let b = input.get_ready_pkt().await.wrap_err("Peer disconnected")?;
        COUNTERS.udp_tx.pkt(b.len());
        keepalive::packet_tx();
        if cfg!(feature = "packet_tracing") {
            debug!("feeding {} bytes to UDP peer {:?}", b.len(), &peer);
        }
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

//#[instrument(skip(output, udp, mtu))]
async fn read_udp(
    udp: Arc<impl ExtranetPacketInterface>,
    output: Decryptor,
    mtu: usize,
) -> Result<()> {
    loop {
        let buf = {
            let mut buf = bytes_mut_uninit(mtu);
            let n = udp.recv(buf.as_mut()).await?;
            buf.truncate(n);
            buf
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
        output.process(pkt).await?;
    }
}

//#[instrument(skip(input, tun))]
async fn feed_tap(input: Decryptor, tun: Arc<impl IntranetPacketInterface>) -> Result<()> {
    // time to wait in ticks for reordered packets.
    let max_lookback_ticks = 2;
    let mut assembler = Reassembler::<32>::new(1);
    loop {
        let pkt = input
            .get_ready_pkt()
            .await
            .wrap_err("No more data for TAP availabe")?;

        if pkt.outer_header.seq < assembler.min_seq() {
            warn!(
                "Got stale packet with stale seq {}, relevant seq {} dropping",
                pkt.outer_header.seq,
                assembler.min_seq()
            );
            COUNTERS.seq_invalid.pkt(pkt.body.len());
        }

        keepalive::packet_rx();
        match pkt.inner_header.msgkind {
            framing::MsgKind::Keepalive => {
                if cfg!(feature = "packet_tracing") {
                    debug!("Got keepalive");
                }
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
                    }
                    Ok(Some(_)) => {
                        while let Some((s, p)) = assembler.poll() {
                            let n = tun.send(&p).await?;
                            COUNTERS.tap_tx.pkt(n);
                            if cfg!(feature = "packet_tracing") {
                                debug!("Assembled packet with seq {} length {}", s, p.len());
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Reassembly failed with error {e}");
                    }
                }
            }
        }

        if cfg!(not(feature = "packet_tracing")) {
            //TODO: make this run on independent timer/thread
            // prevent junk from accumulating in reassembly buffer
            let cpt = CURRENT_PACKET_TIME.load(Ordering::SeqCst);
            if cpt > max_lookback_ticks {
                assembler.check_stale(cpt - max_lookback_ticks);
            }
        }
    }
}
