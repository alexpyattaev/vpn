mod crypto;
mod framing;
mod keepalive;
use crypto::{crypto_decryptor, crypto_encryptor};
use framing::{PacketFragmenter, Reassembler, TrustedMessage, UntrustedMessage};
mod counters;

use counters::{watch_counters, COUNTERS};
use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::AtomicU64,
};
use tracing_subscriber::layer::SubscriberExt;

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
}

//use tracing::{span, Level};
use tracing_attributes::instrument;
//TODO: https://crates.io/crates/tracing-coz or https://crates.io/crates/tracing-tracy

use tracing::{debug, info, subscriber, warn};
// Import relevant traits

//use hex_literal::hex;

pub static TX_SEQUENCE_ALLOCATOR: AtomicU64 = AtomicU64::new(1);

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
    let chachaparams = Arc::new(crypto::ChaChaParams {
        key: [0x42; 32],
        nonce: [0x42; 12],
    });

    let watch_counters = {
        let interval = tokio::time::interval_at(
            Instant::now() + Duration::from_secs(1),
            Duration::from_millis(1000),
        );
        flatten(tokio::spawn(watch_counters(interval)))
    };
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
    info!("Worker thread setup complete");

    let timeout_ticks = {
        let tick = Duration::from_millis(100);
        let timeout = Duration::from_millis(1000);
        let s = encryptor.0.clone();
        flatten(tokio::spawn(keepalive::keepalive_ticks(tick, timeout, s)))
    };
    let udp_reader = flatten(tokio::spawn(read_udp(
        socket.clone(),
        decryptor.0,
        args.udp_mtu,
    )));

    let udp_writer = flatten(tokio::spawn(feed_udp(
        encryptor.1,
        socket.clone(),
        args.remote_address,
    )));

    let tap_reader = flatten(tokio::spawn(read_tap(tun.clone(), encryptor.0)));

    let tap_writer = flatten(tokio::spawn(feed_tap(decryptor.1, tun.clone())));

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

#[instrument(skip(tun, output))]
async fn read_tap(tun: Arc<Tun>, output: tokio::sync::mpsc::Sender<TrustedMessage>) -> Result<()> {
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
        debug!(
            "Received {} bytes from tap, fragmented into {} packets",
            n,
            pf.len()
        );
        // block pipe for needed number of messages (to avoid re-syncing for each)
        let permit = output.reserve_many(pf.len()).await?;
        // dump all fragments in order into the pipe
        for (p, m) in permit.zip(pf) {
            p.send(m);
        }
    }
}

#[instrument(skip(input, udp, peer))]
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
        keepalive::packet_tx();
        debug!("feeding {} bytes to UDP peer {:?}", b.len(), &peer);
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

#[instrument(skip(output, udp, mtu))]
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

        debug!("Receiverd  {} bytes from UDP", buf.len());

        let pkt = match UntrustedMessage::from_buffer(buf) {
            Ok(pkt) => pkt,
            Err(e) => {
                debug!("Could not decode header in packet {:?}", e);
                COUNTERS.udp_invalid.pkt(len);
                continue;
            }
        };
        COUNTERS.udp_rx.pkt(len);
        output.send(pkt).await?;
    }
}

#[instrument(skip(input, tun))]
async fn feed_tap(
    mut input: tokio::sync::mpsc::Receiver<TrustedMessage>,
    tun: Arc<Tun>,
) -> Result<()> {
    // max amount of bytes for possible packet reorderings
    let max_lookback_seq = 5000;
    let mut assembler = Reassembler::<8>::new();
    //Todo: move logic around rx_seq_max to reassembler
    let mut rx_seq_max = 0;
    loop {
        let pkt = match input.recv().await {
            Some(p) => p,
            None => {
                return Err(eyre!("No more data to feed TAP"));
            }
        };

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
                debug!("Got keepalive");
                continue;
            }
            _ => {
                debug!("Got data fragment of size {}", pkt.body.len());
                match assembler.add_msg(pkt) {
                    Ok(None) => {
                        debug!("Not enough to assemble full packet");
                        continue;
                    }
                    Ok(Some((s, p))) => {
                        debug!("Assembled packet with seq {} length {}", s, p.len());
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
