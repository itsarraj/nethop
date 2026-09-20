use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use clap::Parser;
use nethop::icmp::{build_echo_request, parse_icmp_header, TYPE_ECHO_REPLY, TYPE_TIME_EXCEEDED};
use nethop::stats::compute_hop_stats;
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Parser)]
#[command(
    name = "nethop",
    about = "Combined ping + traceroute with per-hop jitter/loss statistics"
)]
struct Cli {
    target: String,
    /// Number of ping rounds against the target.
    #[arg(short = 'c', long, default_value_t = 5)]
    count: usize,
    /// Also run a hop-by-hop traceroute before pinging.
    #[arg(long)]
    trace: bool,
    #[arg(long, default_value_t = 30)]
    max_hops: u8,
}

fn open_icmp_socket() -> anyhow::Result<Socket> {
    // SOCK_DGRAM + IPPROTO_ICMP is Linux's real unprivileged "ping
    // socket" mechanism (net.ipv4.ping_group_range) — no CAP_NET_RAW
    // needed, unlike a true raw ICMP socket. Confirmed live in this
    // sandbox: a real SOCK_RAW ICMP socket is refused with "Operation
    // not permitted," but this exact socket type genuinely works.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    Ok(socket)
}

fn ping_once(
    socket: &Socket,
    target: Ipv4Addr,
    ttl: Option<u32>,
    seq: u16,
) -> anyhow::Result<Option<(Duration, IpAddr, bool)>> {
    if let Some(ttl) = ttl {
        socket.set_ttl(ttl)?;
    }
    let id = std::process::id() as u16;
    let packet = build_echo_request(id, seq, b"nethop");
    let addr = SocketAddr::new(IpAddr::V4(target), 0);
    let sent_at = Instant::now();
    socket.send_to(&packet, &addr.into())?;

    let mut buf = [std::mem::MaybeUninit::uninit(); 512];
    match socket.recv_from(&mut buf) {
        Ok((n, from)) => {
            let bytes: Vec<u8> = buf[..n]
                .iter()
                .map(|b| unsafe { b.assume_init() })
                .collect();
            // A Linux ping socket delivers the ICMP payload with no IP
            // header attached (unlike a true raw socket) — verified
            // live against this exact code path.
            let Some(header) = parse_icmp_header(&bytes, 0) else {
                return Ok(None);
            };
            let rtt = sent_at.elapsed();
            let from_ip = from
                .as_socket()
                .map(|s| s.ip())
                .unwrap_or(IpAddr::V4(target));
            let is_target = header.icmp_type == TYPE_ECHO_REPLY;
            let is_hop = header.icmp_type == TYPE_TIME_EXCEEDED;
            if is_target || is_hop {
                Ok(Some((rtt, from_ip, is_target)))
            } else {
                Ok(None)
            }
        }
        Err(_) => Ok(None), // timeout — a real lost probe, not an error
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let target: Ipv4Addr = match cli.target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let resolved = std::net::ToSocketAddrs::to_socket_addrs(&(cli.target.as_str(), 0))?
                .find_map(|a| match a.ip() {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("could not resolve '{}' to an IPv4 address", cli.target)
                })?;
            resolved
        }
    };

    let socket = open_icmp_socket()?;

    if cli.trace {
        println!("traceroute to {target}, max {} hops:", cli.max_hops);
        for ttl in 1..=cli.max_hops {
            match ping_once(&socket, target, Some(ttl as u32), ttl as u16)? {
                Some((rtt, from, is_target)) => {
                    println!("{ttl:>3}  {from}  {rtt:?}");
                    if is_target {
                        break;
                    }
                }
                None => println!("{ttl:>3}  *"),
            }
        }
        println!();
    }

    println!("ping {target}, {} round(s):", cli.count);
    let mut samples = Vec::with_capacity(cli.count);
    for seq in 0..cli.count {
        let result = ping_once(&socket, target, None, seq as u16)?;
        match result {
            Some((rtt, _, _)) => {
                println!("seq={seq} time={rtt:?}");
                samples.push(Some(rtt));
            }
            None => {
                println!("seq={seq} *** timeout ***");
                samples.push(None);
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let stats = compute_hop_stats(&samples);
    println!(
        "\n{}/{} received, {:.0}% loss, min={:?} avg={:?} max={:?}",
        stats.received,
        stats.sent,
        stats.loss_percent(),
        stats.min,
        stats.avg,
        stats.max
    );

    Ok(())
}
