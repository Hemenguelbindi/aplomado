use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use crate::scanner::model::Hop;

/// Simple per-probe identifier counter. Wraps around harmlessly at u16::MAX.
static PROBE_ID_COUNTER: AtomicU16 = AtomicU16::new(1);

const MAX_HOPS: u32 = 15;
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_PROBES: u32 = 1;
const PROBE_PORT_BASE: u16 = 33434;

/// Весь traceroute выполняется в `spawn_blocking`, так как все операции с
/// сокетами (UDP, ICMP) — синхронные и блокирующие. Это предотвращает
/// блокировку async-рантайма Tokio.
pub async fn trace(ip: IpAddr) -> Vec<Hop> {
    if ip.is_ipv6() {
        eprintln!("[aplomado] IPv6 traceroute not supported");
        return vec![];
    }

    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::task::spawn_blocking(move || trace_blocking(ip))
            .await
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

/// Блокирующая реализация traceroute — вызывается из `spawn_blocking`.
fn trace_blocking(ip: IpAddr) -> Vec<Hop> {
    let icmp_sock = match create_icmp_socket() {
        Some(s) => s,
        None => {
            eprintln!("[aplomado] traceroute: failed to create ICMP socket");
            return vec![];
        }
    };

    let mut hops: Vec<Hop> = Vec::new();

    for ttl in 1..=MAX_HOPS {
        let mut got_response = false;

        for probe in 0..MAX_PROBES {
            let port = (PROBE_PORT_BASE as u32 + (ttl - 1) * MAX_PROBES + probe) as u16;
            let probe_start = Instant::now();

            let router_ip = send_probe_blocking(ip, ttl, port, &icmp_sock);

            if let Some(router_ip) = router_ip {
                let elapsed = probe_start.elapsed().as_secs_f32() * 1000.0;

                if router_ip == ip {
                    hops.push(Hop {
                        hop: ttl,
                        ip: router_ip,
                        rtt_ms: Some(elapsed),
                    });
                    return hops;
                }

                if !hops.iter().any(|h| h.ip == router_ip) {
                    hops.push(Hop {
                        hop: ttl,
                        ip: router_ip,
                        rtt_ms: Some(elapsed),
                    });
                }

                got_response = true;
                break;
            }
        }

        if !got_response {
            hops.push(Hop {
                hop: ttl,
                ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                rtt_ms: None,
            });
        }
    }

    hops
}

fn create_icmp_socket() -> Option<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).ok()?;
    sock.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    Some(sock.into())
}

/// Блокирующая отправка UDP-пробы и ожидание ICMP-ответа.
///
/// Использует per-probe идентификатор для защиты от off-path атак:
/// встраивает `probe_id` в UDP source port и проверяет его в ICMP-ответе.
fn send_probe_blocking(
    target_ip: IpAddr,
    ttl: u32,
    port: u16,
    icmp_sock: &UdpSocket,
) -> Option<IpAddr> {
    // Generate a unique per-probe identifier embedded in the UDP source port.
    // This is validated against the ICMP response to prevent off-path injection.
    let probe_id = PROBE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);

    let probe_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    probe_sock.set_ttl(ttl).ok()?;

    // Bind to our probe_id as the source port — it will be echoed back in ICMP errors
    let bind_addr: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), probe_id);
    probe_sock.bind(&bind_addr.into()).ok()?;

    let probe_udp: UdpSocket = probe_sock.into();
    let target_addr: SocketAddr = SocketAddr::new(target_ip, port);

    // Send the probe (1 byte payload — enough for modern OSes to include in ICMP error)
    probe_udp.send_to(&[0u8; 1], target_addr).ok()?;
    drop(probe_udp);

    let icmp_sock_ref = icmp_sock.try_clone().ok()?;
    let mut buf = [0u8; 512];
    let start = Instant::now();

    while start.elapsed() < PROBE_TIMEOUT {
        match icmp_sock_ref.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if n < 32 {
                    // Minimum: ICMP header (8) + IP hdr (20) + UDP hdr (8) = 36 bytes.
                    // On a cooked ICMP socket the outer IP is stripped → 28 bytes minimum.
                    // We need at least 32 bytes to validate source + destination port.
                    continue;
                }

                let icmp_type = buf[0];

                match icmp_type {
                    11 | 3 => {
                        // ICMP payload embeds the original IP header + start of UDP datagram.
                        // Offsets assume a cooked ICMP socket (outer IP stripped by kernel):
                        //   [28..30] = embedded UDP source port (our probe_id)
                        //   [30..32] = embedded UDP destination port (our target)
                        let embedded_src = u16::from_be_bytes([buf[28], buf[29]]);
                        let embedded_dst = u16::from_be_bytes([buf[30], buf[31]]);

                        // Both the probe identifier AND the target port must match.
                        // This prevents off-path attackers from injecting fake ICMP
                        // responses even if they can guess the destination port sequence.
                        if embedded_src != probe_id || embedded_dst != port {
                            continue;
                        }

                        let router_ip = match addr {
                            std::net::SocketAddr::V4(a) => IpAddr::V4(*a.ip()),
                            _ => continue,
                        };
                        return Some(router_ip);
                    }
                    _ => continue,
                }
            }
            Err(_) => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_display() {
        let hop = Hop {
            hop: 1,
            ip: IpAddr::V4(Ipv4Addr::new(10, 2, 2, 1)),
            rtt_ms: Some(0.5),
        };
        assert_eq!(hop.to_string(), "1. 10.2.2.1 (0ms)");
    }

    #[test]
    fn test_hop_sort() {
        let mut hops = [
            Hop {
                hop: 3,
                ip: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 7)),
                rtt_ms: None,
            },
            Hop {
                hop: 1,
                ip: IpAddr::V4(Ipv4Addr::new(10, 2, 2, 1)),
                rtt_ms: None,
            },
            Hop {
                hop: 2,
                ip: IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
                rtt_ms: None,
            },
        ];
        hops.sort_by_key(|a| a.hop);
        assert_eq!(hops[0].hop, 1);
        assert_eq!(hops[2].hop, 3);
    }
}
