//! Traceroute — встроенная трассировка маршрута.
//!
//! Алгоритм: UDP probe + ICMP listener.
//! Не требует root (использует SOCK_DGRAM + IPPROTO_ICMP на Linux).
//! Не требует системного traceroute.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use socket2::{Domain, Protocol, Socket, Type};

use crate::scanner::model::Hop;

const MAX_HOPS: u32 = 15;
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_PROBES: u32 = 1; // 1 probe на hop (быстро)
const PROBE_PORT_BASE: u16 = 33434;

/// Выполнить traceroute до IP и вернуть список hop'ов.
pub async fn trace(ip: IpAddr) -> Vec<Hop> {
    if ip.is_ipv6() {
        return vec![];
    }

    // Общий таймаут на весь traceroute — не больше 15 секунд
    tokio::time::timeout(Duration::from_secs(15), trace_inner(ip))
        .await
        .unwrap_or_default()
}

async fn trace_inner(ip: IpAddr) -> Vec<Hop> {

    let mut hops: Vec<Hop> = Vec::new();

    let icmp_sock = match create_icmp_listener() {
        Some(s) => s,
        None => return vec![],
    };

    let start = Instant::now();

    for ttl in 1..=MAX_HOPS {
        let mut got_response = false;

        for probe in 0..MAX_PROBES {
            let port = (PROBE_PORT_BASE as u32 + (ttl - 1) * MAX_PROBES + probe) as u16;
            let result = send_probe(ip, ttl, port, &icmp_sock).await;

            if let Some(router_ip) = result {
                let elapsed = start.elapsed().as_secs_f32() * 1000.0;

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

        let _ = got_response;
    }

    hops
}

/// Создать ICMP сокет для приёма Time Exceeded / Unreachable.
fn create_icmp_listener() -> Option<UdpSocket> {
    let sock = Socket::new(
        Domain::IPV4,
        Type::DGRAM,
        Some(Protocol::ICMPV4),
    ).ok()?;

    sock.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;

    let std_sock: UdpSocket = sock.into();
    Some(std_sock)
}

/// Отправить UDP probe с заданным TTL.
async fn send_probe(
    target_ip: IpAddr,
    ttl: u32,
    port: u16,
    icmp_sock: &UdpSocket,
) -> Option<IpAddr> {
    let probe_sock = Socket::new(
        Domain::IPV4,
        Type::DGRAM,
        Some(Protocol::UDP),
    ).ok()?;

    probe_sock.set_ttl(ttl).ok()?;

    let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    probe_sock.bind(&bind_addr.into()).ok()?;

    let probe_udp: UdpSocket = probe_sock.into();

    let target_addr: SocketAddr = SocketAddr::new(target_ip, port);
    probe_udp.send_to(&[0u8; 1], target_addr).ok()?;

    let icmp_sock_ref = icmp_sock.try_clone().ok()?;
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 512];
        let start = Instant::now();

        while start.elapsed() < PROBE_TIMEOUT {
            match icmp_sock_ref.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    if n < 28 {
                        continue;
                    }

                    let icmp_type = buf[0];

                    match icmp_type {
                        11 => {
                            let router_ip = match addr {
                                std::net::SocketAddr::V4(a) => IpAddr::V4(*a.ip()),
                                _ => continue,
                            };
                            return Some(router_ip);
                        }
                        3 => {
                            let target_ip_match = match addr {
                                std::net::SocketAddr::V4(a) => IpAddr::V4(*a.ip()),
                                _ => continue,
                            };
                            return Some(target_ip_match);
                        }
                        _ => continue,
                    }
                }
                Err(_) => return None,
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

impl std::fmt::Display for Hop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.rtt_ms {
            Some(ms) => write!(f, "{}. {} ({}ms)", self.hop, self.ip, ms as u32),
            None => write!(f, "{}. {}", self.hop, self.ip),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_display() {
        let hop = Hop {
            hop: 1,
            ip: "10.2.2.1".parse().unwrap(),
            rtt_ms: Some(0.5),
        };
        assert_eq!(hop.to_string(), "1. 10.2.2.1 (0ms)");
    }

    #[test]
    fn test_hop_sort() {
        let mut hops = vec![
            Hop { hop: 3, ip: "10.2.0.7".parse().unwrap(), rtt_ms: None },
            Hop { hop: 1, ip: "10.2.2.1".parse().unwrap(), rtt_ms: None },
            Hop { hop: 2, ip: "10.2.0.1".parse().unwrap(), rtt_ms: None },
        ];
        hops.sort_by(|a, b| a.hop.cmp(&b.hop));
        assert_eq!(hops[0].hop, 1);
        assert_eq!(hops[2].hop, 3);
    }
}
