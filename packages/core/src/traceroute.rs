use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::scanner::model::Hop;

const MAX_HOPS: u32 = 15;
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_PROBES: u32 = 1;
const PROBE_PORT_BASE: u16 = 33434;

pub async fn trace(ip: IpAddr) -> Vec<Hop> {
    if ip.is_ipv6() {
        return vec![];
    }

    tokio::time::timeout(Duration::from_secs(15), trace_inner(ip))
        .await
        .unwrap_or_default()
}

async fn trace_inner(ip: IpAddr) -> Vec<Hop> {
    let icmp_sock = match create_icmp_listener() {
        Some(s) => s,
        None => {
            eprintln!("[aplomado] traceroute: failed to create ICMP listener");
            return vec![];
        }
    };

    let mut hops: Vec<Hop> = Vec::new();

    for ttl in 1..=MAX_HOPS {
        let mut got_response = false;

        for probe in 0..MAX_PROBES {
            let port = (PROBE_PORT_BASE as u32 + (ttl - 1) * MAX_PROBES + probe) as u16;
            let probe_start = Instant::now();
            let result = send_probe(ip, ttl, port, &icmp_sock).await;

            if let Some(router_ip) = result {
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

fn create_icmp_listener() -> Option<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).ok()?;
    sock.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    let std_sock: UdpSocket = sock.into();
    Some(std_sock)
}

/// Send a UDP probe with a given TTL and wait for ICMP response.
/// Validates that the ICMP error embeds the original UDP datagram with the
/// expected destination port, ensuring the response corresponds to our probe.
async fn send_probe(
    target_ip: IpAddr,
    ttl: u32,
    port: u16,
    icmp_sock: &UdpSocket,
) -> Option<IpAddr> {
    let probe_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    probe_sock.set_ttl(ttl).ok()?;

    let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    probe_sock.bind(&bind_addr.into()).ok()?;

    let probe_udp: UdpSocket = probe_sock.into();
    let target_addr: SocketAddr = SocketAddr::new(target_ip, port);

    // Send the probe
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
                        11 | 3 => {
                            // ICMP Time Exceeded (11) or Destination Unreachable (3)
                            // The ICMP payload contains the IP header + 8 bytes of the
                            // original UDP datagram. Extract the original destination port
                            // from bytes 28-29 (offset 20 for IP header in ICMP payload
                            // + 2 for UDP source port).
                            if n < 30 {
                                continue;
                            }
                            let udp_dst_port = u16::from_be_bytes([buf[28], buf[29]]);
                            if udp_dst_port != port {
                                // ICMP response does not match our probe port — skip
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
    })
    .await
    .ok()
    .flatten()
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
        let mut hops = vec![
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
        hops.sort_by(|a, b| a.hop.cmp(&b.hop));
        assert_eq!(hops[0].hop, 1);
        assert_eq!(hops[2].hop, 3);
    }
}
