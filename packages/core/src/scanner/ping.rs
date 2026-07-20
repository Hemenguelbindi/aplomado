use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;

const PROBE_PORTS: &[u16] = &[80, 443, 22, 53, 8080, 8443];
const PING_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostReachability {
    Alive,
    PortClosed,
    NoResponse,
}

pub async fn is_alive(ip: IpAddr) -> bool {
    probe_host(ip).await != HostReachability::NoResponse
}

pub async fn probe_host(ip: IpAddr) -> HostReachability {
    let futs = PROBE_PORTS.iter().map(|&port| probe_port(ip, port));
    let results: Vec<HostReachability> = futures::future::join_all(futs).await;
    if results.iter().any(|r| *r == HostReachability::Alive) {
        HostReachability::Alive
    } else if results.iter().any(|r| *r == HostReachability::PortClosed) {
        HostReachability::PortClosed
    } else {
        HostReachability::NoResponse
    }
}

pub async fn probe_port(ip: IpAddr, port: u16) -> HostReachability {
    match tokio::time::timeout(PING_TIMEOUT, TcpStream::connect((ip, port))).await {
        Ok(Ok(_)) => HostReachability::Alive,
        Ok(Err(e)) => {
            if let std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset =
                e.kind()
            {
                HostReachability::PortClosed
            } else {
                HostReachability::NoResponse
            }
        }
        Err(_) => HostReachability::NoResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[tokio::test]
    async fn test_probe_port_alive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = probe_port(IpAddr::V4(Ipv4Addr::LOCALHOST), port).await;
        assert_eq!(result, HostReachability::Alive);
        drop(listener);
    }

    #[tokio::test]
    async fn test_probe_port_closed() {
        let result = probe_port(IpAddr::V4(Ipv4Addr::LOCALHOST), 1).await;
        assert_eq!(result, HostReachability::PortClosed);
    }

    #[tokio::test]
    async fn test_probe_host_aggregation() {
        let result = probe_host(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        assert!(result == HostReachability::Alive || result == HostReachability::PortClosed);
    }

    #[tokio::test]
    async fn test_is_alive() {
        assert!(is_alive(IpAddr::V4(Ipv4Addr::LOCALHOST)).await);
    }
}
