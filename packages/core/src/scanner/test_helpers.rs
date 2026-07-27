use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::scanner::config::ScanConfig;
use crate::scanner::model::{HostInfo, PortState};
use crate::scanner::strategy::TcpConnectStrategy;

/// Bind a TCP listener on a random port, return (port, handle)
/// The listener accepts one connection, optionally sends banner bytes.
pub fn tcp_listener(banner: Option<&[u8]>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let owned_banner = banner.map(|b| b.to_vec());
    let handle = tokio::task::spawn_blocking(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            if let Some(ref b) = owned_banner {
                let _ = std::io::Write::write_all(&mut stream, b);
            }
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    (port, handle)
}

/// Run a scan with given config and return results (sequential, for tests)
pub async fn scan_with_config(
    ips: &[IpAddr],
    ports: &[u16],
    config: &ScanConfig,
) -> Vec<HostInfo> {
    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_hosts));
    let strategy = TcpConnectStrategy::new(config);
    let mut results = Vec::new();

    for &ip in ips {
        let _permit = semaphore.acquire().await.unwrap();
        let host = crate::scanner::engine::scan_with_strategy(
            &strategy,
            ip,
            ports,
            config,
            None,
        )
        .await;
        results.push(host);
        drop(_permit);
    }

    results
}

/// Assert port state with tolerance for timing
pub fn assert_port_state(host: &HostInfo, port: u16, expected_state: PortState) {
    if let Some(p) = host.ports.iter().find(|p| p.port == port) {
        assert_eq!(p.state, expected_state, "port {} state mismatch", port);
    } else {
        panic!("port {} not found in host {}", port, host.ip);
    }
}

/// Create a ScanConfig with test defaults (fast timeouts, 1 concurrent host)
pub fn test_config() -> ScanConfig {
    ScanConfig {
        max_concurrent_hosts: 1,
        connect_timeout: std::time::Duration::from_secs(2),
        adaptive_timeouts: false,
        ..ScanConfig::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::model::PortState;

    #[tokio::test]
    async fn tcp_listener_accepts_connection() {
        let (port, handle) = tcp_listener(Some(b"SSH-2.0-OpenSSH_8.9\r\n"));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        assert!(stream.peer_addr().is_ok());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_config_has_fast_timeouts() {
        let cfg = test_config();
        assert_eq!(cfg.max_concurrent_hosts, 1);
        assert!(!cfg.adaptive_timeouts);
    }

    #[tokio::test]
    async fn scan_with_config_returns_results() {
        let (port, _handle) = tcp_listener(Some(b"HTTP/1.1 200 OK\r\n"));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let results = scan_with_config(&[ip], &[port], &test_config()).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].alive);
        assert_port_state(&results[0], port, PortState::Open);
    }
}
