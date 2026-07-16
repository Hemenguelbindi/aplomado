//! Port scanning — TCP connect scan.
//!
//! Пробуем TcpStream::connect на указанные порты.
//! Без root, без сырых сокетов. Медленнее SYN, но безопаснее.
//! Параллельно с лимитом concurrency через Semaphore.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task;

use crate::scanner::model::{PortInfo, PortState, TransportProto};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONCURRENT_PORTS: usize = 100;

/// Публичные порты по умолчанию
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090,
    9200, 27017,
];

/// Сканировать один хост на указанных портах (параллельно, с лимитом)
pub async fn scan_host(ip: IpAddr, ports: &[u16]) -> Vec<PortInfo> {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PORTS));
    let futs = ports.iter().map(|&port| {
        let sem = Arc::clone(&semaphore);
        task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let state = scan_port(ip, port).await;
            if state == PortState::Open {
                let svc = known_service(port);
                Some(PortInfo {
                    port,
                    protocol: TransportProto::Tcp,
                    state,
                    service_name: svc.to_string(),
                    service_version: None,
                    banner: None,
                    cpe: None,
                })
            } else {
                None
            }
        })
    });

    let results: Vec<PortInfo> = futures::future::join_all(futs)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect();

    results
}

/// Проверить один порт
pub async fn scan_port(ip: IpAddr, port: u16) -> PortState {
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((ip, port))).await {
        Ok(Ok(_stream)) => PortState::Open,
        Ok(Err(_)) => PortState::Closed,
        Err(_) => PortState::Filtered,
    }
}

/// Определить сервис по номеру порта
pub fn known_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        9090 => "http-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "unknown",
    }
}
