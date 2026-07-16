//! Ping sweep — проверка доступности хоста.
//!
//! Используем TCP connect ping (не ICMP — требует root).
//! Пробуем подключиться на порты 80, 443, 22, 53.
//! Если хотя бы один ответил — хост жив.
//! Все порты проверяются параллельно для ускорения.

use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;

const PROBE_PORTS: &[u16] = &[80, 443, 22, 53, 8080, 8443];
const PING_TIMEOUT: Duration = Duration::from_secs(2);

/// Проверить, жив ли хост (параллельный TCP connect к популярным портам)
pub async fn is_alive(ip: IpAddr) -> bool {
    let futs = PROBE_PORTS.iter().map(|&port| async move {
        tokio::time::timeout(PING_TIMEOUT, TcpStream::connect((ip, port)))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some()
    });

    futures::future::join_all(futs)
        .await
        .into_iter()
        .any(|alive| alive)
}

/// Проверить хост через конкретный порт (быстрее если порт известен)
pub async fn is_alive_on_port(ip: IpAddr, port: u16) -> bool {
    tokio::time::timeout(PING_TIMEOUT, TcpStream::connect((ip, port)))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
}

// TODO: ICMP ping через socket2 (требует CAP_NET_RAW или root)
