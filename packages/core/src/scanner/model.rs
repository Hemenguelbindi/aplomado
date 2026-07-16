//! Модели данных для сканера.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Цель сканирования — IP, диапазон, или хост
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanTarget {
    Ip(IpAddr),
    Range(IpAddr, IpAddr),        // start, end
    Cidr(String),                 // "10.2.0.0/24"
    Hostname(String),             // "example.com"
}

/// Информация о хосте
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostInfo {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub ttl: Option<u8>,
    pub os_guess: Option<String>,
    pub ports: Vec<PortInfo>,
    pub alive: bool,
    pub route: Vec<Hop>,
}

/// Информация о порте
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: TransportProto,
    pub state: PortState,
    pub service_name: String,        // "ssh", "http", "mysql"
    pub service_version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Option<String>,         // cpe:2.3:a:vendor:product:version
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransportProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Результат сканирования
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanResult {
    pub target: ScanTarget,
    pub hosts: Vec<HostInfo>,
    pub duration_ms: u64,
    pub ports_scanned: u32,
    pub hosts_found: u32,
}

/// Один hop трассировки маршрута
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hop {
    pub hop: u32,
    pub ip: IpAddr,
    pub rtt_ms: Option<f32>,
}

/// Извлечь версию сервиса из баннера.
/// Единая реализация — используется и на сервере, и на клиенте.
pub fn extract_version(service: &str, banner: &str) -> Option<String> {
    match service {
        "ssh" => banner.strip_prefix("SSH-2.0-").map(|s| s.to_string()),
        "http" | "https" => banner
            .lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
            .and_then(|l| l.split(':').nth(1).map(|s| s.trim().to_string())),
        "ftp" => banner.split_whitespace().nth(1).map(|s| s.to_string()),
        _ => {
            let s = banner.trim();
            if s.len() < 60 {
                Some(s.to_string())
            } else {
                Some(format!("{}...", &s[..60]))
            }
        }
    }
}
