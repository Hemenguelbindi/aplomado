//! Shared data models for Aplomado Vulnerability Scanner.
//!
//! This crate is the **single source of truth** for all data types
//! shared across `aplomado-core`, `ui`, `api`, `web`, `desktop`, and
//! `mobile`.  No crate in the workspace should define its own version
//! of these types — import them from here instead.
//!
//! ## Design
//!
//! - Minimal dependencies: only `serde` for serialisation.
//! - All types implement `Serialize` + `Deserialize` so they can travel
//!   across the wire (server functions, IPC, file storage).
//! - `IpAddr` is used natively — it serialises to a human-readable
//!   string via serde so it is wire-compatible with old `String`-based
//!   representations.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// How to resolve/find a scan target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanTarget {
    Ip(IpAddr),
    Range(IpAddr, IpAddr),
    Cidr(String),
    Hostname(String),
}

/// Transport-layer protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransportProto {
    Tcp,
    Udp,
}

/// Observed state of a port after probing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A single hop discovered during a traceroute.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hop {
    pub hop: u32,
    pub ip: IpAddr,
    pub rtt_ms: Option<f32>,
}

impl std::fmt::Display for Hop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.rtt_ms {
            Some(ms) => write!(f, "{}. {} ({}ms)", self.hop, self.ip, ms as u32),
            None => write!(f, "{}. {}", self.hop, self.ip),
        }
    }
}

/// Summary of a CVE vulnerability associated with a service/port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CveSummary {
    pub id: String,
    pub severity: String,
    pub cvss_score: f32,
    #[serde(default)]
    pub fixed_version: Option<String>,
    #[serde(default)]
    pub advisory_url: Option<String>,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub method: String,
}

/// Information about a single open/closed/filtered port on a host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: TransportProto,
    pub state: PortState,
    pub service_name: String,
    pub service_version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Option<String>,
    pub cves: Vec<CveSummary>,
}

/// Information about a scanned host (IP, alive, ports, route, etc.).
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

/// Aggregate result of scanning one or more targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanResult {
    pub target: ScanTarget,
    pub hosts: Vec<HostInfo>,
    pub duration_ms: u64,
    pub ports_scanned: u32,
    pub hosts_found: u32,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract a human-readable version string from a service banner.
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

/// Extract a clean version number from a banner (for CVE matching).
/// Returns only the numeric portion (without service prefixes).
pub fn extract_version_num(service: &str, banner: &str) -> Option<String> {
    match service {
        "ssh" => banner.split('_').nth(1).map(|v| v.to_string()),
        "http" | "https" | "http-proxy" | "https-alt" | "http-alt" => {
            let s = if banner.to_lowercase().starts_with("server:") {
                banner.trim_start_matches("Server:").trim()
            } else {
                banner
            };
            s.split('/').nth(1).map(|v| v.to_string())
        }
        "ftp" => banner
            .split_whitespace()
            .find(|s| s.chars().any(|c| c.is_ascii_digit()) && s.contains('.'))
            .map(|v| v.to_string()),
        "mysql" => banner.strip_prefix("MySQL ").map(|v| v.to_string()),
        _ => banner
            .split(|c: char| !c.is_ascii_digit() && c != '.')
            .filter(|s| !s.is_empty())
            .find(|s| s.chars().filter(|c| *c == '.').count() >= 1)
            .map(|v| v.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Default port lists (scan presets reference these)
// ---------------------------------------------------------------------------

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306,
    3389, 5432, 5900, 6379, 8080, 8443, 9090, 9200, 27017,
];

pub const QUICK_PORTS: &[u16] = &[22, 80, 443, 8080, 3389];

pub const FULL_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306,
    3389, 5432, 5900, 6379, 8080, 8443, 9090, 9200, 27017, 8888, 9999, 10000, 2082, 2083, 2087,
    2096, 3000, 5000, 8000, 9300, 27018, 27019,
];

pub const VULN_PORTS: &[u16] = &[
    21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9200, 27017,
];

pub const CAMERAS_PORTS: &[u16] = &[
    80, 443, 554, 8000, 34567, 37777, 37778, 8080, 8443, 8554, 8899, 7070, 9000, 21,
];
