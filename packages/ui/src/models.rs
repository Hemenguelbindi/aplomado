//! Модели данных для UI (дубликат из kestrel-core, но без тяжёлых зависимостей).
//! Нужны, чтобы ui компилировался под WASM.

use std::net::IpAddr;

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 9200, 27017,
];
pub const QUICK_PORTS: &[u16] = &[22, 80, 443, 8080, 3389];
pub const FULL_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090,
    9200, 27017, 8888, 9999, 10000, 2082, 2083, 2087, 2096,
    3000, 5000, 8000, 9300, 27018, 27019,
];
pub const VULN_PORTS: &[u16] = &[
    21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
];
pub const CAMERAS_PORTS: &[u16] = &[
    80, 443, 554, 8000, 34567, 37777, 37778,
    8080, 8443, 8554, 8899, 7070, 9000, 21,
];

/// Цель сканирования
#[derive(Debug, Clone, PartialEq)]
pub enum ScanTarget {
    Ip(IpAddr),
    Range(IpAddr, IpAddr),
    Cidr(String),
    Hostname(String),
}

/// Цель сканирования с конфигурацией (пресет/порты)
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ScanTargetItem {
    pub id: String,
    pub target: String,
    pub preset: ScanPreset,
    pub custom_ports: Vec<u16>,
    pub status: TargetStatus,
}

/// Статус конкретной цели
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TargetStatus {
    Queued,
    Scanning,
    Done(u32),
    Error(String),
}

/// Пресет сканирования
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ScanPreset {
    Quick,
    Standard,
    Full,
    Vulnerability,
    Cameras,
    Custom,
}

impl ScanPreset {
    pub fn ports(&self) -> Vec<u16> {
        match self {
            Self::Quick => QUICK_PORTS.to_vec(),
            Self::Standard => COMMON_PORTS.to_vec(),
            Self::Full => FULL_PORTS.to_vec(),
            Self::Vulnerability => VULN_PORTS.to_vec(),
            Self::Cameras => CAMERAS_PORTS.to_vec(),
            Self::Custom => vec![],
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::Quick => "Quick",
            Self::Standard => "Standard",
            Self::Full => "Full",
            Self::Vulnerability => "Vuln",
            Self::Cameras => "Cameras",
            Self::Custom => "Custom",
        }
    }
}

/// Один hop трассировки маршрута
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Hop {
    pub hop: u32,
    pub ip: IpAddr,
    pub rtt_ms: Option<f32>,
}

/// Информация о хосте
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub service_name: String,
    pub service_version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Option<String>,
    pub cves: Vec<CveSummary>,
}

/// Краткая информация о CVE
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CveSummary {
    pub id: String,
    pub severity: String,
    pub cvss_score: f32,
}

/// Статус сессии
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SessionStatus {
    Idle,
    Scanning,
    Done,
}

/// Сессия сканирования — именованная группа целей
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub targets: Vec<ScanTargetItem>,
    pub status: SessionStatus,
    pub created_at: String,
    pub updated_at: String,
    pub hosts: Vec<HostInfo>,
    pub duration_secs: u64,
}
