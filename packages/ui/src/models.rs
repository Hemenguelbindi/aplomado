//! Модели данных для UI.
//! Все общие типы приходят из `peregrine-types` — единого источника истины.
//! В этом файле остаются только UI-специфичные типы.

pub use peregrine_types::{
    ScanTarget, HostInfo, PortInfo, Hop, CveSummary,
    TransportProto, PortState, ScanResult,
    extract_version, extract_version_num,
    COMMON_PORTS, QUICK_PORTS, FULL_PORTS, VULN_PORTS, CAMERAS_PORTS,
};

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
