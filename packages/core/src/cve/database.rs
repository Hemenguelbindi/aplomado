use serde::{Deserialize, Serialize};

/// Уровеньseverity CVE
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CveSeverity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl CveSeverity {
    pub fn from_cvss(score: f32) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::None
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::None => "None",
        }
    }
}

/// Диапазон затронутых версий
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    pub start: String,
    pub end: String,
    pub start_including: bool,
    pub end_including: bool,
}

/// Запись CVE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub description: String,
    pub cvss_score: f32,
    pub severity: CveSeverity,
    pub cpe_match: Vec<String>,
    pub affected_versions: Vec<VersionRange>,
}

/// База CVE (хранится в MessagePack)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CveDatabase {
    pub entries: Vec<CveEntry>,
    pub updated: String,
    pub total_count: u32,
}
