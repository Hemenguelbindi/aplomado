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
    pub package_name: String,
    pub description: String,
    pub cvss_score: f32,
    pub severity: CveSeverity,
    pub cpe_match: Vec<String>,
    pub affected_versions: Vec<VersionRange>,
    /// Версия, в которой исправлена уязвимость (например "2.4.68")
    pub fixed_version: Option<String>,
    /// URL к информации об уязвимости (например https://httpd.apache.org/security/...)
    pub advisory_url: Option<String>,
}

/// База CVE (хранится в памяти, загружается из SQLite)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CveDatabase {
    pub entries: Vec<CveEntry>,
    pub updated: String,
    pub total_count: u32,
}

/// Flat-модель для SQLite таблицы vulnerability_fixes.
/// Соответствует рекомендации по Knowledge Base.
#[derive(Debug, Clone)]
pub struct VulnerabilityFix {
    pub cve_id: String,
    pub package_name: String,
    pub affected_version_start: Option<String>,
    pub affected_version_end: Option<String>,
    pub fixed_version: Option<String>,
    pub advisory_url: Option<String>,
    pub severity: String,
    pub cvss_score: f32,
    pub description: String,
}
