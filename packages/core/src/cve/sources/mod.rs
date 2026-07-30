use std::collections::HashMap;

use crate::cve::client::get_cpe_for_service;
use crate::cve::database::{CveDatabase, CveEntry, CveSeverity, VersionRange};

#[cfg(feature = "cve-client")]
pub mod nvd;

#[cfg(feature = "cve-client")]
pub mod osv;

/// Source of CVE data — used for confidence ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CveSource {
    Osv = 0,    // highest priority (distro-aware)
    Nvd = 1,    // medium priority (CPE-based)
    Circl = 2,  // lowest priority (CPE-based, less curated)
}

impl CveSource {
    pub fn confidence_str(&self) -> &'static str {
        match self {
            CveSource::Osv => "high",
            CveSource::Nvd => "medium",
            CveSource::Circl => "medium",
        }
    }
}

/// Unprocessed version range from any source, before merging into CveDatabase.
#[derive(Debug, Clone)]
pub struct RawVersionRange {
    pub start: Option<String>,
    pub end: Option<String>,
    pub start_including: bool,
    pub end_including: bool,
}

/// Unprocessed CVE entry from any source.
#[derive(Debug, Clone)]
pub struct RawCveEntry {
    pub source: CveSource,
    pub cve_id: String,
    pub package_name: String,
    pub description: String,
    pub cvss_score: f32,
    pub affected_versions: Vec<RawVersionRange>,
    pub fixed_version: Option<String>,
    pub advisory_url: Option<String>,
}

/// Merge raw entries from all sources into a single CveDatabase.
/// Deduplicates by (cve_id, package_name): keeps entry from highest-priority source.
pub fn merge_all_sources(entries: Vec<RawCveEntry>) -> CveDatabase {
    let mut best: HashMap<(String, String), RawCveEntry> = HashMap::new();

    for entry in entries {
        let key = (entry.cve_id.clone(), entry.package_name.clone());
        match best.get(&key) {
            Some(existing) if entry.source >= existing.source => {
                // Existing is higher priority — merge version ranges only
                continue;
            }
            Some(existing) if entry.source < existing.source => {
                // New entry has higher priority — replace, but keep ranges from both
                let mut merged = entry;
                merged
                    .affected_versions
                    .extend(existing.affected_versions.clone());
                best.insert(key, merged);
            }
            _ => {
                best.insert(key, entry);
            }
        }
    }

    let mut db = CveDatabase::default();
    for entry in best.into_values() {
        let cpes = get_cpe_for_service(&entry.package_name);
        let affected_versions: Vec<VersionRange> = entry
            .affected_versions
            .into_iter()
            .map(|r| VersionRange {
                start: r.start.unwrap_or_default(),
                end: r.end.unwrap_or_default(),
                start_including: r.start_including,
                end_including: r.end_including,
            })
            .collect();
        db.entries.push(CveEntry {
            id: entry.cve_id,
            package_name: entry.package_name,
            description: entry.description,
            cvss_score: entry.cvss_score,
            severity: CveSeverity::from_cvss(entry.cvss_score),
            cpe_match: cpes.iter().map(|s| s.to_string()).collect(),
            affected_versions,
            fixed_version: entry.fixed_version,
            advisory_url: entry.advisory_url,
            source: entry.source.confidence_str().to_string(),
        });
    }
    db.total_count = db.entries.len() as u32;
    db
}
