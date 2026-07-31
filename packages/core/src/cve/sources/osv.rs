use crate::cve::sources::{CveSource, RawCveEntry, RawVersionRange};

const OSV_QUERY: &str = "https://api.osv.dev/v1/query";

/// Extract OSV package name from a CPE 2.3 URI.
/// CPE format: cpe:2.3:a:vendor:product:...
/// OSV package name is typically just the "product" part.
fn cpe_to_osv_name(cpe: &str) -> &str {
    let parts: Vec<&str> = cpe.split(':').collect();
    // cpe:2.3:a:vendor:product -> index 4
    parts.get(4).unwrap_or(&"")
}

/// Fetch CVEs for a given CPE from OSV.dev by package name (no ecosystem).
/// This is a cross-ecosystem search — less precise but broader coverage.
pub async fn fetch_cves_for_cpe(
    client: &reqwest::Client,
    service: &str,
    cpe: &str,
) -> Vec<RawCveEntry> {
    let package_name = cpe_to_osv_name(cpe);
    if package_name.is_empty() {
        return vec![];
    }

    // OSV query requires a `version` field. `*` returns all vulns for the package
    // (we don't have a concrete version during the bulk update phase).
    let body = serde_json::json!({
        "package": {
            "name": package_name
        },
        "version": "*"
    });

    let resp = match client.post(OSV_QUERY).json(&body).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            eprintln!(
                "[aplomado] OSV API returned {} for {}",
                r.status(),
                package_name
            );
            return vec![];
        }
        Err(e) => {
            eprintln!("[aplomado] OSV request failed for {}: {}", package_name, e);
            return vec![];
        }
    };

    let result: OsvResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "[aplomado] OSV JSON parse failed for {}: {}",
                package_name, e
            );
            return vec![];
        }
    };

    let mut entries = Vec::new();
    for vuln in &result.vulns {
        let cve_id = vuln
            .aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .cloned()
            .unwrap_or_else(|| vuln.id.clone());

        let summary = vuln.summary.as_deref().unwrap_or("").to_string();
        let cvss_score = extract_osv_severity(&vuln.severity);
        let advisory_url = vuln
            .references
            .first()
            .map(|r| r.url.clone());

        let mut ranges = Vec::new();
        let mut global_fixed: Option<String> = None;
        for affected in &vuln.affected {
            for range in &affected.ranges {
                if range.type_ != "SEMVER" && range.type_ != "ECOSYSTEM" {
                    continue;
                }
                let mut introduced: Option<String> = None;
                let mut fixed: Option<String> = None;
                for event in &range.events {
                    if let Some(v) = &event.introduced {
                        introduced = Some(v.clone());
                    }
                    if let Some(v) = &event.fixed {
                        fixed = Some(v.clone());
                        global_fixed = global_fixed.take().or(fixed.clone());
                    }
                }
                ranges.push(RawVersionRange {
                    start: introduced,
                    end: fixed.clone(),
                    start_including: true,
                    end_including: false,
                });
            }
        }

        // Deduplicate ranges by (start, end)
        ranges.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
        ranges.dedup_by(|a, b| a.start == b.start && a.end == b.end);

        entries.push(RawCveEntry {
            source: CveSource::Osv,
            cve_id,
            package_name: service.to_string(),
            description: summary,
            cvss_score,
            affected_versions: ranges,
            fixed_version: global_fixed,
            advisory_url,
        });
    }

    entries
}

fn extract_osv_severity(severity: &[OsvSeverity]) -> f32 {
    for s in severity {
        if s.type_ == "CVSS_V3" {
            if let Ok(score) = s.score.parse::<f32>() {
                return score;
            }
        }
    }
    for s in severity {
        if s.type_ == "CVSS_V2" {
            if let Ok(score) = s.score.parse::<f32>() {
                return score;
            }
        }
    }
    0.0
}

// ─── OSV API response structures ───────────────────────────────────

#[derive(serde::Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(serde::Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(serde::Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    type_: String,
    score: String,
}

#[derive(serde::Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(serde::Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    type_: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(serde::Deserialize)]
struct OsvEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(serde::Deserialize)]
struct OsvReference {
    url: String,
}
