use crate::cve::sources::{CveSource, RawCveEntry, RawVersionRange};

const NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// NVD API 2.0 requires at least 6 CPE fields (part:vendor:product:version)
/// and the version field must not be `*`. Our CPEs may be truncated
/// (e.g. `cpe:2.3:a:openbsd:openssh` — 5 fields, no version). Append `:-`
/// to set version="any" where missing.
fn normalize_cpe_for_nvd(cpe: &str) -> String {
    let field_count = cpe.split(':').count();
    if field_count < 6 {
        // Add version=NA (-) and remaining wildcards for full 13-field CPE
        let suffix_count = 13 - field_count;
        let mut result = cpe.to_string();
        for i in 0..suffix_count {
            result.push(':');
            result.push(if i == 0 { '-' } else { '*' });
        }
        result
    } else {
        cpe.to_string()
    }
}

/// Fetch CVEs for a given CPE from the NVD API 2.0.
/// Rate-limited to 5 requests per 30 seconds (free tier).
pub async fn fetch_cves_for_cpe(
    client: &reqwest::Client,
    service: &str,
    cpe: &str,
) -> Vec<RawCveEntry> {
    let full_cpe = normalize_cpe_for_nvd(cpe);

    let resp = match client
        .get(NVD_BASE)
        .query(&[
            ("cpeName", full_cpe.as_str()),
            ("resultsPerPage", "200"),
        ])
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            eprintln!("[aplomado] NVD API returned {} for {}", r.status(), cpe);
            return vec![];
        }
        Err(e) => {
            eprintln!("[aplomado] NVD request failed for {}: {}", cpe, e);
            return vec![];
        }
    };

    let body: NvdResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[aplomado] NVD JSON parse failed for {}: {}", cpe, e);
            return vec![];
        }
    };

    let mut entries = Vec::new();
    for vuln in &body.vulnerabilities {
        let meta = &vuln.cve;
        if meta.vuln_status.as_deref() == Some("Rejected") {
            continue;
        }

        let description = meta
            .descriptions
            .iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value.as_str())
            .unwrap_or("")
            .to_string();

        let cvss_score = extract_nvd_cvss(&meta.metrics);
        let advisory_url = meta.references.first().map(|r| r.url.clone());

        let mut ranges = Vec::new();
        for config in &meta.configurations {
            collect_cpe_ranges(config, cpe, &mut ranges);
        }

        entries.push(RawCveEntry {
            source: CveSource::Nvd,
            cve_id: meta.id.clone(),
            package_name: service.to_string(),
            description,
            cvss_score,
            affected_versions: ranges,
            fixed_version: None,
            advisory_url,
        });
    }
    entries
}

/// Recursively extract CPE version ranges matching the target CPE.
fn collect_cpe_ranges(
    config: &NvdConfig,
    target_cpe: &str,
    ranges: &mut Vec<RawVersionRange>,
) {
    for node in &config.nodes {
        for m in &node.cpeMatch {
            if m.vulnerable && m.criteria.starts_with(
                &target_cpe[..target_cpe
                    .rfind(':')
                    .map(|i| i + 1)
                    .unwrap_or(target_cpe.len())],
            ) {
                // Only add if at least one bound is specified
                if m.versionStartIncluding.is_some()
                    || m.versionStartExcluding.is_some()
                    || m.versionEndIncluding.is_some()
                    || m.versionEndExcluding.is_some()
                {
                    let (start, start_including) = match (
                        &m.versionStartIncluding,
                        &m.versionStartExcluding,
                    ) {
                        (Some(s), _) => (Some(s.clone()), true),
                        (_, Some(s)) => (Some(s.clone()), false),
                        _ => (None, true),
                    };
                    let (end, end_including) = match (&m.versionEndIncluding, &m.versionEndExcluding)
                    {
                        (Some(s), _) => (Some(s.clone()), true),
                        (_, Some(s)) => (Some(s.clone()), false),
                        _ => (None, true),
                    };
                    ranges.push(RawVersionRange {
                        start,
                        end,
                        start_including,
                        end_including,
                    });
                }
            }
        }
    }
    // Recurse into sub-configurations (AND/OR nesting)
    for child in &config.configurations {
        collect_cpe_ranges(child, target_cpe, ranges);
    }
}

fn extract_nvd_cvss(metrics: &Option<NvdMetrics>) -> f32 {
    let m = match metrics {
        Some(m) => m,
        None => return 0.0,
    };
    if let Some(arr) = &m.cvssMetricV31 {
        if let Some(first) = arr.first() {
            return first.cvssData.baseScore;
        }
    }
    if let Some(arr) = &m.cvssMetricV30 {
        if let Some(first) = arr.first() {
            return first.cvssData.baseScore;
        }
    }
    if let Some(arr) = &m.cvssMetricV2 {
        if let Some(first) = arr.first() {
            return first.cvssData.baseScore;
        }
    }
    0.0
}

// ─── NVD API 2.0 response structures ───────────────────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdResponse {
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdVulnerability {
    cve: NvdCveItem,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdCveItem {
    id: String,
    #[serde(default)]
    vuln_status: Option<String>,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: Option<NvdMetrics>,
    #[serde(default)]
    configurations: Vec<NvdConfig>,
    #[serde(default)]
    references: Vec<NvdReference>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdMetrics {
    #[serde(default)]
    cvssMetricV31: Option<Vec<NvdCvssMetric>>,
    #[serde(default)]
    cvssMetricV30: Option<Vec<NvdCvssMetric>>,
    #[serde(default)]
    cvssMetricV2: Option<Vec<NvdCvssMetric>>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdCvssMetric {
    cvssData: NvdCvssData,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdCvssData {
    #[serde(default)]
    baseScore: f32,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdConfig {
    #[serde(default)]
    nodes: Vec<NvdNode>,
    #[serde(default)]
    configurations: Vec<NvdConfig>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdNode {
    #[serde(default)]
    cpeMatch: Vec<NvdCpeMatch>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdCpeMatch {
    #[serde(default)]
    vulnerable: bool,
    #[serde(default)]
    criteria: String,
    #[serde(default)]
    versionStartIncluding: Option<String>,
    #[serde(default)]
    versionStartExcluding: Option<String>,
    #[serde(default)]
    versionEndIncluding: Option<String>,
    #[serde(default)]
    versionEndExcluding: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(non_snake_case)]
struct NvdReference {
    url: String,
}
