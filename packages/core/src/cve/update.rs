#![allow(non_snake_case, dead_code)]

use crate::cve::client::{save_cve_db, CPE_MAPPING};
use crate::cve::sources::{merge_all_sources, CveSource, RawCveEntry, RawVersionRange};

/// Update CVE database from all configured sources (CIRCL, NVD, OSV).
/// Results are merged with priority: OSV > NVD > CIRCL.
pub async fn update_cve_from_sources(path: &std::path::Path) -> Result<Vec<RawCveEntry>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("aplomado-vuln-scanner/0.1")
        .build()
        .map_err(|e| e.to_string())?;

    let circl_entries = fetch_all_circl(&client).await;
    let nvd_entries = fetch_all_nvd(&client).await;
    let osv_entries = fetch_all_osv(&client).await;

    let total_raw = circl_entries.len() + nvd_entries.len() + osv_entries.len();
    eprintln!(
        "[aplomado] CVE sources: CIRCL={}, NVD={}, OSV={}",
        circl_entries.len(),
        nvd_entries.len(),
        osv_entries.len()
    );

    let mut all_entries = Vec::with_capacity(total_raw);
    all_entries.extend(circl_entries);
    all_entries.extend(nvd_entries);
    all_entries.extend(osv_entries);

    let db = merge_all_sources(all_entries);
    save_cve_db(&db, path).map_err(|e| e.to_string())?;

    eprintln!(
        "[aplomado] CVE database updated: {} deduplicated entries from {} raw entries",
        db.total_count,
        total_raw,
    );
    Ok(db.entries.iter().map(|e| RawCveEntry {
        source: CveSource::Circl,
        cve_id: e.id.clone(),
        package_name: e.package_name.clone(),
        description: e.description.clone(),
        cvss_score: e.cvss_score,
        affected_versions: e.affected_versions.iter().map(|r| RawVersionRange {
            start: if r.start.is_empty() { None } else { Some(r.start.clone()) },
            end: if r.end.is_empty() { None } else { Some(r.end.clone()) },
            start_including: r.start_including,
            end_including: r.end_including,
        }).collect(),
        fixed_version: e.fixed_version.clone(),
        advisory_url: e.advisory_url.clone(),
    }).collect())
}

// ─── CIRCL source (parallel) ───────────────────────────────────────

async fn fetch_all_circl(client: &reqwest::Client) -> Vec<RawCveEntry> {
    let futs: Vec<_> = CPE_MAPPING
        .iter()
        .flat_map(|(service, cpes)| {
            cpes.iter()
                .map(|cpe| circl_fetch_cpe(client, service, cpe))
        })
        .collect();
    let results = futures::future::join_all(futs).await;
    let mut all = Vec::new();
    for entries in results {
        all.extend(entries);
    }
    all
}

async fn circl_fetch_cpe(
    client: &reqwest::Client,
    service: &str,
    cpe: &str,
) -> Vec<RawCveEntry> {
    let mut entries = Vec::new();
    // CIRCL cpesearch paginates by `page` (default 30/page). Fetch until empty.
    for page in 1..=50 {
        let url = format!(
            "https://cve.circl.lu/api/vulnerability/cpesearch/{}?page={}",
            cpe, page
        );
        let resp = match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                eprintln!("[aplomado] CIRCL returned {} for {} (page {})", r.status(), cpe, page);
                break;
            }
            Err(e) => {
                eprintln!("[aplomado] CIRCL request failed for {} (page {}): {}", cpe, page, e);
                break;
            }
        };

        let body_text = resp.text().await.unwrap_or_default();
        let circl: CirclResponse = match serde_json::from_str(&body_text) {
            Ok(b) => b,
            Err(e) => {
                let preview: String = body_text.chars().take(200).collect();
                eprintln!(
                    "[aplomado] CIRCL parse failed for {} (page {}): {} — preview: {:?}",
                    cpe, page, e, preview
                );
                break;
            }
        };

        let count = circl.cvelistv5.len();
        for record in &circl.cvelistv5 {
            let meta = &record.cveMetadata;
            let cve_id = meta.cveId.as_str();
            let cna = &record.containers.cna;

            let description = cna
                .descriptions
                .iter()
                .find(|d| d.lang == "en")
                .map(|d| d.value.as_str())
                .unwrap_or("")
                .to_string();

            let cvss_score = circl_extract_cvss(&record.containers);
            let advisory_url = cna.references.first().map(|r| r.url.clone());

            let mut ranges = Vec::new();
            for affected in &cna.affected {
                for v in &affected.versions {
                    let (start, start_including) = if v.version.is_empty() || v.version == "*" {
                        (None, true)
                    } else {
                        (Some(v.version.clone()), true)
                    };

                    let (end, end_including) =
                        if !v.lessThanOrEqual.is_empty() && v.lessThanOrEqual != "*" {
                            (Some(v.lessThanOrEqual.clone()), true)
                        } else if !v.lessThan.is_empty() && v.lessThan != "*" {
                            (Some(v.lessThan.clone()), false)
                        } else {
                            (None, true)
                        };

                    ranges.push(RawVersionRange {
                        start,
                        end,
                        start_including,
                        end_including,
                    });
                }
            }

            if ranges.is_empty() {
                ranges.push(RawVersionRange {
                    start: None,
                    end: None,
                    start_including: true,
                    end_including: true,
                });
            }

            entries.push(RawCveEntry {
                source: CveSource::Circl,
                cve_id: cve_id.to_string(),
                package_name: service.to_string(),
                description,
                cvss_score,
                affected_versions: ranges,
                fixed_version: None,
                advisory_url,
            });
        }

        if count > 0 {
            eprintln!(
                "[aplomado] CIRCL: {} CVEs for {} ({}) on page {}",
                count, service, cpe, page
            );
        }
        if count < 30 {
            break;
        }
    }

    entries
}

fn circl_extract_cvss(containers: &CirclContainers) -> f32 {
    for adp in &containers.adp {
        if let Some(score) = find_any_cvss(&adp.metrics) {
            return score;
        }
    }
    find_any_cvss(&containers.cna.metrics).unwrap_or(0.0)
}

fn find_any_cvss(metrics: &[CirclMetric]) -> Option<f32> {
    for m in metrics {
        if let Some(ref v3) = m.cvssV3_1 {
            return Some(v3.baseScore);
        }
        if let Some(ref v3) = m.cvssV3_0 {
            return Some(v3.baseScore);
        }
        if let Some(ref v2) = m.cvssV2_0 {
            return Some(v2.baseScore);
        }
    }
    None
}

// ─── NVD source (rate-limited, deduplicated) ───────────────────────

/// Build a unique CPE list, mapping each CPE to the services that use it.
fn unique_cpes() -> Vec<(&'static str, Vec<&'static str>)> {
    let mut map: std::collections::HashMap<&'static str, Vec<&'static str>> =
        std::collections::HashMap::new();
    for (service, cpes) in CPE_MAPPING {
        for cpe in *cpes {
            map.entry(cpe).or_default().push(service);
        }
    }
    let mut list: Vec<_> = map.into_iter().collect();
    list.sort_by_key(|(cpe, _)| *cpe);
    list
}

async fn fetch_all_nvd(client: &reqwest::Client) -> Vec<RawCveEntry> {
    let mut all = Vec::new();
    for (cpe, services) in unique_cpes() {
        // Fetch once per unique CPE
        let entries = crate::cve::sources::nvd::fetch_cves_for_cpe(client, services[0], cpe).await;
        let count = entries.len();
        // Replicate the CVE entries for every service that maps to this CPE
        for svc in &services {
            let mut svc_entries = entries.clone();
            for e in &mut svc_entries {
                e.package_name = svc.to_string();
            }
            all.extend(svc_entries);
        }
        if count > 0 {
            eprintln!(
                "[aplomado] NVD: {} CVEs for {} ({})",
                count,
                services.join("/"),
                cpe
            );
        }
        // Rate limit: 5 req / 30s free tier → 6s between requests
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    }
    all
}

// ─── OSV source (parallel) ─────────────────────────────────────────

async fn fetch_all_osv(client: &reqwest::Client) -> Vec<RawCveEntry> {
    let futs: Vec<_> = CPE_MAPPING
        .iter()
        .flat_map(|(service, cpes)| {
            cpes.iter()
                .map(|cpe| osv_fetch_with_log(client, service, cpe))
        })
        .collect();
    let results = futures::future::join_all(futs).await;
    let mut all = Vec::new();
    for entries in results {
        all.extend(entries);
    }
    all
}

async fn osv_fetch_with_log(
    client: &reqwest::Client,
    service: &str,
    cpe: &str,
) -> Vec<RawCveEntry> {
    let entries = crate::cve::sources::osv::fetch_cves_for_cpe(client, service, cpe).await;
    let count = entries.len();
    if count > 0 {
        eprintln!("[aplomado] OSV: {} CVEs for {} ({})", count, service, cpe);
    }
    entries
}

// ─── CIRCL API 5.0 deserialization ─────────────────────────────────

#[derive(serde::Deserialize)]
struct CirclResponse {
    #[serde(default)]
    cvelistv5: Vec<CirclCveRecord>,
}

#[derive(serde::Deserialize)]
struct CirclCveRecord {
    #[serde(rename = "cveMetadata")]
    cveMetadata: CirclMetadata,
    containers: CirclContainers,
}

#[derive(serde::Deserialize)]
struct CirclMetadata {
    #[serde(rename = "cveId")]
    cveId: String,
}

#[derive(serde::Deserialize)]
struct CirclContainers {
    cna: CirclCna,
    #[serde(default)]
    adp: Vec<CirclAdp>,
}

#[derive(serde::Deserialize)]
struct CirclCna {
    descriptions: Vec<CirclDescription>,
    #[serde(default)]
    affected: Vec<CirclAffected>,
    #[serde(default)]
    references: Vec<CirclReference>,
    #[serde(default)]
    metrics: Vec<CirclMetric>,
}

#[derive(serde::Deserialize)]
struct CirclDescription {
    lang: String,
    value: String,
}

#[derive(serde::Deserialize)]
struct CirclAffected {
    #[serde(default)]
    product: String,
    #[serde(default)]
    vendor: String,
    #[serde(default)]
    versions: Vec<CirclVersion>,
}

#[derive(serde::Deserialize)]
struct CirclVersion {
    #[serde(default)]
    version: String,
    #[serde(default)]
    lessThan: String,
    #[serde(default)]
    lessThanOrEqual: String,
    #[serde(default)]
    status: String,
}

#[derive(serde::Deserialize)]
struct CirclReference {
    url: String,
}

#[derive(serde::Deserialize)]
struct CirclMetric {
    #[serde(default)]
    cvssV3_1: Option<CirclCvssData>,
    #[serde(default)]
    cvssV3_0: Option<CirclCvssData>,
    #[serde(default)]
    cvssV2_0: Option<CirclCvssData>,
}

#[derive(serde::Deserialize)]
struct CirclCvssData {
    #[serde(default)]
    baseScore: f32,
}

#[derive(serde::Deserialize)]
struct CirclAdp {
    #[serde(default)]
    providerMetadata: CirclProviderMeta,
    #[serde(default)]
    metrics: Vec<CirclMetric>,
}

#[derive(Default, serde::Deserialize)]
struct CirclProviderMeta {
    #[serde(default)]
    shortName: String,
}
