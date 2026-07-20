#![allow(non_snake_case, dead_code)]

use crate::cve::client::{save_cve_db, CPE_MAPPING};
use crate::cve::database::{CveDatabase, CveSeverity};

/// Обновить CVE базу из CIRCL API (Vulnerability-Lookup).
/// Использует новый эндпоинт `/api/vulnerability/cpesearch/{cpe}`
/// и парсит CVE 5.0 формат ответа.
pub async fn update_cve_from_sources(path: &std::path::Path) -> Result<CveDatabase, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("aplomado-vuln-scanner/0.1")
        .build()
        .map_err(|e| e.to_string())?;

    let mut all_fixes = Vec::new();

    // Используем CPE_MAPPING из client.rs — единый источник истины
    for (service, cpes) in CPE_MAPPING {
        for cpe in *cpes {
            let url = format!("https://cve.circl.lu/api/vulnerability/cpesearch/{}", cpe);
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let body_text = resp.text().await.unwrap_or_default();
                    match serde_json::from_str::<CirclResponse>(&body_text) {
                        Ok(body) => {
                            let count = body.cvelistv5.len();
                            for cve_record in body.cvelistv5 {
                                if let Some(fixes) = parse_cve_record(&cve_record, service) {
                                    all_fixes.extend(fixes);
                                }
                            }
                            if count > 0 {
                                eprintln!(
                                    "[aplomado] CIRCL: {} CVEs for {} ({})",
                                    count, service, cpe
                                );
                            }
                        }
                        Err(e) => {
                            let preview: String = body_text.chars().take(200).collect();
                            eprintln!(
                                "[aplomado] Warning: failed to parse CIRCL response for {}: {} — body preview: {:?}",
                                cpe, e, preview
                            );
                        }
                    }
                }
                Ok(resp) => {
                    eprintln!(
                        "[aplomado] Warning: CIRCL API returned {} for {}",
                        resp.status(),
                        cpe
                    );
                }
                Err(e) => {
                    eprintln!("[aplomado] Warning: failed to fetch CVE for {}: {}", cpe, e);
                }
            }
        }
    }

    // Строим CveDatabase из собранных записей
    let db = fixes_to_db_inner(&all_fixes);
    save_cve_db(&db, path).map_err(|e| e.to_string())?;

    eprintln!(
        "[aplomado] CVE database updated: {} entries from {} fixes",
        db.total_count,
        all_fixes.len()
    );
    Ok(db)
}

/// Собрать CveDatabase из плоских VulnerabilityFix записей.
fn fixes_to_db_inner(fixes: &[VulnerabilityFixInner]) -> CveDatabase {
    use crate::cve::database::CveEntry;
    use crate::cve::database::VersionRange;

    let mut db = CveDatabase::default();
    for fix in fixes {
        let cpes = crate::cve::client::get_cpe_for_service(&fix.package_name);
        let affected_versions = vec![VersionRange {
            start: fix.affected_version_start.clone().unwrap_or_default(),
            end: fix.affected_version_end.clone().unwrap_or_default(),
            start_including: fix.start_including,
            end_including: fix.end_including,
        }];
        db.entries.push(CveEntry {
            id: fix.cve_id.clone(),
            package_name: fix.package_name.clone(),
            description: fix.description.clone(),
            cvss_score: fix.cvss_score,
            severity: CveSeverity::from_cvss(fix.cvss_score),
            cpe_match: cpes.iter().map(|s| s.to_string()).collect(),
            affected_versions,
            fixed_version: fix.fixed_version.clone(),
            advisory_url: fix.advisory_url.clone(),
        });
    }
    db.updated = chrono::Utc::now().to_rfc3339();
    db.total_count = db.entries.len() as u32;
    db
}

/// Распарсить одну CVE 5.0 запись в набор VulnerabilityFixInner.
fn parse_cve_record(record: &CirclCveRecord, service: &str) -> Option<Vec<VulnerabilityFixInner>> {
    let meta = &record.cveMetadata;
    let cve_id = meta.cveId.as_str();
    let containers = &record.containers;
    let cna = &containers.cna;

    // Description (eng)
    let description = cna
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.as_str())
        .unwrap_or("")
        .to_string();

    // CVSS score — ищем в ADP, затем в CNA
    let cvss_score = extract_cvss(containers);

    // Severity
    let severity_str = CveSeverity::from_cvss(cvss_score).as_str().to_string();

    // Advisory URL
    let advisory_url = cna.references.first().map(|r| r.url.clone());

    // Affected versions
    let mut fixes = Vec::new();
    for affected in &cna.affected {
        for v in &affected.versions {
            let version_start = if v.version.is_empty() || v.version == "*" {
                None
            } else {
                Some(v.version.clone())
            };

            let (version_end, fixed_ver, end_including) =
                if !v.lessThanOrEqual.is_empty() && v.lessThanOrEqual != "*" {
                    // lessThanOrEqual: "2.4.67" → affected <= 2.4.67, fix is next
                    (
                        Some(v.lessThanOrEqual.clone()),
                        Some(v.lessThanOrEqual.clone()),
                        true,
                    )
                } else if !v.lessThan.is_empty() && v.lessThan != "*" {
                    // lessThan: "2.4.68" → affected < 2.4.68, fix is 2.4.68
                    (Some(v.lessThan.clone()), Some(v.lessThan.clone()), false)
                } else {
                    (None, None, true)
                };

            fixes.push(VulnerabilityFixInner {
                cve_id: cve_id.to_string(),
                package_name: service.to_string(),
                affected_version_start: version_start,
                affected_version_end: version_end,
                start_including: true,
                end_including,
                fixed_version: fixed_ver,
                advisory_url: advisory_url.clone(),
                severity: severity_str.clone(),
                cvss_score,
                description: description.clone(),
            });
        }
    }

    if fixes.is_empty() {
        // No version ranges — wildcard
        fixes.push(VulnerabilityFixInner {
            cve_id: cve_id.to_string(),
            package_name: service.to_string(),
            affected_version_start: None,
            affected_version_end: None,
            start_including: true,
            end_including: true,
            fixed_version: None,
            advisory_url: advisory_url.clone(),
            severity: severity_str.clone(),
            cvss_score,
            description: description.clone(),
        });
    }

    Some(fixes)
}

/// Извлечь CVSS score из CVE 5.0 контейнеров.
/// Ищет в ADP (Authorized Data Publisher), затем в CNA.
fn extract_cvss(containers: &CirclContainers) -> f32 {
    // ADP metrics
    for adp in &containers.adp {
        if let Some(score) = find_cvss_in_metrics(&adp.metrics) {
            return score;
        }
    }
    // CNA metrics
    find_cvss_in_metrics(&containers.cna.metrics).unwrap_or(0.0)
}

fn find_cvss_in_metrics(metrics: &[CirclMetric]) -> Option<f32> {
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

// ─── Внутренняя flat-модель ───────────────────────────────────────

struct VulnerabilityFixInner {
    cve_id: String,
    package_name: String,
    affected_version_start: Option<String>,
    affected_version_end: Option<String>,
    start_including: bool,
    end_including: bool,
    fixed_version: Option<String>,
    advisory_url: Option<String>,
    severity: String,
    cvss_score: f32,
    description: String,
}

// ─── CVE 5.0 format deserialization ───────────────────────────────

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
