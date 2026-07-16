use crate::cve::client::save_cve_db;
use crate::cve::database::{CveDatabase, CveEntry, CveSeverity};

/// Обновить CVE базу из CIRCL API.
/// Для каждого сервиса из CPE_MAPPING делает запрос к CIRCL API.
pub async fn update_cve_from_sources(path: &std::path::Path) -> Result<CveDatabase, String> {
    let mut db = CveDatabase {
        entries: vec![],
        updated: chrono::Utc::now().to_rfc3339(),
        total_count: 0,
    };

    // Сервисы для которых есть CPE
    let services = [
        ("ssh", "cpe:2.3:a:openbsd:openssh"),
        ("http", "cpe:2.3:a:apache:http_server"),
        ("http", "cpe:2.3:a:nginx:nginx"),
        ("http", "cpe:2.3:a:microsoft:internet_information_services"),
        ("ftp", "cpe:2.3:a:filezilla:filezilla_ftp_server"),
        ("mysql", "cpe:2.3:a:oracle:mysql"),
        ("redis", "cpe:2.3:a:redis:redis"),
        ("mongodb", "cpe:2.3:a:mongodb:mongodb"),
        ("elasticsearch", "cpe:2.3:a:elastic:elasticsearch"),
        ("mssql", "cpe:2.3:a:microsoft:sql_server"),
        ("postgresql", "cpe:2.3:a:postgresql:postgresql"),
    ];

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    for (_service, cpe) in services {
        let url = format!("https://cve.circl.lu/api/cvefor/{}", cpe);
        match client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(cves) = resp.json::<Vec<CirclCve>>().await {
                    for cve in cves {
                        let cvss = cve.cvss.unwrap_or(0.0);
                        if cvss <= 0.0 {
                            continue;
                        }
                        db.entries.push(CveEntry {
                            id: cve.id,
                            description: cve.summary,
                            cvss_score: cvss,
                            severity: CveSeverity::from_cvss(cvss),
                            cpe_match: cve
                                .vulnerable_configuration
                                .iter()
                                .filter(|c| c.starts_with("cpe:"))
                                .cloned()
                                .collect(),
                            affected_versions: vec![],
                        });
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: failed to fetch CVE for {}: {}", cpe, e);
            }
        }
    }

    db.total_count = db.entries.len() as u32;
    save_cve_db(&db, path).map_err(|e| e.to_string())?;
    Ok(db)
}

/// Формат ответа CIRCL API
#[derive(serde::Deserialize)]
struct CirclCve {
    id: String,
    summary: String,
    cvss: Option<f32>,
    vulnerable_configuration: Vec<String>,
}
