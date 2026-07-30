use std::path::Path;

use crate::cve::database::CveDatabase;

#[cfg(feature = "database")]
use crate::cve::database::{CveEntry, CveSeverity, VersionRange, VulnerabilityFix};

/// Загрузить CVE базу из SQLite.
/// Если БД не существует или произошла ошибка — возвращается пустая база.
pub fn load_cve_db(_path: &Path) -> CveDatabase {
    #[cfg(feature = "database")]
    {
        let fixes = load_all_fixes(_path);
        if !fixes.is_empty() {
            return fixes_to_database(&fixes);
        }
    }
    CveDatabase::default()
}

/// Сохранить CVE базу в SQLite (перезаписывает все записи).
pub fn save_cve_db(_db: &CveDatabase, _path: &Path) -> std::io::Result<()> {
    if let Some(parent) = _path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(feature = "database")]
    {
        let fixes = database_to_fixes(_db);
        save_fixes(_path, &fixes).map_err(std::io::Error::other)?;
    }
    Ok(())
}

// ─── SQLite operations ────────────────────────────────────────────

/// Открыть (и создать при необходимости) SQLite БД уязвимостей.
#[cfg(feature = "database")]
fn open_vuln_db(path: &Path) -> Result<rusqlite::Connection, String> {
    let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;

    // WAL mode for concurrent reads during BG update
    conn.execute_batch("PRAGMA journal_mode=WAL;").ok();
    conn.execute_batch("PRAGMA foreign_keys=OFF;").ok();

    // Migration: add columns if missing (older DB schema)
    conn.execute_batch(
        "ALTER TABLE vulnerability_fixes ADD COLUMN start_including INTEGER NOT NULL DEFAULT 1;",
    )
    .ok();
    conn.execute_batch(
        "ALTER TABLE vulnerability_fixes ADD COLUMN end_including INTEGER NOT NULL DEFAULT 1;",
    )
    .ok();

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vulnerability_fixes (
            cve_id TEXT NOT NULL,
            package_name TEXT NOT NULL,
            affected_version_start TEXT,
            affected_version_end TEXT,
            start_including INTEGER NOT NULL DEFAULT 1,
            end_including INTEGER NOT NULL DEFAULT 1,
            fixed_version TEXT,
            advisory_url TEXT,
            severity TEXT NOT NULL,
            cvss_score REAL NOT NULL DEFAULT 0.0,
            description TEXT NOT NULL DEFAULT ''
        );",
    )
    .map_err(|e| e.to_string())?;

    Ok(conn)
}

/// Загрузить все записи из SQLite.
#[cfg(feature = "database")]
fn load_all_fixes(path: &Path) -> Vec<VulnerabilityFix> {
    let conn = match open_vuln_db(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut stmt = match conn.prepare(
        "SELECT cve_id, package_name, affected_version_start, affected_version_end,
                start_including, end_including,
                fixed_version, advisory_url, severity, cvss_score, description
         FROM vulnerability_fixes",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let fixes = stmt.query_map([], |row| {
        Ok(VulnerabilityFix {
            cve_id: row.get(0)?,
            package_name: row.get(1)?,
            affected_version_start: row.get(2)?,
            affected_version_end: row.get(3)?,
            start_including: row.get::<_, i32>(4)? != 0,
            end_including: row.get::<_, i32>(5)? != 0,
            fixed_version: row.get(6)?,
            advisory_url: row.get(7)?,
            severity: row.get(8)?,
            cvss_score: row.get(9)?,
            description: row.get(10)?,
        })
    });
    match fixes {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    }
}

/// Сохранить записи в SQLite (полная перезапись).
#[cfg(feature = "database")]
fn save_fixes(path: &Path, fixes: &[VulnerabilityFix]) -> Result<(), String> {
    let conn = open_vuln_db(path)?;
    conn.execute("DELETE FROM vulnerability_fixes", [])
        .map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "INSERT INTO vulnerability_fixes
             (cve_id, package_name, affected_version_start, affected_version_end,
              start_including, end_including,
              fixed_version, advisory_url, severity, cvss_score, description)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .map_err(|e| e.to_string())?;

    for fix in fixes {
        stmt.execute(rusqlite::params![
            fix.cve_id,
            fix.package_name,
            fix.affected_version_start,
            fix.affected_version_end,
            fix.start_including as i32,
            fix.end_including as i32,
            fix.fixed_version,
            fix.advisory_url,
            fix.severity,
            fix.cvss_score,
            fix.description,
        ])
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ─── Conversion helpers ───────────────────────────────────────────

/// Сконвертировать Vec<VulnerabilityFix> в CveDatabase (in-memory модель).
/// Группирует строки с одинаковым (cve_id, package_name) в один CveEntry
/// с множественными VersionRange.
#[cfg(feature = "database")]
fn fixes_to_database(fixes: &[VulnerabilityFix]) -> CveDatabase {
    use std::collections::HashMap;

    let mut entries: HashMap<(String, String), CveEntry> = HashMap::new();

    for fix in fixes {
        let key = (fix.cve_id.clone(), fix.package_name.clone());
        let cpes = get_cpe_for_service(&fix.package_name);
        let range = VersionRange {
            start: fix.affected_version_start.clone().unwrap_or_default(),
            end: fix.affected_version_end.clone().unwrap_or_default(),
            start_including: fix.start_including,
            end_including: fix.end_including,
        };

        if let Some(entry) = entries.get_mut(&key) {
            entry.affected_versions.push(range);
        } else {
            entries.insert(key, CveEntry {
                id: fix.cve_id.clone(),
                package_name: fix.package_name.clone(),
                description: fix.description.clone(),
                cvss_score: fix.cvss_score,
                severity: CveSeverity::from_cvss(fix.cvss_score),
                cpe_match: cpes.iter().map(|s| s.to_string()).collect(),
                affected_versions: vec![range],
                fixed_version: fix.fixed_version.clone(),
                advisory_url: fix.advisory_url.clone(),
            });
        }
    }

    let mut db = CveDatabase::default();
    db.entries = entries.into_values().collect();
    db.updated = chrono::Utc::now().to_rfc3339();
    db.total_count = db.entries.len() as u32;
    db
}

/// Сконвертировать CveDatabase в Vec<VulnerabilityFix> (для SQLite).
/// Создаёт одну строку на каждый VersionRange, сохраняя start_including/end_including.
#[cfg(feature = "database")]
fn database_to_fixes(db: &CveDatabase) -> Vec<VulnerabilityFix> {
    let mut fixes = Vec::new();
    for entry in &db.entries {
        if entry.affected_versions.is_empty() {
            fixes.push(VulnerabilityFix {
                cve_id: entry.id.clone(),
                package_name: entry.package_name.clone(),
                affected_version_start: None,
                affected_version_end: None,
                start_including: true,
                end_including: true,
                fixed_version: entry.fixed_version.clone(),
                advisory_url: entry.advisory_url.clone(),
                severity: entry.severity.as_str().to_string(),
                cvss_score: entry.cvss_score,
                description: entry.description.clone(),
            });
        } else {
            for range in &entry.affected_versions {
                let start = if range.start.is_empty() {
                    None
                } else {
                    Some(range.start.clone())
                };
                let end = if range.end.is_empty() {
                    None
                } else {
                    Some(range.end.clone())
                };
                fixes.push(VulnerabilityFix {
                    cve_id: entry.id.clone(),
                    package_name: entry.package_name.clone(),
                    affected_version_start: start,
                    affected_version_end: end,
                    start_including: range.start_including,
                    end_including: range.end_including,
                    fixed_version: entry.fixed_version.clone(),
                    advisory_url: entry.advisory_url.clone(),
                    severity: entry.severity.as_str().to_string(),
                    cvss_score: entry.cvss_score,
                    description: entry.description.clone(),
                });
            }
        }
    }
    fixes
}

// ─── CPE mapping (unchanged) ──────────────────────────────────────

/// CPE → сервис mapping для запросов к CIRCL API
pub const CPE_MAPPING: &[(&str, &[&str])] = &[
    ("ssh", &["cpe:2.3:a:openbsd:openssh"]),
    (
        "http",
        &[
            "cpe:2.3:a:apache:http_server",
            "cpe:2.3:a:nginx:nginx",
            "cpe:2.3:a:apache:tomcat",
            "cpe:2.3:a:microsoft:internet_information_services",
        ],
    ),
    (
        "https",
        &[
            "cpe:2.3:a:apache:http_server",
            "cpe:2.3:a:nginx:nginx",
            "cpe:2.3:a:microsoft:internet_information_services",
        ],
    ),
    (
        "ftp",
        &[
            "cpe:2.3:a:vsftpd:vsftpd",
            "cpe:2.3:a:proftpd:proftpd",
            "cpe:2.3:a:pureftpd:pure-ftpd",
        ],
    ),
    ("mysql", &["cpe:2.3:a:oracle:mysql", "cpe:2.3:a:mariadb:mariadb"]),
    ("mssql", &["cpe:2.3:a:microsoft:sql_server"]),
    ("postgresql", &["cpe:2.3:a:postgresql:postgresql"]),
    ("redis", &["cpe:2.3:a:redis:redis"]),
    ("mongodb", &["cpe:2.3:a:mongodb:mongodb"]),
    ("elasticsearch", &["cpe:2.3:a:elastic:elasticsearch"]),
    ("oracle", &["cpe:2.3:a:oracle:oracle_database"]),
    ("smb", &["cpe:2.3:a:microsoft:windows_smb"]),
    ("rdp", &["cpe:2.3:a:microsoft:remote_desktop"]),
    (
        "vnc",
        &[
            "cpe:2.3:a:realvnc:vnc",
            "cpe:2.3:a:tigervnc:tigervnc",
            "cpe:2.3:a:tightvnc:tightvnc",
        ],
    ),
    ("nfs", &["cpe:2.3:a:linux:nfs-utils"]),
    ("dns", &["cpe:2.3:a:isc:bind", "cpe:2.3:a:nlnetlabs:unbound"]),
    ("netbios", &["cpe:2.3:a:samba:samba"]),
    ("imap", &["cpe:2.3:a:cyrus:imap"]),
    ("pop3", &["cpe:2.3:a:cyrus:pop3d"]),
    (
        "smtp",
        &[
            "cpe:2.3:a:postfix:postfix",
            "cpe:2.3:a:exim:exim",
            "cpe:2.3:a:proofpoint:sendmail",
            "cpe:2.3:a:openbsd:opensmtpd",
        ],
    ),
    (
        "http-proxy",
        &[
            "cpe:2.3:a:apache:http_server",
            "cpe:2.3:a:squid-cache:squid",
        ],
    ),
    (
        "https-alt",
        &["cpe:2.3:a:apache:http_server", "cpe:2.3:a:nginx:nginx"],
    ),
    (
        "http-alt",
        &["cpe:2.3:a:apache:http_server", "cpe:2.3:a:nginx:nginx"],
    ),
];

/// Получить CPE для сервиса (известные имена)
pub fn get_cpe_for_service(service: &str) -> Vec<&'static str> {
    let svc = service.to_lowercase();
    let svc = match svc.as_str() {
        "http-alt" | "http-proxy" => "http",
        "https-alt" => "https",
        other => other,
    };
    CPE_MAPPING
        .iter()
        .find(|(name, _)| *name == svc)
        .map(|(_, cpes)| cpes.to_vec())
        .unwrap_or_default()
}
