use crate::cve::database::{CveDatabase, CveEntry, VersionRange};
use std::sync::OnceLock;

/// Глобальная CVE база
static CVE_DB: OnceLock<std::sync::RwLock<CveDatabase>> = OnceLock::new();

/// Инициализировать глобальную CVE базу из файла.
pub fn init_cve_db(path: &std::path::Path) {
    let db = crate::cve::client::load_cve_db(path);
    CVE_DB
        .set(std::sync::RwLock::new(db))
        .ok();
}

/// Получить чтение из глобальной CVE базы.
pub fn get_cve_db() -> Option<std::sync::RwLockReadGuard<'static, CveDatabase>> {
    CVE_DB.get().map(|db| db.read().unwrap())
}

/// Найти CVE для сервиса и версии (из banner).
pub fn match_cves<'a>(db: &'a CveDatabase, service: &str, banner: &str) -> Vec<&'a CveEntry> {
    if banner.is_empty() || db.entries.is_empty() {
        return vec![];
    }

    let cpes = crate::cve::client::get_cpe_for_service(service);
    if cpes.is_empty() {
        return vec![];
    }

    let version = match extract_version_from_banner(service, banner) {
        Some(v) => v,
        None => return vec![],
    };

    db.entries
        .iter()
        .filter(|entry| {
            let cpe_match = entry
                .cpe_match
                .iter()
                .any(|cpe| cpes.iter().any(|known| cpe.starts_with(known)));
            if !cpe_match {
                return false;
            }
            entry
                .affected_versions
                .iter()
                .any(|range| version_in_range(&version, range))
        })
        .collect()
}

/// Извлечь версию из banner.
fn extract_version_from_banner(service: &str, banner: &str) -> Option<String> {
    match service {
        "ssh" => {
            // "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"
            banner.split('_').nth(1).map(|v| v.to_string())
        }
        "http" | "https" | "http-proxy" | "https-alt" | "http-alt" => {
            // "Server: Apache/2.4.49" or "Apache/2.4.49"
            let s = if banner.to_lowercase().starts_with("server:") {
                banner.trim_start_matches("Server:").trim()
            } else {
                banner
            };
            // "Apache/2.4.49" → "2.4.49"
            s.split('/').nth(1).map(|v| v.to_string())
        }
        "ftp" => {
            // "220 ProFTPD 1.3.5 Server"
            banner.split_whitespace().nth(1).map(|v| v.to_string())
        }
        "mysql" => {
            // "MySQL 5.7.35"
            banner.strip_prefix("MySQL ").map(|v| v.to_string())
        }
        _ => {
            // Пробуем найти числа и точки в banner
            banner
                .split(|c: char| !c.is_ascii_digit() && c != '.')
                .filter(|s| !s.is_empty())
                .find(|s| s.chars().filter(|c| *c == '.').count() >= 1)
                .map(|v| v.to_string())
        }
    }
}

/// Сравнить версии (semver-like).
fn version_in_range(version: &str, range: &VersionRange) -> bool {
    let v = parse_version(version);
    let start = parse_version(&range.start);
    let end = parse_version(&range.end);

    let v = match v {
        Some(v) => v,
        None => return false,
    };
    let start = match start {
        Some(s) => s,
        None => return true, // no lower bound
    };
    let end = match end {
        Some(e) => e,
        None => return true, // no upper bound
    };

    let after_start = if range.start_including {
        v >= start
    } else {
        v > start
    };

    let before_end = if range.end_including {
        v <= end
    } else {
        v < end
    };

    after_start && before_end
}

fn parse_version(v: &str) -> Option<Vec<u32>> {
    let parts: Vec<u32> = v.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version_ssh() {
        assert_eq!(
            extract_version_from_banner("ssh", "SSH-2.0-OpenSSH_8.9p1"),
            Some("8.9p1".into())
        );
    }

    #[test]
    fn test_extract_version_http() {
        assert_eq!(
            extract_version_from_banner("http", "Server: Apache/2.4.49"),
            Some("2.4.49".into())
        );
    }

    #[test]
    fn test_version_in_range() {
        let range = VersionRange {
            start: "2.4.0".into(),
            end: "2.4.49".into(),
            start_including: true,
            end_including: true,
        };
        assert!(version_in_range("2.4.49", &range));
        assert!(version_in_range("2.4.0", &range));
        assert!(!version_in_range("2.4.50", &range));
        assert!(!version_in_range("2.3.0", &range));
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.2.3"), Some(vec![1, 2, 3]));
        assert_eq!(parse_version("1.2"), Some(vec![1, 2]));
        assert_eq!(parse_version("abc"), None);
    }
}
