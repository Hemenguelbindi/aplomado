use crate::cve::database::{CveDatabase, CveEntry, VersionRange};
use std::sync::OnceLock;

/// Глобальная CVE база
static CVE_DB: OnceLock<std::sync::RwLock<CveDatabase>> = OnceLock::new();

/// Инициализировать глобальную CVE базу из SQLite.
pub fn init_cve_db(path: &std::path::Path) {
    let db = crate::cve::client::load_cve_db(path);
    CVE_DB.set(std::sync::RwLock::new(db)).ok();
}

/// Получить чтение из глобальной CVE базы.
/// Возвращает `None`, если база не инициализирована или лок poisoned.
pub fn get_cve_db() -> Option<std::sync::RwLockReadGuard<'static, CveDatabase>> {
    CVE_DB.get().and_then(|db| db.read().ok())
}

/// Найти CVE для сервиса и версии (из banner).
pub fn match_cves<'a>(db: &'a CveDatabase, service: &str, banner: &str) -> Vec<&'a CveEntry> {
    if banner.is_empty() || db.entries.is_empty() {
        return vec![];
    }

    let version = match crate::scanner::model::extract_version_num(service, banner) {
        Some(v) => v,
        None => return vec![],
    };

    let svc_lower = service.to_lowercase();
    let cpes = crate::cve::client::get_cpe_for_service(service);

    db.entries
        .iter()
        .filter(|entry| {
            // Match by package_name (new) or by CPE (backward compat)
            let matched = if !entry.package_name.is_empty() {
                entry.package_name == svc_lower
            } else {
                entry
                    .cpe_match
                    .iter()
                    .any(|cpe| cpes.iter().any(|known| cpe.starts_with(known)))
            };
            if !matched {
                return false;
            }
            entry
                .affected_versions
                .iter()
                .any(|range| version_in_range(&version, range))
        })
        .collect()
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
    fn test_extract_version_num_ssh() {
        assert_eq!(
            crate::scanner::model::extract_version_num("ssh", "SSH-2.0-OpenSSH_8.9p1"),
            Some("8.9p1".into())
        );
    }

    #[test]
    fn test_extract_version_num_http() {
        assert_eq!(
            crate::scanner::model::extract_version_num("http", "Server: Apache/2.4.49"),
            Some("2.4.49".into())
        );
    }

    #[test]
    fn test_extract_version_num_ftp() {
        assert_eq!(
            crate::scanner::model::extract_version_num("ftp", "220 ProFTPD 1.3.5 Server"),
            Some("1.3.5".into())
        );
    }

    #[test]
    fn test_extract_version_num_mysql() {
        assert_eq!(
            crate::scanner::model::extract_version_num("mysql", "MySQL 5.7.35"),
            Some("5.7.35".into())
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
