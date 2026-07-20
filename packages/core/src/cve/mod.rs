pub mod client;
pub mod database;
pub mod matcher;

#[cfg(feature = "cve-client")]
pub mod update;

pub use database::{CveDatabase, CveEntry, CveSeverity, VersionRange, VulnerabilityFix};
pub use matcher::{get_cve_db, init_cve_db, match_cves};

/// Путь к файлу CVE базы (SQLite).
/// Единое место для всех платформ — `~/.aplomado/vulnerabilities.db`.
pub fn cve_db_path() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".aplomado")
        .join("vulnerabilities.db")
}

/// Инициализировать CVE систему при старте приложения:
/// 1. Создать директорию для БД
/// 2. Загрузить кешированную CVE базу из SQLite
/// 3. Запустить фоновое обновление (если включён `cve-client`)
pub fn init_cve_on_startup() {
    let path = cve_db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    init_cve_db(&path);

    #[cfg(feature = "cve-client")]
    {
        // Фоновое обновление — не блокируем старт
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().ok();
            if let Some(rt) = rt {
                rt.block_on(async {
                    match crate::cve::update::update_cve_from_sources(&path).await {
                        Ok(db) => {
                            // После обновления перезагрузить в глобальный кеш
                            init_cve_db(&path);
                            eprintln!(
                                "[aplomado] CVE database updated: {} entries",
                                db.total_count
                            );
                        }
                        Err(e) => eprintln!("[aplomado] CVE update failed: {e}"),
                    }
                });
            }
        });
    }
}

/// Try to update CVE database from CIRCL API (async). Returns count of entries loaded.
/// Safe to call from any platform. No-op if `cve-client` feature is disabled.
pub async fn update_cve_if_stale() -> u32 {
    #[cfg(feature = "cve-client")]
    {
        let path = cve_db_path();
        match crate::cve::update::update_cve_from_sources(&path).await {
            Ok(db) => {
                init_cve_db(&path);
                eprintln!(
                    "[aplomado] CVE database updated: {} entries",
                    db.total_count
                );
                db.total_count
            }
            Err(e) => {
                eprintln!("[aplomado] CVE update failed: {e}");
                0
            }
        }
    }
    #[cfg(not(feature = "cve-client"))]
    {
        0
    }
}
