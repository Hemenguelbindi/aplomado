//! Server Functions для Kestrel scanner.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Флаг — была ли уже инициализирована БД
static DB_INIT: OnceLock<bool> = OnceLock::new();

/// Инициализировать БД (если не была инициализирована).
/// Вызывается при старте сервера перед любым сканированием.
fn ensure_db() {
    DB_INIT.get_or_init(|| {
        #[cfg(feature = "server")]
        {
            // Создать таблицы, если нет
            if let Err(e) = kestrel_core::database::init_db() {
                eprintln!("[kestrel] DB init error: {e}");
            } else {
                // Мигрировать старые JSON файлы
                if let Err(e) = kestrel_core::database::migrate_from_json() {
                    eprintln!("[kestrel] DB migration error: {e}");
                } else {
                    eprintln!("[kestrel] SQLite DB ready");
                }
            }
        }
        true
    });
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub ip: String,
    pub alive: bool,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub ports: Vec<PortInfo>,
    pub route: Vec<HopInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopInfo {
    pub hop: u32,
    pub ip: String,
    pub rtt_ms: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}

/// Server function: запуск сканирования.
/// Реальная реализация — только на сервере (cfg feature = "server").
#[post("/api/scan")]
pub async fn run_scan(req: ScanRequest) -> Result<Vec<ScanResult>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        run_scan_on_server(req).await
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = req;
        Err(ServerFnError::new("Scan only available on server"))
    }
}

/// Per-host timeout: if a host doesn't respond within this duration, mark as dead.
#[cfg(feature = "server")]
const HOST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(feature = "server")]
async fn run_scan_on_server(req: ScanRequest) -> Result<Vec<ScanResult>, ServerFnError> {
    // Инициализировать БД при первом запуске
    ensure_db();

    // Install rustls ring provider BEFORE any network call (reqwest, tokio-rustls, etc.)
    kestrel_core::fingerprint::banner::ensure_crypto_provider();

    // 1. Собрать все IP из всех целей
    let mut all_ips = Vec::new();
    for target_str in &req.targets {
        all_ips.extend(resolve_ips(target_str));
    }

    // 2. Сканировать параллельно с лимитом
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(50)); // макс 50 хостов одновременно
    let ports = req.ports.clone();
    let mut handles = Vec::new();

    for ip in all_ips {
        let sem = std::sync::Arc::clone(&semaphore);
        let ports = ports.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.map_err(|_| ());
            
            let alive = tokio::time::timeout(
                HOST_TIMEOUT,
                kestrel_core::scanner::ping::is_alive(ip),
            )
            .await
            .unwrap_or(false);

            let mut ports_vec = Vec::new();
            if alive {
                // port scan использует scan_host (параллельно по портам внутри)
                let open_ports = kestrel_core::scanner::port::scan_host(ip, &ports).await;
                for p in open_ports {
                    let banner = kestrel_core::fingerprint::banner::grab_banner(
                        &ip.to_string(), p.port,
                    ).await;
                    let version = banner.as_ref().and_then(|b| extract_ver(&p.service_name, b));
                    ports_vec.push(PortInfo {
                        port: p.port,
                        service: p.service_name,
                        version,
                        banner,
                    });
                }
            }

            // OS detection по баннерам
            let os_guess = {
                let ports_for_os: Vec<(u16, String, Option<String>)> = ports_vec.iter()
                    .map(|p| (p.port, p.service.clone(), p.banner.clone()))
                    .collect();
                kestrel_core::fingerprint::os::guess_os(&ports_for_os)
            };

            // Traceroute — реальный маршрут до хоста
            let hops = if alive {
                kestrel_core::traceroute::trace(ip).await
            } else {
                vec![]
            };
            let route: Vec<HopInfo> = hops.into_iter().map(|h| HopInfo {
                hop: h.hop,
                ip: h.ip.to_string(),
                rtt_ms: h.rtt_ms,
            }).collect();

            ScanResult {
                ip: ip.to_string(),
                alive,
                hostname: None,
                os_guess,
                ports: ports_vec,
                route,
            }
        }));
    }

    // 3. Собрать результаты
    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    Ok(results)
}

/// Resolve target string to list of IP addresses.
/// Uses kestrel_core for CIDR expansion (safe, guarded).
#[cfg(feature = "server")]
fn resolve_ips(s: &str) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, ToSocketAddrs};
    use std::str::FromStr;

    let s = s.trim();

    // Single IP
    if let Ok(ip) = IpAddr::from_str(s) {
        return vec![ip];
    }

    // CIDR — delegate to kestrel_core (has overflow guard)
    if s.contains('/') {
        return kestrel_core::scanner::expand_cidr(s);
    }

    // Hostname — DNS resolve
    if let Ok(addrs) = (s, 0u16).to_socket_addrs() {
        return addrs.map(|a| a.ip()).collect();
    }

    vec![]
}

/// Извлечь версию сервиса из баннера.
/// Делегирует в kestrel-core для единообразия.
#[cfg(feature = "server")]
pub fn extract_ver(service: &str, banner: &str) -> Option<String> {
    kestrel_core::scanner::model::extract_version(service, banner)
}

/// ---- Server functions для сессий сканирования ----

/// Создать новую сессию.
#[post("/api/session/create")]
pub async fn create_session(name: String) -> Result<String, ServerFnError> {
    #[cfg(feature = "server")]
    {
        ensure_db();
        let id = format!("ses_{}", chrono::Utc::now().timestamp_millis());
        let now = chrono::Utc::now().to_rfc3339();
        let session = kestrel_core::database::SessionData {
            id: id.clone(),
            name,
            targets: vec![],
            status: "Idle".into(),
            created_at: now.clone(),
            updated_at: now,
            hosts_json: "[]".into(),
            duration_secs: 0,
        };
        kestrel_core::database::save_session(&session)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(id)
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = name;
        Err(ServerFnError::new("Server only"))
    }
}

/// Сохранить сессию.
#[post("/api/session/save")]
pub async fn save_session(data: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        ensure_db();
        let session: kestrel_core::database::SessionData = serde_json::from_str(&data)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        kestrel_core::database::save_session(&session)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = data;
        Err(ServerFnError::new("Server only"))
    }
}

/// Загрузить сессию.
#[post("/api/session/get")]
pub async fn get_session(id: String) -> Result<Option<String>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        ensure_db();
        match kestrel_core::database::load_session(&id) {
            Ok(Some(s)) => {
                let json = serde_json::to_string(&s)
                    .map_err(|e| ServerFnError::new(e.to_string()))?;
                Ok(Some(json))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ServerFnError::new(e.to_string())),
        }
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = id;
        Err(ServerFnError::new("Server only"))
    }
}

/// Список сессий.
#[get("/api/session/list")]
pub async fn list_sessions() -> Result<Vec<String>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        ensure_db();
        match kestrel_core::database::list_sessions() {
            Ok(sessions) => {
                let items: Vec<String> = sessions.iter().map(|s| {
                    serde_json::to_string(s).unwrap_or_default()
                }).collect();
                Ok(items)
            }
            Err(e) => Err(ServerFnError::new(e.to_string())),
        }
    }
    #[cfg(not(feature = "server"))]
    {
        Ok(vec![])
    }
}

/// Удалить сессию.
#[post("/api/session/delete")]
pub async fn delete_session(id: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        kestrel_core::database::delete_session(&id)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = id;
        Err(ServerFnError::new("Server only"))
    }
}

/// Server function: загрузить последний скан из истории (для восстановления после перезагрузки).
#[get("/api/last_scan")]
pub async fn get_last_scan() -> Result<Option<LastScanData>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        get_last_scan_impl().await
    }
    #[cfg(not(feature = "server"))]
    {
        Ok(None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastScanData {
    pub hosts: Vec<ScanResult>,
    pub targets: Vec<String>,
    pub status: String, // "Done" | "Error" | "Idle"
    pub count: u32,
}

#[cfg(feature = "server")]
async fn get_last_scan_impl() -> Result<Option<LastScanData>, ServerFnError> {
    ensure_db();
    match kestrel_core::history::load_last_scan() {
        Some(record) => {
            let hosts: Vec<ScanResult> = record.hosts.iter().map(|h| {
                ScanResult {
                    ip: h.ip.clone(),
                    alive: h.alive,
                    hostname: h.hostname.clone(),
                    os_guess: h.os_guess.clone(),
                    ports: h.ports.iter().map(|p| PortInfo {
                        port: p.port,
                        service: p.service.clone(),
                        version: p.version.clone(),
                        banner: p.banner.clone(),
                    }).collect(),
                    route: vec![],
                }
            }).collect();
            Ok(Some(LastScanData {
                hosts,
                targets: record.targets.clone(),
                status: format!("Done({})", record.hosts_alive),
                count: record.hosts_alive,
            }))
        }
        None => Ok(None),
    }
}
