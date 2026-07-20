//! Server Functions for Peregrine scanner.

use dioxus::prelude::*;
use peregrine_types::*;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Server initialisation guard — runs exactly once.
static SERVER_INIT: OnceLock<bool> = OnceLock::new();

/// Initialise all server subsystems (DB, CVE, crypto provider).
/// Safe to call multiple times — runs only on first invocation.
fn init_server() {
    SERVER_INIT.get_or_init(|| {
        #[cfg(feature = "server")]
        {
            if let Err(e) = peregrine_core::database::init_db() {
                eprintln!("[peregrine] DB init error: {e}");
            } else {
                if let Err(e) = peregrine_core::database::migrate_from_json() {
                    eprintln!("[peregrine] DB migration error: {e}");
                } else {
                    eprintln!("[peregrine] SQLite DB ready");
                }
            }
            eprintln!("[peregrine] Initializing CVE database...");
            peregrine_core::cve::init_cve_on_startup();
            peregrine_core::fingerprint::banner::ensure_crypto_provider();
        }
        true
    });
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
}

/// Server function: запуск сканирования.
#[post("/api/scan")]
pub async fn run_scan(req: ScanRequest) -> Result<Vec<HostInfo>, ServerFnError> {
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

/// Maximum total IPs across all targets in a single scan request.
#[cfg(feature = "server")]
const MAX_TOTAL_IPS: usize = 65536;

#[cfg(feature = "server")]
async fn run_scan_on_server(req: ScanRequest) -> Result<Vec<HostInfo>, ServerFnError> {
    init_server();

    // 1. Resolve all IPs from all targets (with global limit)
    let mut all_ips: Vec<std::net::IpAddr> = Vec::new();
    for target_str in &req.targets {
        if all_ips.len() >= MAX_TOTAL_IPS {
            eprintln!("[peregrine] Target IP limit reached ({MAX_TOTAL_IPS}), truncating");
            break;
        }
        all_ips.extend(peregrine_core::scanner::resolve_target_str(target_str));
    }
    all_ips.truncate(MAX_TOTAL_IPS);

    // 2. Scan in parallel with concurrency limit (max 50 hosts)
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(50));
    let ports = req.ports;
    let mut handles = Vec::with_capacity(all_ips.len());

    for ip in all_ips {
        let sem = std::sync::Arc::clone(&semaphore);
        let ports = ports.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            peregrine_core::scanner::engine::scan_single_target(ip, &ports, None).await
        }));
    }

    // 3. Collect results
    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    Ok(results)
}

// ---------------------------------------------------------------------------
// Session CRUD
// ---------------------------------------------------------------------------

/// Создать новую сессию.
#[post("/api/session/create")]
pub async fn create_session(name: String) -> Result<String, ServerFnError> {
    #[cfg(feature = "server")]
    {
        init_server();
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let session = peregrine_core::database::SessionData {
            id: id.clone(),
            name,
            targets: vec![],
            status: "Idle".into(),
            created_at: now.clone(),
            updated_at: now,
            hosts_json: "[]".into(),
            duration_secs: 0,
        };
        peregrine_core::database::save_session(&session)
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
        init_server();
        let session: peregrine_core::database::SessionData = serde_json::from_str(&data)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        peregrine_core::database::save_session(&session)
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
        init_server();
        match peregrine_core::database::load_session(&id) {
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
        init_server();
        let sessions = peregrine_core::database::list_sessions()
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        sessions
            .iter()
            .map(|s| {
                serde_json::to_string(s)
                    .map_err(|e| ServerFnError::new(e.to_string()))
            })
            .collect()
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
        peregrine_core::database::delete_session(&id)
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
    pub hosts: Vec<HostInfo>,
    pub targets: Vec<String>,
    pub status: String,
    pub count: u32,
}

#[cfg(feature = "server")]
async fn get_last_scan_impl() -> Result<Option<LastScanData>, ServerFnError> {
    init_server();
    match peregrine_core::history::load_last_scan() {
        Some(record) => {
            let hosts: Vec<HostInfo> = record.hosts.into_iter().map(|h| h.into()).collect();
            Ok(Some(LastScanData {
                hosts,
                targets: record.targets,
                status: format!("Done({})", record.hosts_alive),
                count: record.hosts_alive,
            }))
        }
        None => Ok(None),
    }
}
