//! Server Functions for Aplomado scanner.

use aplomado_types::*;
use dioxus::prelude::*;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Server initialisation guard — runs exactly once.
/// Stores `true` if all subsystems initialised successfully.
static SERVER_INIT: OnceLock<bool> = OnceLock::new();

/// Initialise all server subsystems (DB, CVE, crypto provider).
/// Safe to call multiple times — runs only on first invocation.
/// Returns `true` if initialisation succeeded or was already initialised.
fn init_server() -> bool {
    *SERVER_INIT.get_or_init(|| {
        #[cfg(feature = "server")]
        {
            let db_ok = match aplomado_core::database::init_db() {
                Ok(()) => {
                    if let Err(e) = aplomado_core::database::migrate_from_json() {
                        eprintln!("[aplomado] DB migration error: {e}");
                        false
                    } else {
                        eprintln!("[aplomado] SQLite DB ready");
                        true
                    }
                }
                Err(e) => {
                    eprintln!("[aplomado] DB init error: {e}");
                    false
                }
            };
            if db_ok {
                eprintln!("[aplomado] Initializing CVE database...");
                aplomado_core::cve::init_cve_on_startup();
            }
            aplomado_core::fingerprint::banner::ensure_crypto_provider();
            db_ok
        }
        #[cfg(not(feature = "server"))]
        {
            true
        }
    })
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

/// Maximum number of concurrent host scans.
#[cfg(feature = "server")]
const MAX_CONCURRENT_HOSTS: usize = 50;

/// Validated scan request — all targets resolved, ports validated, special addresses removed.
#[cfg(feature = "server")]
struct ValidatedScanRequest {
    ips: Vec<std::net::IpAddr>,
    ports: Vec<u16>,
}

/// Validate and resolve a raw scan request.
///
/// Checks performed:
/// - All target strings are resolvable (CIDR, IP, hostname)
/// - All ports are in 1-65535
/// - Special/denied addresses (loopback, multicast, etc.) are excluded via `ScanPolicy`
/// - Duplicate IPs are removed
/// - Total IPs do not exceed policy limit
#[cfg(feature = "server")]
fn validate_scan_request(req: &ScanRequest) -> Result<ValidatedScanRequest, ServerFnError> {
    let policy = aplomado_core::scanner::policy::ScanPolicy::default();

    // Validate ports
    if req.ports.is_empty() {
        return Err(ServerFnError::new("At least one port is required"));
    }
    let mut seen_ports = std::collections::BTreeSet::new();
    for &p in &req.ports {
        if p == 0 {
            return Err(ServerFnError::new(format!(
                "Invalid port {p} (0 is reserved)"
            )));
        }
        seen_ports.insert(p);
    }
    let ports: Vec<u16> = seen_ports.into_iter().collect();

    // Resolve and deduplicate targets
    let mut all_ips: Vec<std::net::IpAddr> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut seen_ips = std::collections::BTreeSet::new();

    for target_str in &req.targets {
        if all_ips.len() >= policy.max_ips {
            errors.push(format!(
                "Target IP limit reached ({}), truncating",
                policy.max_ips
            ));
            break;
        }
        match aplomado_core::scanner::resolve_target_str(target_str) {
            Ok(ips) => {
                for ip in ips {
                    if !policy.is_allowed(ip) {
                        continue;
                    }
                    if seen_ips.insert(ip) {
                        all_ips.push(ip);
                    }
                }
            }
            Err(e) => errors.push(format!("{target_str}: {e}")),
        }
    }
    all_ips.truncate(policy.max_ips);

    if !errors.is_empty() {
        eprintln!("[aplomado] Target resolution errors: {}", errors.join("; "));
    }
    if all_ips.is_empty() {
        let msg = if errors.is_empty() {
            "No targets resolved".to_string()
        } else {
            format!("No targets resolved: {}", errors.join("; "))
        };
        return Err(ServerFnError::new(msg));
    }

    Ok(ValidatedScanRequest {
        ips: all_ips,
        ports,
    })
}

#[cfg(feature = "server")]
async fn run_scan_on_server(req: ScanRequest) -> Result<Vec<HostInfo>, ServerFnError> {
    init_server();

    // Validate and resolve the request
    let validated = validate_scan_request(&req)?;

    // Scan with bounded concurrency using futures::stream::buffer_unordered.
    // This avoids creating N tokio tasks upfront (one per IP).
    let ports: std::sync::Arc<[u16]> = std::sync::Arc::from(validated.ports);

    let results: Vec<HostInfo> = futures::stream::iter(validated.ips)
        .map(|ip| {
            let ports = std::sync::Arc::clone(&ports);
            async move {
                let host =
                    aplomado_core::scanner::engine::scan_single_target(ip, &ports, None).await;
                (ip, host)
            }
        })
        .buffer_unordered(MAX_CONCURRENT_HOSTS)
        .collect::<Vec<(std::net::IpAddr, HostInfo)>>()
        .await
        .into_iter()
        .map(|(_ip, host)| host)
        .collect();

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
        let session = aplomado_core::database::SessionData {
            id: id.clone(),
            name,
            targets: vec![],
            status: "Idle".into(),
            created_at: now.clone(),
            updated_at: now,
            hosts_json: "[]".into(),
            duration_secs: 0,
        };
        aplomado_core::database::save_session(&session)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(id)
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = name;
        Err(ServerFnError::new("Server only"))
    }
}

/// Сохранить сессию (принимает JSON-строку сессии).
#[post("/api/session/save")]
pub async fn save_session(data: String) -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        init_server();
        let session: aplomado_core::database::SessionData =
            serde_json::from_str(&data).map_err(|e| ServerFnError::new(e.to_string()))?;
        aplomado_core::database::save_session(&session)
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = data;
        Err(ServerFnError::new("Server only"))
    }
}

/// Response type for session retrieval — avoids double-serialising `hosts_json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: String,
    pub name: String,
    pub targets: Vec<aplomado_core::database::SessionTargetData>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub hosts: Vec<HostInfo>,
    pub duration_secs: u64,
}

impl From<aplomado_core::database::SessionData> for SessionResponse {
    fn from(s: aplomado_core::database::SessionData) -> Self {
        let hosts: Vec<HostInfo> = serde_json::from_str(&s.hosts_json).unwrap_or_default();
        Self {
            id: s.id,
            name: s.name,
            targets: s.targets,
            status: s.status,
            created_at: s.created_at,
            updated_at: s.updated_at,
            hosts,
            duration_secs: s.duration_secs,
        }
    }
}

/// Загрузить сессию.
#[post("/api/session/get")]
pub async fn get_session(id: String) -> Result<Option<SessionResponse>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        init_server();
        match aplomado_core::database::load_session(&id) {
            Ok(Some(s)) => Ok(Some(s.into())),
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
pub async fn list_sessions() -> Result<Vec<SessionResponse>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        init_server();
        let sessions = aplomado_core::database::list_sessions()
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(sessions.into_iter().map(|s| s.into()).collect())
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
        aplomado_core::database::delete_session(&id)
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
    match aplomado_core::history::load_last_scan() {
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
