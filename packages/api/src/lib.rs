//! Server Functions for Aplomado scanner.

use aplomado_types::*;
use dioxus::prelude::*;
#[cfg(feature = "server")]
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

/// Execute a blocking database operation on the blocking thread pool.
/// The closure may return `Box<dyn Error>` (non-Send); we convert to `String`
/// inside `spawn_blocking` so the tokio-required `Send` bound is satisfied.
#[cfg(feature = "server")]
async fn db_call<T, F>(f: F) -> Result<T, ServerFnError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Box<dyn std::error::Error>> + Send + 'static,
{
    let result = tokio::task::spawn_blocking(move || f().map_err(|e| e.to_string()))
        .await
        .map_err(|e| ServerFnError::new(format!("spawn_blocking join error: {e}")))?;
    result.map_err(ServerFnError::new)
}

/// Check API key authentication.
/// Reads `APLOMADO_API_KEY` env var. If set and non-empty, validates the
/// `Authorization: Bearer <key>` header. If not set, auth is skipped (dev mode).
#[cfg(feature = "server")]
async fn check_auth() -> Result<(), ServerFnError> {
    let expected = std::env::var("APLOMADO_API_KEY").unwrap_or_default();
    if expected.is_empty() {
        return Ok(());
    }

    let headers = dioxus_fullstack::FullstackContext::extract::<dioxus_fullstack::HeaderMap, _>()
        .await
        .map_err(|_| ServerFnError::new("Failed to extract request headers"))?;

    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if auth == format!("Bearer {expected}") || auth == expected {
        Ok(())
    } else {
        Err(ServerFnError::new(
            "Unauthorized: invalid or missing API key",
        ))
    }
}

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
/// - All target strings are resolvable (CIDR, IP, hostname) using async DNS
/// - All ports are in 1-65535
/// - Special/denied addresses (loopback, multicast, etc.) are excluded via `ScanPolicy`
/// - Duplicate IPs are removed
/// - Total IPs do not exceed policy limit
#[cfg(feature = "server")]
async fn validate_scan_request(req: &ScanRequest) -> Result<ValidatedScanRequest, ServerFnError> {
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
        match aplomado_core::scanner::resolve_target_str_async(target_str).await {
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
    check_auth().await?;
    init_server();

    // Validate and resolve the request (async DNS)
    let validated = validate_scan_request(&req).await?;

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
        check_auth().await?;
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
            hosts: vec![],
            duration_secs: 0,
        };
        db_call(move || aplomado_core::database::save_session(&session)).await?;
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
        check_auth().await?;
        init_server();
        let session: aplomado_core::database::SessionData =
            serde_json::from_str(&data).map_err(|e| ServerFnError::new(e.to_string()))?;
        db_call(move || aplomado_core::database::save_session(&session)).await?;
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = data;
        Err(ServerFnError::new("Server only"))
    }
}

/// Target summary as returned by the session API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTargetSummary {
    pub id: String,
    pub target: String,
    pub preset: String,
    pub custom_ports: Vec<u16>,
    pub status: String,
    pub hosts_count: u32,
}

/// Response type for session retrieval — `hosts` is stored directly (not double-serialised).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: String,
    pub name: String,
    pub targets: Vec<SessionTargetSummary>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub hosts: Vec<HostInfo>,
    pub duration_secs: u64,
}

#[cfg(feature = "server")]
impl From<aplomado_core::database::SessionData> for SessionResponse {
    fn from(s: aplomado_core::database::SessionData) -> Self {
        let targets = s
            .targets
            .into_iter()
            .map(|t| SessionTargetSummary {
                id: t.id,
                target: t.target,
                preset: t.preset,
                custom_ports: t.custom_ports,
                status: t.status,
                hosts_count: t.hosts_count,
            })
            .collect();
        Self {
            id: s.id,
            name: s.name,
            targets,
            status: s.status,
            created_at: s.created_at,
            updated_at: s.updated_at,
            hosts: s.hosts,
            duration_secs: s.duration_secs,
        }
    }
}

/// Загрузить сессию.
#[post("/api/session/get")]
pub async fn get_session(id: String) -> Result<Option<SessionResponse>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        check_auth().await?;
        init_server();
        let result = db_call(move || aplomado_core::database::load_session(&id)).await?;
        match result {
            Some(s) => Ok(Some(s.into())),
            None => Ok(None),
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
        check_auth().await?;
        init_server();
        let sessions = db_call(|| aplomado_core::database::list_sessions()).await?;
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
        check_auth().await?;
        db_call(move || aplomado_core::database::delete_session(&id)).await?;
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
    check_auth().await?;
    init_server();
    let record = db_call(|| Ok(aplomado_core::history::load_last_scan())).await?;
    match record {
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
