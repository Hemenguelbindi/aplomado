//! SQLite база данных для хранения результатов сканирования.
//! Создаётся автоматически при первом запуске.
//!
//! # Architecture
//!
//! - [`DatabaseHandle`] wraps a `Mutex<Connection>` and provides all CRUD
//!   operations.  Tests create their own handles for isolated test DBs.
//! - [`init_db`] stores one production handle in a global `OnceLock`.
//! - Convenience functions (`save_session`, `load_session`, …) delegate to
//!   the global handle.

use crate::history::ScanRecord;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Сессия сканирования (хранится как JSON в БД)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub id: String,
    pub name: String,
    pub targets: Vec<SessionTargetData>,
    pub status: String, // "Idle" | "Scanning" | "Done"
    pub created_at: String,
    pub updated_at: String,
    /// Хосты напрямую (не JSON-строка) — предотвращает двойную сериализацию.
    /// `#[serde(default)]` для обратной совместимости со старыми записями,
    /// где поле называлось `hosts_json` и было строкой.
    #[serde(default)]
    pub hosts: Vec<aplomado_types::HostInfo>,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTargetData {
    pub id: String,
    pub target: String,
    pub preset: String, // "Quick" | "Standard" | ...
    pub custom_ports: Vec<u16>,
    pub status: String, // "Queued" | "Scanning" | "Done" | "Error"
    pub hosts_count: u32,
    /// Non-empty when `status == "Error"`.
    #[serde(default)]
    pub error_message: Option<String>,
}

// ---------------------------------------------------------------------------
// DatabaseHandle
// ---------------------------------------------------------------------------

/// A handle to a single SQLite database connection (protected by a Mutex).
///
/// All repository operations are methods on this handle.  Production code
/// uses the global singleton; tests create isolated handles.
pub struct DatabaseHandle {
    conn: Mutex<rusqlite::Connection>,
}

impl DatabaseHandle {
    /// Open (or create) a SQLite database at `path`, apply schema and WAL
    /// PRAGMAs, and return a handle.
    /// Open (or create) a SQLite database at `path`, apply schema and WAL
    /// PRAGMAs, and return a handle.
    ///
    /// ## SQLite PRAGMAs
    ///
    /// | PRAGMA            | Value   | Purpose                                                    |
    /// |-------------------|---------|------------------------------------------------------------|
    /// | `journal_mode`    | `WAL`   | Write-ahead logging — concurrent readers don't block.      |
    /// | `synchronous`     | `NORMAL`| Durability without the fsync storm of FULL.                |
    /// | `busy_timeout`    | `5000`  | Wait 5 s instead of failing immediately on locked DB.      |
    /// | `foreign_keys`    | `ON`    | Enforce FK constraints (schema currently has none, but ready). |
    ///
    /// PRAGMAs are applied before the schema to ensure WAL mode is
    /// active when tables and indices are created.
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn with_conn<F, T>(&self, f: F) -> Result<T, Box<dyn std::error::Error>>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<T, Box<dyn std::error::Error>>,
    {
        let guard = self.conn.lock().map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Database lock poisoned: {e}"))
        })?;
        f(&guard)
    }

    // ── Scans ──────────────────────────────────────────────────────────

    pub fn save_scan(&self, record: &ScanRecord) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(record)?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO scans (id, data) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                rusqlite::params![record.id, json],
            )?;
            Ok(())
        })
    }

    pub fn load_last_scan(&self) -> Result<Option<ScanRecord>, Box<dyn std::error::Error>> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT data FROM scans ORDER BY created_at DESC LIMIT 1")?;
            let result = stmt.query_row([], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            });
            match result {
                Ok(json) => {
                    let record: ScanRecord = serde_json::from_str(&json)?;
                    Ok(Some(record))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(Box::new(e)),
            }
        })
    }

    pub fn load_history(&self) -> Result<Vec<ScanRecord>, Box<dyn std::error::Error>> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT data FROM scans ORDER BY created_at DESC LIMIT 1000")?;
            let records = stmt.query_map([], |row| {
                let json: String = row.get(0)?;
                let record: ScanRecord = serde_json::from_str(&json)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                Ok(record)
            })?;
            // Propagate deserialization errors instead of silently skipping
            records.collect::<Result<Vec<_>, _>>().map_err(|e| {
                Box::<dyn std::error::Error>::from(format!(
                    "Failed to deserialize scan record: {e}"
                ))
            })
        })
    }

    pub fn delete_scan(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM scans WHERE id = ?1", rusqlite::params![id])?;
            Ok(())
        })
    }

    // ── Sessions ───────────────────────────────────────────────────────

    pub fn save_session(&self, session: &SessionData) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(session)?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO sessions (id, data, updated_at) VALUES (?1, ?2, datetime('now')) ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = datetime('now')",
                rusqlite::params![session.id, json],
            )?;
            Ok(())
        })
    }

    pub fn load_session(
        &self,
        id: &str,
    ) -> Result<Option<SessionData>, Box<dyn std::error::Error>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT data FROM sessions WHERE id = ?1")?;
            let result = stmt.query_row(rusqlite::params![id], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            });
            match result {
                Ok(json) => {
                    let session: SessionData = serde_json::from_str(&json)?;
                    Ok(Some(session))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(Box::new(e)),
            }
        })
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionData>, Box<dyn std::error::Error>> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT data FROM sessions ORDER BY updated_at DESC LIMIT 100")?;
            let rows = stmt.query_map([], |row| {
                let json: String = row.get(0)?;
                let session: SessionData = serde_json::from_str(&json)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                Ok(session)
            })?;
            // Propagate deserialization errors instead of silently skipping
            rows.collect::<Result<Vec<_>, _>>().map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("Failed to deserialize session: {e}"))
            })
        })
    }

    pub fn delete_session(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM sessions WHERE id = ?1", rusqlite::params![id])?;
            Ok(())
        })
    }

    // ── Migration ──────────────────────────────────────────────────────

    /// Migrate from legacy JSON files into this database.
    /// No-op if the database already has scan records.
    pub fn migrate_from_json(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.with_conn(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
                .unwrap_or(0);
            if count > 0 {
                return Ok(());
            }

            let json_dir = dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".aplomado")
                .join("scans");
            if !json_dir.exists() {
                return Ok(());
            }

            if let Ok(entries) = std::fs::read_dir(&json_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "json").unwrap_or(false) {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if let Ok(record) = serde_json::from_str::<ScanRecord>(&content) {
                                let json = serde_json::to_string(&record)?;
                                conn.execute(
                                    "INSERT OR IGNORE INTO scans (id, data) VALUES (?1, ?2)",
                                    rusqlite::params![record.id, json],
                                )?;
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// SQL schema
// ---------------------------------------------------------------------------

const SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS scans (
    id         TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at DESC);";

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

static DB: OnceLock<DatabaseHandle> = OnceLock::new();

fn db_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aplomado")
        .join("aplomado.db")
}

/// Lock that serialises the first `init_db()` call so that two racing
/// threads do not both call `DatabaseHandle::open` on the same file.
static INIT_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

fn init_lock() -> &'static std::sync::Mutex<()> {
    INIT_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// Core initialisation logic — shared between `init_db()` and tests.
///
/// Uses double-checked locking:
/// 1. Fast path — check `DB` once (lock-free).
/// 2. Acquire `INIT_LOCK` mutex.
/// 3. Re-check `DB` after acquiring lock (another thread may have won).
/// 4. Create and set the handle.
fn init_db_inner(
    db: &OnceLock<DatabaseHandle>,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // Fast path
    if db.get().is_some() {
        return Ok(());
    }
    // Serialise first access
    let _guard = init_lock()
        .lock()
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("Init lock poisoned: {e}")))?;
    // Re-check after lock
    if db.get().is_some() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let handle = DatabaseHandle::open(path)?;
    match db.set(handle) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Another thread won — our handle is dropped, which is fine.
            Ok(())
        }
    }
}

/// Инициализировать production singleton БД: создать файл и таблицы.
///
/// Идемпотентна и потокобезопасна — только первый вызов создаёт
/// соединение; последующие возвращают `Ok(())`.
pub fn init_db() -> Result<(), Box<dyn std::error::Error>> {
    let path = db_path();
    init_db_inner(&DB, &path)
}

// ---------------------------------------------------------------------------
// Convenience functions (delegate to global singleton)
// ---------------------------------------------------------------------------

fn with_db<F, T>(f: F) -> Result<T, Box<dyn std::error::Error>>
where
    F: FnOnce(&DatabaseHandle) -> Result<T, Box<dyn std::error::Error>>,
{
    let handle = DB.get().ok_or_else(|| {
        Box::<dyn std::error::Error>::from("Database not initialized. Call init_db() first.")
    })?;
    f(handle)
}

pub fn save_scan(record: &ScanRecord) -> Result<(), Box<dyn std::error::Error>> {
    with_db(|h| h.save_scan(record))
}

pub fn load_last_scan() -> Result<Option<ScanRecord>, Box<dyn std::error::Error>> {
    with_db(|h| h.load_last_scan())
}

pub fn load_history() -> Result<Vec<ScanRecord>, Box<dyn std::error::Error>> {
    with_db(|h| h.load_history())
}

pub fn delete_scan(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    with_db(|h| h.delete_scan(id))
}

pub fn migrate_from_json() -> Result<(), Box<dyn std::error::Error>> {
    with_db(|h| h.migrate_from_json())
}

pub fn save_session(session: &SessionData) -> Result<(), Box<dyn std::error::Error>> {
    with_db(|h| h.save_session(session))
}

pub fn load_session(id: &str) -> Result<Option<SessionData>, Box<dyn std::error::Error>> {
    with_db(|h| h.load_session(id))
}

pub fn list_sessions() -> Result<Vec<SessionData>, Box<dyn std::error::Error>> {
    with_db(|h| h.list_sessions())
}

pub fn delete_session(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    with_db(|h| h.delete_session(id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::StoredHostInfo;

    fn tmp_db_file() -> (PathBuf, PathBuf) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aplomado_db_test_{ts}"));
        std::fs::create_dir_all(&dir).unwrap();
        (dir.clone(), dir.join("test.db"))
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    // ── 1. DatabaseHandle::open idempotence ────────────────────────────

    #[test]
    fn database_handle_open_is_idempotent() {
        let (dir, path) = tmp_db_file();
        let _handle = DatabaseHandle::open(&path).unwrap();
        // The handle is already open; verify subsequent DB open is still ok
        assert!(DatabaseHandle::open(&path).is_ok());
        cleanup(&dir);
    }

    #[test]
    fn save_and_load_after_repeated_open() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();
        // Open additional handles (simulating repeated init)
        let _h2 = DatabaseHandle::open(&path).unwrap();
        let _h3 = DatabaseHandle::open(&path).unwrap();

        let session = SessionData {
            id: "save_after_repeat-test-1".into(),
            name: "test".into(),
            targets: vec![],
            status: "Idle".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-01T00:00:00Z".into(),
            hosts: vec![],
            duration_secs: 0,
        };
        h.save_session(&session).unwrap();

        let loaded = h.load_session("save_after_repeat-test-1").unwrap();
        assert!(loaded.is_some(), "session should be loadable");
        assert_eq!(loaded.unwrap().id, "save_after_repeat-test-1");
        cleanup(&dir);
    }

    // ── 2. SessionData roundtrip ───────────────────────────────────────

    #[test]
    fn session_data_roundtrip() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let session = SessionData {
            id: "session_data_roundtrip-1".into(),
            name: "roundtrip test".into(),
            targets: vec![
                SessionTargetData {
                    id: "t1".into(),
                    target: "192.168.1.1".into(),
                    preset: "Quick".into(),
                    custom_ports: vec![],
                    status: "Done".into(),
                    hosts_count: 5,
                    error_message: None,
                },
                SessionTargetData {
                    id: "t2".into(),
                    target: "10.0.0.1".into(),
                    preset: "Standard".into(),
                    custom_ports: vec![8080, 9090],
                    status: "Error".into(),
                    hosts_count: 0,
                    error_message: Some("connection refused".into()),
                },
            ],
            status: "Done".into(),
            created_at: "2024-06-01T00:00:00Z".into(),
            updated_at: "2024-06-01T01:00:00Z".into(),
            hosts: vec![aplomado_types::HostInfo {
                ip: "192.168.1.1".parse().unwrap(),
                hostname: Some("router.local".into()),
                ttl: Some(64),
                os_guess: Some("Linux".into()),
                ports: vec![],
                alive: true,
                route: vec![],
            }],
            duration_secs: 120,
        };

        h.save_session(&session).unwrap();
        let loaded = h.load_session("session_data_roundtrip-1").unwrap().unwrap();
        assert_eq!(loaded.id, session.id);
        assert_eq!(loaded.name, session.name);
        assert_eq!(loaded.status, session.status);
        assert_eq!(loaded.targets.len(), session.targets.len());
        assert_eq!(loaded.targets[0].status, "Done");
        assert_eq!(loaded.targets[0].hosts_count, 5);
        assert_eq!(loaded.targets[0].error_message, None);
        assert_eq!(loaded.targets[1].status, "Error");
        assert_eq!(
            loaded.targets[1].error_message.as_deref(),
            Some("connection refused")
        );
        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.hosts[0].hostname.as_deref(), Some("router.local"));
        assert_eq!(loaded.duration_secs, 120);
        cleanup(&dir);
    }

    // ── 3. create → save → list/get ────────────────────────────────────

    #[test]
    fn create_save_list_get() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let s1 = SessionData {
            id: "create_save_list_get-s1".into(),
            name: "first".into(),
            targets: vec![],
            status: "Idle".into(),
            created_at: "t1".into(),
            updated_at: "t1".into(),
            hosts: vec![],
            duration_secs: 0,
        };
        let s2 = SessionData {
            id: "create_save_list_get-s2".into(),
            name: "second".into(),
            targets: vec![],
            status: "Scanning".into(),
            created_at: "t2".into(),
            updated_at: "t2".into(),
            hosts: vec![],
            duration_secs: 5,
        };

        h.save_session(&s1).unwrap();
        h.save_session(&s2).unwrap();

        let all = h.list_sessions().unwrap();
        assert_eq!(all.len(), 2, "isolated DB should have exactly 2 sessions");

        let loaded = h.load_session("create_save_list_get-s1").unwrap().unwrap();
        assert_eq!(loaded.name, "first");

        // Update
        let mut updated = s1.clone();
        updated.status = "Done".into();
        updated.duration_secs = 10;
        h.save_session(&updated).unwrap();

        let reloaded = h.load_session("create_save_list_get-s1").unwrap().unwrap();
        assert_eq!(reloaded.status, "Done");
        assert_eq!(reloaded.duration_secs, 10);
        cleanup(&dir);
    }

    // ── 4. TargetStatus roundtrip via DB model ─────────────────────────

    #[test]
    fn target_status_done_roundtrip() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let session = SessionData {
            id: "target_status_done_rt".into(),
            name: "done".into(),
            targets: vec![SessionTargetData {
                id: "t1".into(),
                target: "10.0.0.1".into(),
                preset: "Quick".into(),
                custom_ports: vec![],
                status: "Done".into(),
                hosts_count: 51,
                error_message: None,
            }],
            status: "Done".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
            hosts: vec![],
            duration_secs: 0,
        };

        h.save_session(&session).unwrap();
        let loaded = h.load_session("target_status_done_rt").unwrap().unwrap();
        assert_eq!(loaded.targets[0].status, "Done");
        assert_eq!(loaded.targets[0].hosts_count, 51);
        cleanup(&dir);
    }

    #[test]
    fn target_status_error_roundtrip() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let session = SessionData {
            id: "target_status_err_rt".into(),
            name: "err".into(),
            targets: vec![SessionTargetData {
                id: "t1".into(),
                target: "bad-host".into(),
                preset: "Quick".into(),
                custom_ports: vec![],
                status: "Error".into(),
                hosts_count: 0,
                error_message: Some("test error message".into()),
            }],
            status: "Scanning".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
            hosts: vec![],
            duration_secs: 0,
        };

        h.save_session(&session).unwrap();
        let loaded = h.load_session("target_status_err_rt").unwrap().unwrap();
        assert_eq!(loaded.targets[0].status, "Error");
        assert_eq!(loaded.targets[0].hosts_count, 0);
        assert_eq!(
            loaded.targets[0].error_message.as_deref(),
            Some("test error message")
        );
        cleanup(&dir);
    }

    // ── 5. SessionData DB persistence roundtrip tests ─────────────────

    /// Verify Done(51) survives save+load.
    #[test]
    fn session_done_with_count_roundtrip() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let session = SessionData {
            id: "db-done-1".into(),
            name: "done".into(),
            targets: vec![SessionTargetData {
                id: "t1".into(),
                target: "10.0.0.1".into(),
                preset: "Quick".into(),
                custom_ports: vec![],
                status: "Done".into(),
                hosts_count: 51,
                error_message: None,
            }],
            status: "Idle".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
            hosts: vec![],
            duration_secs: 0,
        };

        h.save_session(&session).unwrap();
        let loaded = h.load_session("db-done-1").unwrap().unwrap();
        assert_eq!(loaded.targets[0].status, "Done");
        assert_eq!(loaded.targets[0].hosts_count, 51);
        cleanup(&dir);
    }

    #[test]
    fn session_error_with_message_roundtrip() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let session = SessionData {
            id: "db-err-1".into(),
            name: "err".into(),
            targets: vec![SessionTargetData {
                id: "t1".into(),
                target: "bad-host".into(),
                preset: "Quick".into(),
                custom_ports: vec![],
                status: "Error".into(),
                hosts_count: 0,
                error_message: Some("connection timeout".into()),
            }],
            status: "Scanning".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
            hosts: vec![],
            duration_secs: 0,
        };

        h.save_session(&session).unwrap();
        let loaded = h.load_session("db-err-1").unwrap().unwrap();
        assert_eq!(loaded.targets[0].status, "Error");
        assert_eq!(
            loaded.targets[0].error_message.as_deref(),
            Some("connection timeout")
        );
        cleanup(&dir);
    }

    #[test]
    fn session_status_roundtrip_variants() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        for (label, status) in [("Idle", "Idle"), ("Scanning", "Scanning"), ("Done", "Done")] {
            let session = SessionData {
                id: format!("db-status-{label}"),
                name: label.into(),
                targets: vec![],
                status: status.into(),
                created_at: "now".into(),
                updated_at: "now".into(),
                hosts: vec![],
                duration_secs: 0,
            };

            h.save_session(&session).unwrap();
            let loaded = h
                .load_session(&format!("db-status-{label}"))
                .unwrap()
                .unwrap();
            assert_eq!(
                loaded.status, status,
                "SessionStatus {label} should roundtrip"
            );
        }
        cleanup(&dir);
    }

    #[test]
    fn session_hostinfo_roundtrip() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let host = aplomado_types::HostInfo {
            ip: "192.168.1.100".parse().unwrap(),
            hostname: Some("nas.local".into()),
            ttl: Some(128),
            os_guess: Some("FreeBSD".into()),
            ports: vec![aplomado_types::PortInfo {
                port: 80,
                protocol: aplomado_types::TransportProto::Tcp,
                state: aplomado_types::PortState::Open,
                service_name: "http".into(),
                service_version: Some("nginx/1.25".into()),
                version_info: None,
                banner: Some("nginx".into()),
                cpe: Some("cpe:2.3:a:nginx:nginx:1.25".into()),
                cves: vec![],
            }],
            alive: true,
            route: vec![],
        };

        let session = SessionData {
            id: "db-hostinfo".into(),
            name: "hostinfo test".into(),
            targets: vec![],
            status: "Done".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
            hosts: vec![host.clone()],
            duration_secs: 42,
        };

        h.save_session(&session).unwrap();
        let loaded = h.load_session("db-hostinfo").unwrap().unwrap();
        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.hosts[0].ip, host.ip);
        assert_eq!(loaded.hosts[0].hostname.as_deref(), Some("nas.local"));
        assert_eq!(loaded.hosts[0].os_guess.as_deref(), Some("FreeBSD"));
        assert_eq!(loaded.hosts[0].ports.len(), 1);
        assert_eq!(loaded.hosts[0].ports[0].port, 80);
        assert_eq!(loaded.hosts[0].ports[0].service_name, "http");
        assert_eq!(loaded.duration_secs, 42);
        cleanup(&dir);
    }

    // ── 9. Parallel init_db race via production code path ──────────────

    /// Prove that init_db_inner is race-free: 8 threads simultaneously
    /// enter, all get Ok, and the database works afterwards.
    #[test]
    fn parallel_init_db_race() {
        let (dir, path) = tmp_db_file();

        let db: std::sync::Arc<std::sync::OnceLock<DatabaseHandle>> =
            std::sync::Arc::new(std::sync::OnceLock::new());
        let num_threads = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(num_threads));
        let mut thread_handles = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let b = std::sync::Arc::clone(&barrier);
            let p = path.clone();
            let db_clone = std::sync::Arc::clone(&db);
            thread_handles.push(std::thread::spawn(move || {
                b.wait();
                init_db_inner(&db_clone, &p).map_err(|e| e.to_string())
            }));
        }

        for h in thread_handles {
            let result = h.join().unwrap();
            assert!(
                result.is_ok(),
                "parallel init_db_inner must succeed: {:?}",
                result
            );
        }

        // Verify DB works after concurrent init
        let handle = db.get().expect("DB must be initialized");
        let session = SessionData {
            id: "parallel-init-race".into(),
            name: "barrier test".into(),
            targets: vec![],
            status: "Idle".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
            hosts: vec![],
            duration_secs: 0,
        };
        handle.save_session(&session).unwrap();
        let loaded = handle.load_session("parallel-init-race").unwrap().unwrap();
        assert_eq!(loaded.name, "barrier test");
        cleanup(&dir);
    }

    // ── 10. Backward compatibility — old JSON without error_message ─────

    #[test]
    fn backward_compat_no_error_message() {
        // Simulate a session saved by an older version that didn't have
        // the `error_message` field on SessionTargetData.
        let old_json = r#"{
            "id": "backward-compat-1",
            "name": "old format",
            "targets": [{
                "id": "t1",
                "target": "10.0.0.1",
                "preset": "Quick",
                "custom_ports": [],
                "status": "Error",
                "hosts_count": 0
            }],
            "status": "Scanning",
            "created_at": "2024-06-01T00:00:00Z",
            "updated_at": "2024-06-01T01:00:00Z",
            "hosts": [],
            "duration_secs": 0
        }"#;

        let session: SessionData = serde_json::from_str(old_json)
            .expect("old JSON without error_message must deserialize");
        assert_eq!(session.targets.len(), 1);
        assert_eq!(session.targets[0].status, "Error");
        // error_message must be None when absent in JSON
        assert_eq!(
            session.targets[0].error_message, None,
            "missing error_message must deserialize as None"
        );
    }

    #[test]
    fn backward_compat_no_hosts_field() {
        // Verify that the #[serde(default)] on SessionData.hosts works
        let old_json = r#"{
            "id": "backward-compat-no-hosts",
            "name": "no hosts",
            "targets": [],
            "status": "Done",
            "created_at": "now",
            "updated_at": "now",
            "duration_secs": 0
        }"#;

        let session: SessionData =
            serde_json::from_str(old_json).expect("old JSON without hosts field must deserialize");
        assert!(session.hosts.is_empty());
    }

    // ── 11. Full Error round-trip ───────────────────────────────────────

    /// Construct the full round-trip:
    ///   SessionTargetData { status: "Error", error_message: Some("msg") }
    ///   → serde_json serialize → deserialize
    ///   → assert error_message survives
    #[test]
    fn error_roundtrip_via_json() {
        let target = SessionTargetData {
            id: "err-t1".into(),
            target: "bad-host".into(),
            preset: "Quick".into(),
            custom_ports: vec![],
            status: "Error".into(),
            hosts_count: 0,
            error_message: Some("connection refused: timeout".into()),
        };

        let json = serde_json::to_string(&target).unwrap();
        let deserialized: SessionTargetData = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, "Error");
        assert_eq!(
            deserialized.error_message.as_deref(),
            Some("connection refused: timeout")
        );
    }

    /// Full round-trip through DB: Error target → save → load → check
    #[test]
    fn error_roundtrip_via_db() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let session = SessionData {
            id: "err-db-rt".into(),
            name: "err rt".into(),
            targets: vec![SessionTargetData {
                id: "t-err".into(),
                target: "10.0.0.99".into(),
                preset: "Quick".into(),
                custom_ports: vec![],
                status: "Error".into(),
                hosts_count: 0,
                error_message: Some("DNS resolution failed".into()),
            }],
            status: "Scanning".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
            hosts: vec![],
            duration_secs: 0,
        };

        h.save_session(&session).unwrap();
        let loaded = h.load_session("err-db-rt").unwrap().unwrap();
        assert_eq!(loaded.targets[0].status, "Error");
        assert_eq!(
            loaded.targets[0].error_message.as_deref(),
            Some("DNS resolution failed")
        );
        cleanup(&dir);
    }

    // ── 12. list_sessions rejects corrupt data ───────────────────────────

    #[test]
    fn list_sessions_rejects_corrupt_data() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        // Insert a valid session
        let session = SessionData {
            id: "valid".into(),
            name: "valid".into(),
            targets: vec![],
            status: "Idle".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
            hosts: vec![],
            duration_secs: 0,
        };
        h.save_session(&session).unwrap();

        // Manually insert corrupt data
        h.with_conn(|conn| {
            conn.execute(
                "INSERT INTO sessions (id, data, updated_at) VALUES ('corrupt', 'not-json', datetime('now'))",
                [],
            )?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .unwrap();

        // list_sessions must return an error, not silently skip
        let result = h.list_sessions();
        assert!(
            result.is_err(),
            "list_sessions should reject corrupt data: {result:?}"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Failed to deserialize session"),
            "error should mention deserialization failure: {err}"
        );
        cleanup(&dir);
    }

    // ── 6. Load non-existent session returns None ─────────────────────

    #[test]
    fn load_nonexistent_session_returns_none() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let loaded = h.load_session("non-existent-id").unwrap();
        assert!(loaded.is_none(), "non-existent session should return None");

        cleanup(&dir);
    }

    // ── 7. Parallel DatabaseHandle::open (equivalent to parallel init) ──

    #[test]
    fn parallel_db_handle_init() {
        let (dir, path) = tmp_db_file();

        let path = std::sync::Arc::new(path);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(10));
        let mut thread_handles = Vec::new();

        for _ in 0..10 {
            let b = std::sync::Arc::clone(&barrier);
            let p = std::sync::Arc::clone(&path);
            thread_handles.push(std::thread::spawn(move || {
                b.wait();
                DatabaseHandle::open(&p).map_err(|e| e.to_string())
            }));
        }

        for h in thread_handles {
            let result = h.join().unwrap();
            assert!(result.is_ok(), "parallel DatabaseHandle::open must succeed");
        }

        // Verify the handle still works
        let h = DatabaseHandle::open(&path).unwrap();
        let session = SessionData {
            id: "parallel-test".into(),
            name: "parallel".into(),
            targets: vec![],
            status: "Idle".into(),
            created_at: "now".into(),
            updated_at: "now".into(),
            hosts: vec![],
            duration_secs: 0,
        };
        h.save_session(&session).unwrap();
        let loaded = h.load_session("parallel-test").unwrap();
        assert!(loaded.is_some());
        cleanup(&dir);
    }

    // ── 8. Session-after-scan verification ──────────────────────────────

    /// Prove that calling a mapper with scan results produces a session
    /// containing all required fields: hosts, SessionStatus::Done,
    /// updated TargetStatus, duration_secs, and a recent updated_at.
    #[test]
    fn session_after_scan_contains_all_fields() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let hosts = vec![
            aplomado_types::HostInfo {
                ip: "10.0.0.1".parse().unwrap(),
                hostname: None,
                ttl: None,
                os_guess: None,
                ports: vec![],
                alive: true,
                route: vec![],
            },
            aplomado_types::HostInfo {
                ip: "10.0.0.2".parse().unwrap(),
                hostname: None,
                ttl: None,
                os_guess: None,
                ports: vec![],
                alive: false,
                route: vec![],
            },
        ];

        let targets = vec![SessionTargetData {
            id: "t-scan-1".into(),
            target: "10.0.0.0/24".into(),
            preset: "Quick".into(),
            custom_ports: vec![],
            status: "Done".into(),
            hosts_count: 1,
            error_message: None,
        }];

        let now = "2024-07-01T12:00:00Z";
        let session = SessionData {
            id: "session-after-scan".into(),
            name: "scan test".into(),
            targets,
            status: "Done".into(),
            created_at: now.into(),
            updated_at: now.into(),
            hosts: hosts.clone(),
            duration_secs: 30,
        };
        h.save_session(&session).unwrap();

        let loaded = h.load_session("session-after-scan").unwrap().unwrap();

        // All fields present
        assert_eq!(loaded.status, "Done", "session status must be Done");
        assert_eq!(loaded.hosts.len(), 2, "both hosts must be saved");
        assert_eq!(
            loaded.hosts[0].ip.to_string(),
            "10.0.0.1",
            "first host IP preserved"
        );
        assert_eq!(
            loaded.hosts[1].ip.to_string(),
            "10.0.0.2",
            "second host IP preserved"
        );
        assert_eq!(loaded.targets.len(), 1, "target preserved");
        assert_eq!(loaded.targets[0].status, "Done", "target status Done");
        assert_eq!(loaded.targets[0].hosts_count, 1, "hosts_count preserved");
        assert_eq!(loaded.duration_secs, 30, "duration preserved");
        assert!(!loaded.updated_at.is_empty(), "updated_at must be set");
        cleanup(&dir);
    }

    // ── Route roundtrip tests ──────────────────────────────────────────

    fn make_route_scan(id: &str, hosts: Vec<StoredHostInfo>) -> ScanRecord {
        let alive = hosts.iter().filter(|h| h.alive).count() as u32;
        let ports: u32 = hosts.iter().map(|h| h.ports.len() as u32).sum();
        ScanRecord {
            id: id.to_string(),
            label: format!("scan-{id}"),
            targets: vec![],
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            duration_secs: 0,
            hosts_total: hosts.len() as u32,
            hosts_alive: alive,
            hosts_found: hosts.len() as u32,
            ports_total: ports,
            hosts,
        }
    }

    // ── 13. ScanRecord route SQLite roundtrip ────────────────────────────

    #[test]
    fn scan_record_route_sqlite_roundtrip() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let record = make_route_scan(
            "route-sqlite-1",
            vec![StoredHostInfo {
                ip: "10.0.0.1".into(),
                hostname: None,
                os_guess: None,
                alive: true,
                ports: vec![],
                route: vec![
                    aplomado_types::Hop {
                        hop: 1,
                        ip: "10.0.0.1".parse().unwrap(),
                        rtt_ms: Some(1.0),
                    },
                    aplomado_types::Hop {
                        hop: 2,
                        ip: "10.0.0.2".parse().unwrap(),
                        rtt_ms: Some(2.5),
                    },
                    aplomado_types::Hop {
                        hop: 3,
                        ip: "10.0.0.3".parse().unwrap(),
                        rtt_ms: None,
                    },
                ],
            }],
        );

        h.save_scan(&record).expect("save_scan must succeed");
        let loaded = h
            .load_last_scan()
            .expect("load_last_scan must succeed")
            .expect("loaded scan must be Some");

        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.hosts[0].route.len(), 3);
        assert_eq!(loaded.hosts[0].route[0].hop, 1);
        assert_eq!(loaded.hosts[0].route[1].hop, 2);
        assert_eq!(loaded.hosts[0].route[2].hop, 3);
        assert_eq!(loaded.hosts[0].route[0].ip.to_string(), "10.0.0.1");
        assert_eq!(loaded.hosts[0].route[1].ip.to_string(), "10.0.0.2");
        assert_eq!(loaded.hosts[0].route[2].ip.to_string(), "10.0.0.3");
        assert_eq!(loaded.hosts[0].route[0].rtt_ms, Some(1.0));
        assert_eq!(loaded.hosts[0].route[1].rtt_ms, Some(2.5));
        assert_eq!(loaded.hosts[0].route[2].rtt_ms, None);

        cleanup(&dir);
    }

    // ── 14. load_history preserves routes ────────────────────────────────

    #[test]
    fn load_history_preserves_routes() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let record1 = make_route_scan(
            "hist-route-1",
            vec![StoredHostInfo {
                ip: "10.0.0.1".into(),
                hostname: None,
                os_guess: None,
                alive: true,
                ports: vec![],
                route: vec![aplomado_types::Hop {
                    hop: 1,
                    ip: "10.0.0.1".parse().unwrap(),
                    rtt_ms: Some(1.0),
                }],
            }],
        );
        let record2 = make_route_scan(
            "hist-route-2",
            vec![StoredHostInfo {
                ip: "10.0.0.2".into(),
                hostname: None,
                os_guess: None,
                alive: true,
                ports: vec![],
                route: vec![
                    aplomado_types::Hop {
                        hop: 1,
                        ip: "10.0.0.1".parse().unwrap(),
                        rtt_ms: Some(5.0),
                    },
                    aplomado_types::Hop {
                        hop: 2,
                        ip: "10.0.0.2".parse().unwrap(),
                        rtt_ms: Some(10.0),
                    },
                ],
            }],
        );

        h.save_scan(&record1).expect("save record1");
        h.save_scan(&record2).expect("save record2");

        let history = h.load_history().expect("load_history must succeed");

        assert_eq!(history.len(), 2);

        let r1 = history
            .iter()
            .find(|r| r.id == "hist-route-1")
            .expect("record 1");
        let r2 = history
            .iter()
            .find(|r| r.id == "hist-route-2")
            .expect("record 2");

        assert_eq!(r1.hosts[0].route.len(), 1);
        assert_eq!(r1.hosts[0].route[0].rtt_ms, Some(1.0));

        assert_eq!(r2.hosts[0].route.len(), 2);
        assert_eq!(r2.hosts[0].route[1].ip.to_string(), "10.0.0.2");
        assert_eq!(r2.hosts[0].route[1].rtt_ms, Some(10.0));

        cleanup(&dir);
    }

    // ── 15. Corrupted route data returns error ───────────────────────────

    #[test]
    fn corrupted_route_data_returns_error() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        // route contains a hop with a non-string IP
        // (this simulates binary garbage or wrong type for the route field)
        let corrupt_json = r#"{
            "id": "corrupt-route",
            "label": "corrupt",
            "targets": [],
            "timestamp": "2025-01-01T00:00:00Z",
            "duration_secs": 0,
            "hosts_total": 1,
            "hosts_alive": 1,
            "hosts_found": 1,
            "ports_total": 0,
            "hosts": [{
                "ip": "10.0.0.1",
                "hostname": null,
                "os_guess": null,
                "alive": true,
                "ports": [],
                "route": [
                    {
                        "hop": 1,
                        "ip": 12345,
                        "rtt_ms": null
                    }
                ]
            }]
        }"#;

        // Insert corrupt JSON directly into the scans table
        h.with_conn(|conn| {
            conn.execute(
                "INSERT INTO scans (id, data) VALUES ('corrupt-route', ?1)",
                rusqlite::params![corrupt_json],
            )?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .unwrap();

        // load_last_scan must propagate deserialization error
        let result = h.load_last_scan();
        assert!(
            result.is_err(),
            "corrupt route data must produce an error, got: {result:?}"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid type") || err.contains("invalid"),
            "error must mention type mismatch: {err}"
        );

        // load_history must also reject it
        let hist_result = h.load_history();
        assert!(
            hist_result.is_err(),
            "load_history must reject corrupt route data"
        );

        cleanup(&dir);
    }

    // ── UPSERT behaviour tests ──────────────────────────────────────────

    /// Repeated save_session updates data, does not increase row count,
    /// and the record stays accessible by the same ID.
    #[test]
    fn upsert_session_updates_data_in_place() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let s1 = SessionData {
            id: "upsert-sess-1".into(),
            name: "version 1".into(),
            targets: vec![],
            status: "Idle".into(),
            created_at: "t1".into(),
            updated_at: "t1".into(),
            hosts: vec![],
            duration_secs: 0,
        };
        let s2 = SessionData {
            id: "upsert-sess-1".into(), // same ID
            name: "version 2".into(),
            targets: vec![],
            status: "Done".into(),
            created_at: "t1".into(),
            updated_at: "t2".into(),
            hosts: vec![],
            duration_secs: 10,
        };

        h.save_session(&s1).unwrap();
        h.save_session(&s2).unwrap();

        // Only 1 row
        let all = h.list_sessions().unwrap();
        assert_eq!(all.len(), 1, "UPSERT must not create extra rows");

        // Data is updated
        let loaded = h.load_session("upsert-sess-1").unwrap().unwrap();
        assert_eq!(loaded.name, "version 2");
        assert_eq!(loaded.status, "Done");
        assert_eq!(loaded.duration_secs, 10);

        cleanup(&dir);
    }

    /// Repeated save_scan updates data, does not increase row count.
    #[test]
    fn upsert_scan_updates_data_in_place() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        use crate::history::StoredHostInfo;
        let r1 = ScanRecord {
            id: "upsert-scan-1".into(),
            label: "v1".into(),
            targets: vec![],
            timestamp: "t1".into(),
            duration_secs: 0,
            hosts_total: 0,
            hosts_alive: 0,
            hosts_found: 0,
            ports_total: 0,
            hosts: vec![],
        };
        let r2 = ScanRecord {
            id: "upsert-scan-1".into(), // same ID
            label: "v2".into(),
            targets: vec!["10.0.0.1".into()],
            timestamp: "t2".into(),
            duration_secs: 30,
            hosts_total: 1,
            hosts_alive: 1,
            hosts_found: 1,
            ports_total: 2,
            hosts: vec![StoredHostInfo {
                ip: "10.0.0.1".into(),
                hostname: None,
                os_guess: None,
                alive: true,
                ports: vec![],
                route: vec![],
            }],
        };

        h.save_scan(&r1).unwrap();
        h.save_scan(&r2).unwrap();

        // Only 1 row
        let history = h.load_history().unwrap();
        assert_eq!(history.len(), 1, "UPSERT must not create extra scan rows");

        // Data is updated
        let loaded = h.load_last_scan().unwrap().unwrap();
        assert_eq!(loaded.label, "v2");
        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.duration_secs, 30);

        cleanup(&dir);
    }

    /// Save two distinct sessions, verify both survive.
    #[test]
    fn upsert_preserves_distinct_ids() {
        let (dir, path) = tmp_db_file();
        let h = DatabaseHandle::open(&path).unwrap();

        let a = SessionData {
            id: "upsert-a".into(),
            name: "A".into(),
            targets: vec![],
            status: "Idle".into(),
            created_at: "t".into(),
            updated_at: "t".into(),
            hosts: vec![],
            duration_secs: 0,
        };
        let b = SessionData {
            id: "upsert-b".into(),
            name: "B".into(),
            targets: vec![],
            status: "Done".into(),
            created_at: "t".into(),
            updated_at: "t".into(),
            hosts: vec![],
            duration_secs: 0,
        };

        // Save A, save B, save A again (UPSERT A again)
        h.save_session(&a).unwrap();
        h.save_session(&b).unwrap();
        let mut a_updated = a.clone();
        a_updated.name = "A updated".into();
        h.save_session(&a_updated).unwrap();

        let all = h.list_sessions().unwrap();
        assert_eq!(all.len(), 2, "must have 2 distinct sessions");

        let loaded_a = h.load_session("upsert-a").unwrap().unwrap();
        assert_eq!(loaded_a.name, "A updated");

        let loaded_b = h.load_session("upsert-b").unwrap().unwrap();
        assert_eq!(loaded_b.name, "B");

        cleanup(&dir);
    }
}
