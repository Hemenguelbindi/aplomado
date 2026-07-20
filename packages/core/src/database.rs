//! SQLite база данных для хранения результатов сканирования.
//! Создаётся автоматически при первом запуске.
//! Использует пул соединений через OnceLock<Mutex<Connection>>.

use crate::history::ScanRecord;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Глобальный пул соединений SQLite (WAL mode).
static DB: OnceLock<Mutex<rusqlite::Connection>> = OnceLock::new();

/// Сессия сканирования (хранится как JSON в БД)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub id: String,
    pub name: String,
    pub targets: Vec<SessionTargetData>,
    pub status: String, // "Idle" | "Scanning" | "Done"
    pub created_at: String,
    pub updated_at: String,
    pub hosts_json: String, // сериализованные HostInfo
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
}

/// Получить путь к файлу БД.
fn db_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aplomado")
        .join("aplomado.db")
}

/// Выполнить замыкание с доступом к пулу соединений.
fn with_db<F, T>(f: F) -> Result<T, Box<dyn std::error::Error>>
where
    F: FnOnce(&rusqlite::Connection) -> Result<T, Box<dyn std::error::Error>>,
{
    let db = DB.get().ok_or_else(|| {
        Box::<dyn std::error::Error>::from("Database not initialized. Call init_db() first.")
    })?;
    let conn = db.lock().map_err(|e| {
        Box::<dyn std::error::Error>::from(format!("Database lock poisoned: {e}"))
    })?;
    f(&conn)
}

/// Инициализировать БД: создать файл и таблицы, если ещё нет.
pub fn init_db() -> Result<(), Box<dyn std::error::Error>> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = rusqlite::Connection::open(&path)?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scans (
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
        CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at DESC);"
    )?;

    // WAL mode for better concurrent access
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

    DB.set(Mutex::new(conn))
        .map_err(|_| "Database already initialized".into())
}

/// Сохранить скан в БД.
pub fn save_scan(record: &ScanRecord) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(record)?;
    with_db(|conn| {
        conn.execute(
            "INSERT OR REPLACE INTO scans (id, data) VALUES (?1, ?2)",
            rusqlite::params![record.id, json],
        )?;
        Ok(())
    })
}

/// Загрузить последний скан из БД.
pub fn load_last_scan() -> Result<Option<ScanRecord>, Box<dyn std::error::Error>> {
    let path = db_path();
    if !path.exists() {
        return Ok(None);
    }
    // Ensure DB is initialized
    init_db().ok();

    with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT data FROM scans ORDER BY created_at DESC LIMIT 1"
        )?;

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

/// Загрузить всю историю сканов из БД.
pub fn load_history() -> Result<Vec<ScanRecord>, Box<dyn std::error::Error>> {
    let path = db_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    init_db().ok();

    with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT data FROM scans ORDER BY created_at DESC LIMIT 1000"
        )?;

        let records = stmt.query_map([], |row| {
            let json: String = row.get(0)?;
            let record: ScanRecord = serde_json::from_str(&json)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            Ok(record)
        })?;

        let mut result = Vec::new();
        for r in records.flatten() {
            result.push(r);
        }
        Ok(result)
    })
}

/// Удалить скан из БД.
pub fn delete_scan(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = db_path();
    if !path.exists() {
        return Ok(());
    }
    init_db().ok();

    with_db(|conn| {
        conn.execute("DELETE FROM scans WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    })
}

/// Мигрировать из JSON-файлов в SQLite (если есть JSON, а БД пустая).
/// Вызывается при первом запуске после init_db().
pub fn migrate_from_json() -> Result<(), Box<dyn std::error::Error>> {
    with_db(|conn| {
        // Проверить, есть ли уже записи в БД
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM scans", [], |row| row.get(0)
        ).unwrap_or(0);

        if count > 0 {
            return Ok(()); // уже есть данные, не мигрируем
        }

        // Загрузить из старых JSON файлов
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

/// Сохранить или обновить сессию в БД.
pub fn save_session(session: &SessionData) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(session)?;
    with_db(|conn| {
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, data, updated_at) VALUES (?1, ?2, datetime('now'))",
            rusqlite::params![session.id, json],
        )?;
        Ok(())
    })
}

/// Загрузить сессию по ID.
pub fn load_session(id: &str) -> Result<Option<SessionData>, Box<dyn std::error::Error>> {
    let path = db_path();
    if !path.exists() {
        return Ok(None);
    }
    init_db().ok();

    with_db(|conn| {
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

/// Загрузить все сессии (последние сверху).
pub fn list_sessions() -> Result<Vec<SessionData>, Box<dyn std::error::Error>> {
    let path = db_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    init_db().ok();

    with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT data FROM sessions ORDER BY updated_at DESC LIMIT 100"
        )?;
        let rows = stmt.query_map([], |row| {
            let json: String = row.get(0)?;
            let session: SessionData = serde_json::from_str(&json)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            Ok(session)
        })?;
        let mut result = Vec::new();
        for r in rows.flatten() {
            result.push(r);
        }
        Ok(result)
    })
}

/// Удалить сессию.
pub fn delete_session(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = db_path();
    if !path.exists() {
        return Ok(());
    }
    init_db().ok();

    with_db(|conn| {
        conn.execute("DELETE FROM sessions WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    })
}
