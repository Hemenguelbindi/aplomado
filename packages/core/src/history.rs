use serde::{Deserialize, Serialize};

/// Полный результат скана для сохранения
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanRecord {
    pub id: String,
    pub label: String,
    pub targets: Vec<String>,
    pub timestamp: String,
    pub duration_secs: u64,
    pub hosts_total: u32,
    pub hosts_alive: u32,
    pub hosts_found: u32,
    pub ports_total: u32,
    pub hosts: Vec<StoredHostInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredHostInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub alive: bool,
    pub ports: Vec<StoredPortInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredPortInfo {
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}

/// Сохранить скан.
/// Пытается сохранить в SQLite (если feature включена), иначе в JSON файл.
pub fn save_scan(record: &ScanRecord) -> std::io::Result<()> {
    #[cfg(feature = "database")]
    {
        if let Err(e) = crate::database::save_scan(record) {
            eprintln!("DB save failed, falling back to JSON: {e}");
        } else {
            return Ok(());
        }
    }
    save_scan_json(record)
}

/// Загрузить историю.
/// Пытается из SQLite, иначе из JSON файлов.
pub fn load_history() -> Vec<ScanRecord> {
    #[cfg(feature = "database")]
    {
        match crate::database::load_history() {
            Ok(records) if !records.is_empty() => return records,
            _ => {} // fallback to JSON
        }
    }
    load_history_json()
}

/// Загрузить последний скан.
pub fn load_last_scan() -> Option<ScanRecord> {
    #[cfg(feature = "database")]
    {
        if let Ok(Some(record)) = crate::database::load_last_scan() {
            return Some(record);
        }
    }
    // fallback: взять первый из JSON истории
    let mut records = load_history_json();
    records.into_iter().next()
}

/// Удалить запись.
pub fn delete_scan(id: &str) -> std::io::Result<()> {
    #[cfg(feature = "database")]
    {
        crate::database::delete_scan(id).ok();
    }
    // также удалить из JSON
    let path = history_dir().join(format!("{id}.json"));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

// ---- JSON fallback (старый способ) ----

fn history_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".kestrel")
        .join("scans")
}

fn save_scan_json(record: &ScanRecord) -> std::io::Result<()> {
    let dir = history_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", record.id));
    let json = serde_json::to_string_pretty(record)?;
    std::fs::write(&path, &json)?;
    Ok(())
}

fn load_history_json() -> Vec<ScanRecord> {
    let dir = history_dir();
    if !dir.exists() {
        return vec![];
    }
    let mut records = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(record) = serde_json::from_str::<ScanRecord>(&content) {
                        records.push(record);
                    }
                }
            }
        }
    }
    records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    records.truncate(1000);
    records
}
