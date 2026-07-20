use crate::history::ScanRecord;

/// Serialize a scan record to pretty-printed JSON.
pub fn export_json(record: &ScanRecord) -> String {
    serde_json::to_string_pretty(record).unwrap_or_default()
}
