use aplomado_core::export::*;
use aplomado_core::history::{ScanRecord, StoredHostInfo, StoredPortInfo};

fn make_record(id: &str) -> ScanRecord {
    ScanRecord {
        id: id.to_string(),
        label: format!("Scan {id}"),
        targets: vec!["192.168.1.0/24".to_string()],
        timestamp: "2025-01-01T00:00:00Z".to_string(),
        duration_secs: 42,
        hosts_total: 2,
        hosts_alive: 1,
        hosts_found: 2,
        ports_total: 3,
        hosts: vec![
            StoredHostInfo {
                ip: "192.168.1.1".to_string(),
                hostname: Some("router.local".to_string()),
                os_guess: Some("Linux".to_string()),
                alive: true,
                ports: vec![
                    StoredPortInfo {
                        port: 80,
                        service: "http".to_string(),
                        version: Some("nginx/1.20".to_string()),
                        banner: None,
                        cves: vec![],
                    },
                    StoredPortInfo {
                        port: 22,
                        service: "ssh".to_string(),
                        version: Some("OpenSSH_8.9".to_string()),
                        banner: None,
                        cves: vec![],
                    },
                ],
            },
            StoredHostInfo {
                ip: "192.168.1.2".to_string(),
                hostname: None,
                os_guess: None,
                alive: false,
                ports: vec![],
            },
        ],
    }
}

fn make_records() -> Vec<ScanRecord> {
    vec![
        make_record("rec-001"),
        make_record("rec-002"),
        make_record("rec-003"),
    ]
}

// ── JSON multi-record tests ──────────────────────────────────────────────

#[test]
fn export_json_multi_three_records() {
    let records = make_records();
    let json = serde_json::to_string_pretty(&records).unwrap();
    let parsed: Vec<ScanRecord> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.len(), 3);
}

#[test]
fn export_json_multi_empty() {
    let records: Vec<ScanRecord> = vec![];
    let json = serde_json::to_string_pretty(&records).unwrap();
    assert_eq!(json, "[]");
}

// ── HTML multi-record tests ──────────────────────────────────────────────

#[test]
fn export_html_multi_contains_summaries() {
    let records = make_records();
    let html = export_html_multi(&records);
    assert!(html.contains("Scan rec-001"));
    assert!(html.contains("Scan rec-002"));
    assert!(html.contains("Scan rec-003"));
    assert!(html.contains("192.168.1.1"));
    assert!(html.contains("192.168.1.2"));
    assert!(html.contains("<details"));
    assert!(html.contains("<summary"));
    assert!(html.contains("</details>"));
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.ends_with("</html>"));
}

#[test]
fn export_html_multi_empty() {
    let records: Vec<ScanRecord> = vec![];
    let html = export_html_multi(&records);
    assert!(html.contains("No records found"));
    assert!(html.starts_with("<!DOCTYPE html>"));
}

// ── TXT multi-record tests ───────────────────────────────────────────────

#[test]
fn export_txt_multi_has_separators() {
    let records = make_records();
    let txt = export_txt_multi(&records);
    assert!(txt.contains("\n\n---\n\n"));
    let count = txt.matches("\n\n---\n\n").count();
    assert_eq!(count, 2);
    assert!(txt.contains("APLOMADO Scan Report"));
    assert!(txt.contains("192.168.1.1"));
}

#[test]
fn export_txt_multi_empty() {
    let records: Vec<ScanRecord> = vec![];
    let txt = export_txt_multi(&records);
    assert!(txt.contains("No records found"));
}

// ── CSV tests ────────────────────────────────────────────────────────────

#[test]
fn export_csv_has_header() {
    let records = make_records();
    let csv = export_csv(&records);
    let first_line = csv.lines().next().unwrap();
    assert_eq!(
        first_line,
        "scan_id,timestamp,target,ip,hostname,os,alive,port,protocol,state,service,version,cve_id,cve_severity,cve_cvss"
    );
}

#[test]
fn export_csv_rows_per_port() {
    let records = make_records();
    let csv = export_csv(&records);
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 10);
}

#[test]
fn export_csv_valid_format() {
    let records = make_records();
    let csv = export_csv(&records);
    let lines: Vec<&str> = csv.lines().collect();
    assert!(lines.len() > 1);
    let header: Vec<&str> = lines[0].split(',').collect();
    assert_eq!(header.len(), 15);
    let first_row: Vec<&str> = lines[1].split(',').collect();
    assert_eq!(first_row.len(), 15);
    assert_eq!(first_row[0], "rec-001");
    assert_eq!(first_row[7], "80");
    assert_eq!(first_row[8], "tcp");
    assert_eq!(first_row[9], "open");
}

#[test]
fn export_csv_escapes_commas() {
    let mut record = make_record("esc-test");
    record.targets = vec!["192.168.1.0/24,extra".to_string()];
    let records = vec![record];
    let csv = export_csv(&records);
    assert!(csv.contains("\"192.168.1.0/24,extra\""));
}

// ── ZIP tests (feature-gated) ────────────────────────────────────────────

#[cfg(feature = "export")]
#[test]
fn export_zip_creates_valid_archive() {
    let records = make_records();
    let dir = std::env::temp_dir().join("aplomado_zip_test");
    let _ = std::fs::create_dir_all(&dir);
    let zip_path = dir.join("test_export.zip");
    let _ = std::fs::remove_file(&zip_path);

    save_reports(&records, ExportFormat::Zip, &zip_path).unwrap();
    assert!(zip_path.exists());
    assert!(zip_path.metadata().unwrap().len() > 100);

    let _ = std::fs::remove_file(&zip_path);
    let _ = std::fs::remove_dir(&dir);
}

// ── save_reports dispatch tests ──────────────────────────────────────────

fn test_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("aplomado_export_test").join(name);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn cleanup(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn save_reports_dispatches_json() {
    let records = make_records();
    let dir = test_dir("dispatch_json");
    let path = dir.join("test.json");

    save_reports(&records, ExportFormat::Json, &path).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: Vec<ScanRecord> = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed.len(), 3);

    cleanup(&dir);
}

#[test]
fn save_reports_dispatches_html() {
    let records = make_records();
    let dir = test_dir("dispatch_html");
    let path = dir.join("test.html");

    save_reports(&records, ExportFormat::Html, &path).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("Scan rec-001"));
    assert!(content.contains("<details"));

    cleanup(&dir);
}

#[test]
fn save_reports_dispatches_txt() {
    let records = make_records();
    let dir = test_dir("dispatch_txt");
    let path = dir.join("test.txt");

    save_reports(&records, ExportFormat::Txt, &path).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("APLOMADO Scan Report"));
    assert!(content.contains("\n\n---\n\n"));

    cleanup(&dir);
}

#[test]
fn save_reports_dispatches_csv() {
    let records = make_records();
    let dir = test_dir("dispatch_csv");
    let path = dir.join("test.csv");

    save_reports(&records, ExportFormat::Csv, &path).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    let first_line = content.lines().next().unwrap();
    assert!(first_line.starts_with("scan_id"));

    cleanup(&dir);
}

// ── Edge cases ───────────────────────────────────────────────────────────

#[test]
fn export_empty_records_json_valid() {
    let records: Vec<ScanRecord> = vec![];
    let json = serde_json::to_string_pretty(&records).unwrap();
    assert_eq!(json, "[]");
}

#[test]
fn export_empty_records_html_shows_message() {
    let records: Vec<ScanRecord> = vec![];
    let html = export_html_multi(&records);
    assert!(html.contains("No records found"));
}

#[test]
fn export_empty_records_txt_shows_message() {
    let records: Vec<ScanRecord> = vec![];
    let txt = export_txt_multi(&records);
    assert!(txt.contains("No records found"));
}
