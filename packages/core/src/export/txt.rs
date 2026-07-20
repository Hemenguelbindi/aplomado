use crate::history::ScanRecord;

/// Generate a plain-text report for a single scan record.
pub fn export_txt(record: &ScanRecord) -> String {
    let mut txt = String::new();
    txt.push_str("APLOMADO Scan Report\n");
    txt.push_str(&format!("Date: {}\n", record.timestamp));
    txt.push_str(&format!("Targets: {}\n", record.targets.join(", ")));
    txt.push_str(&format!("Hosts found: {}\n", record.hosts_found));
    txt.push_str(&format!("Duration: {}s\n\n", record.duration_secs));

    for host in &record.hosts {
        txt.push_str(&format!(
            "  {} ({})",
            host.ip,
            host.os_guess.as_deref().unwrap_or("?")
        ));
        if !host.alive {
            txt.push_str(" — DOWN");
        }
        txt.push('\n');
        for port in &host.ports {
            txt.push_str(&format!(
                "    {}/tcp   {}  {}\n",
                port.port,
                port.service,
                port.version.as_deref().unwrap_or("")
            ));
        }
        txt.push('\n');
    }
    txt
}

/// Generate a plain-text report for multiple scan records (separated by `---`).
pub fn export_txt_multi(records: &[ScanRecord]) -> String {
    if records.is_empty() {
        return "APLOMADO Scan Reports\nNo records found.\n".to_string();
    }

    let mut parts = Vec::new();
    for record in records {
        parts.push(export_txt(record));
    }
    parts.join("\n\n---\n\n")
}
