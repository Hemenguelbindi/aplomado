use crate::history::ScanRecord;

/// Generate a CSV report for multiple scan records.
///
/// Each row represents a single port on a single host.
/// Hosts with no ports produce one row (with empty port fields).
pub fn export_csv(records: &[ScanRecord]) -> String {
    let mut csv = String::new();
    csv.push_str(
        "scan_id,timestamp,target,ip,hostname,os,alive,port,protocol,state,service,version,cve_id,cve_severity,cve_cvss\n",
    );

    for record in records {
        let timestamp = csv_escape(&record.timestamp);
        for target in &record.targets {
            let target_escaped = csv_escape(target);
            for host in &record.hosts {
                let alive = if host.alive { "true" } else { "false" };
                let hostname = csv_escape(host.hostname.as_deref().unwrap_or(""));
                let os = csv_escape(host.os_guess.as_deref().unwrap_or(""));

                if host.ports.is_empty() {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{},{},,,,,,,,\n",
                        record.id,
                        timestamp,
                        target_escaped,
                        host.ip,
                        hostname,
                        os,
                        alive,
                    ));
                } else {
                    for port in &host.ports {
                        let version = csv_escape(port.version.as_deref().unwrap_or(""));
                        csv.push_str(&format!(
                            "{},{},{},{},{},{},{},{},{},{},{},{},,,\n",
                            record.id,
                            timestamp,
                            target_escaped,
                            host.ip,
                            hostname,
                            os,
                            alive,
                            port.port,
                            "tcp",
                            "open",
                            csv_escape(&port.service),
                            version,
                        ));
                    }
                }
            }
        }
    }

    csv
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}
