use crate::history::ScanRecord;

pub fn export_html(record: &ScanRecord) -> String {
    let mut html = format!(
        r#"<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><title>KESTREL Scan Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
h1 {{ color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }}
th {{ color: #8b949e; }}
.alive {{ color: #3fb950; }}
.dead {{ color: #f85149; }}
</style></head><body>
<h1>KESTREL Scan Report</h1>
<p>Date: {} | Targets: {} | Hosts: {} | Alive: {} | Duration: {}s</p>
<table>
<thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Status</th><th>Ports</th></tr></thead>
<tbody>"#,
        record.timestamp,
        record.targets.join(", "),
        record.hosts_total,
        record.hosts_alive,
        record.duration_secs,
    );

    for host in &record.hosts {
        let status = if host.alive {
            "class=\"alive\""
        } else {
            "class=\"dead\""
        };
        let ports = host
            .ports
            .iter()
            .map(|p| format!("{}:{}", p.port, p.service))
            .collect::<Vec<_>>()
            .join(", ");

        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td {}>{}</td><td>{}</td></tr>",
            host.ip,
            host.hostname.as_deref().unwrap_or("—"),
            host.os_guess.as_deref().unwrap_or("—"),
            status,
            if host.alive { "Alive" } else { "Down" },
            ports,
        ));
    }

    html.push_str("</tbody></table></body></html>");
    html
}

pub fn export_json(record: &ScanRecord) -> String {
    serde_json::to_string_pretty(record).unwrap_or_default()
}

pub fn export_txt(record: &ScanRecord) -> String {
    let mut txt = String::new();
    txt.push_str("KESTREL Scan Report\n");
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

/// Сохранить отчёт в файл.
pub fn save_report(
    record: &ScanRecord,
    format: &str,
    output_path: &std::path::Path,
) -> std::io::Result<()> {
    let content = match format {
        "html" => export_html(record),
        "json" => export_json(record),
        "txt" | "text" => export_txt(record),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported format. Use: html, json, txt",
            ))
        }
    };
    std::fs::write(output_path, &content)
}
