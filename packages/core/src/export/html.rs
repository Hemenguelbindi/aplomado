use crate::history::ScanRecord;

/// Generate an HTML report for a single scan record.
pub fn export_html(record: &ScanRecord) -> String {
    let mut html = format!(
        r#"<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><title>PEREGRINE Scan Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
h1 {{ color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #30363d; }}
th {{ color: #8b949e; }}
.alive {{ color: #3fb950; }}
.dead {{ color: #f85149; }}
</style></head><body>
<h1>PEREGRINE Scan Report</h1>
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

/// Generate an HTML report for multiple scan records (collapsible).
pub fn export_html_multi(records: &[ScanRecord]) -> String {
    if records.is_empty() {
        return r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>PEREGRINE Scan Reports</title>
<style>
body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
h1 { color: #58a6ff; }
</style></head><body>
<h1>PEREGRINE Scan Reports</h1>
<p>No records found.</p>
</body></html>"#
            .to_string();
    }

    let mut html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>PEREGRINE Scan Reports</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
h1 {{ color: #58a6ff; }}
details {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 12px; }}
summary {{ cursor: pointer; font-weight: bold; color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #30363d; }}
th {{ color: #8b949e; }}
.alive {{ color: #3fb950; }}
.dead {{ color: #f85149; }}
</style></head><body>
<h1>PEREGRINE Scan Reports ({} records)</h1>
"#,
        records.len()
    );

    for (i, record) in records.iter().enumerate() {
        html.push_str(&format!(
            r#"<details{}><summary>Scan #{}: {} — {} targets, {} hosts, {} alive, {}s</summary>
<p><strong>ID:</strong> {} | <strong>Date:</strong> {}</p>
<table>
<thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Status</th><th>Ports</th></tr></thead>
<tbody>"#,
            if i == 0 { " open" } else { "" },
            i + 1,
            record.label,
            record.targets.len(),
            record.hosts_total,
            record.hosts_alive,
            record.duration_secs,
            record.id,
            record.timestamp,
        ));

        for host in &record.hosts {
            let status_class = if host.alive { "alive" } else { "dead" };
            let ports = host
                .ports
                .iter()
                .map(|p| format!("{}:{}", p.port, p.service))
                .collect::<Vec<_>>()
                .join(", ");

            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>",
                host.ip,
                host.hostname.as_deref().unwrap_or("—"),
                host.os_guess.as_deref().unwrap_or("—"),
                status_class,
                if host.alive { "Alive" } else { "Down" },
                ports,
            ));
        }

        html.push_str("</tbody></table></details>\n");
    }

    html.push_str("</body></html>");
    html
}
