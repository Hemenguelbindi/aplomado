use crate::helpers::{format_datetime, pluralize};
use crate::models::HostInfo;
use peregrine_core::history::ScanRecord;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq)]
pub struct CriticalVulnItem {
    pub host_ip: String,
    pub port: u16,
    pub cve_id: String,
    pub severity: String,
    pub cvss_score: f32,
}

#[derive(Clone, PartialEq)]
pub struct DashboardStats {
    pub alive_hosts: usize,
    pub total_hosts: usize,
    pub open_ports: usize,
    pub vuln_count: usize,
    pub critical_vulns: Vec<CriticalVulnItem>,
    pub recent_scans: Vec<ScanRecord>,
    pub last_scan_time: Option<String>,
    pub alive_pct: u32,
    pub alive_summary: Option<String>,
    pub ports_summary: Option<String>,
    pub top_services: Vec<(String, usize)>,
}

// ---------------------------------------------------------------------------
// Pure calculation
// ---------------------------------------------------------------------------

pub fn calculate_stats(hosts: &[HostInfo], history: &[ScanRecord]) -> DashboardStats {
    let alive_hosts = hosts.iter().filter(|h| h.alive).count();
    let total_hosts = hosts.len();
    let open_ports: usize = hosts.iter().map(|h| h.ports.len()).sum();
    let vuln_count: usize = hosts
        .iter()
        .flat_map(|h| h.ports.iter())
        .filter(|p| !p.cves.is_empty())
        .count();

    let critical_vulns: Vec<CriticalVulnItem> = hosts
        .iter()
        .flat_map(|h| {
            h.ports.iter().flat_map(move |p| {
                p.cves.iter().filter_map(move |c| {
                    let sev = c.severity.to_lowercase();
                    if sev == "critical" || sev == "high" {
                        Some(CriticalVulnItem {
                            host_ip: h.ip.to_string(),
                            port: p.port,
                            cve_id: c.id.clone(),
                            severity: c.severity.clone(),
                            cvss_score: c.cvss_score,
                        })
                    } else {
                        None
                    }
                })
            })
        })
        .collect();

    let recent_scans: Vec<ScanRecord> = history.iter().take(5).cloned().collect();
    let last_scan_time = history.first().map(|r| format_datetime(&r.timestamp));
    let alive_pct = if total_hosts > 0 {
        (alive_hosts as u32) * 100 / (total_hosts as u32)
    } else {
        0
    };

    let alive_summary = history.first().map(|r| {
        let a = pluralize(r.hosts_alive as usize, "хост", "хоста", "хостов");
        format!("{a} из {}", r.hosts_total)
    });
    let ports_summary = history.first().map(|r| {
        let p = pluralize(r.ports_total as usize, "порт", "порта", "портов");
        format!("{p} · {}с", r.duration_secs)
    });

    // Top services
    let mut service_counts = std::collections::HashMap::new();
    for host in hosts {
        for port in &host.ports {
            *service_counts.entry(port.service_name.clone()).or_insert(0) += 1;
        }
    }
    let mut top_services: Vec<(String, usize)> = service_counts.into_iter().collect();
    top_services.sort_by(|a, b| b.1.cmp(&a.1));
    top_services.truncate(5);

    DashboardStats {
        alive_hosts,
        total_hosts,
        open_ports,
        vuln_count,
        critical_vulns,
        recent_scans,
        last_scan_time,
        alive_pct,
        alive_summary,
        ports_summary,
        top_services,
    }
}
