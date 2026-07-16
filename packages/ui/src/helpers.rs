use crate::models::{HostInfo, ScanTarget, Session, SessionStatus};
use kestrel_core::history::{ScanRecord, StoredHostInfo, StoredPortInfo};

pub fn create_default_session() -> Session {
    let now = chrono::Local::now().to_rfc3339();
    Session {
        id: format!("ses_{}", chrono::Local::now().timestamp_millis()),
        name: String::new(),
        targets: vec![],
        status: SessionStatus::Idle,
        created_at: now.clone(),
        updated_at: now,
        hosts: vec![],
        duration_secs: 0,
    }
}

pub fn build_scan_record(
    hosts: &[HostInfo],
    targets_str: &[String],
    duration_secs: u64,
) -> ScanRecord {
    let hosts_alive = hosts.iter().filter(|h| h.alive).count() as u32;
    let ports_total: u32 = hosts.iter().map(|h| h.ports.len() as u32).sum();

    ScanRecord {
        id: chrono::Utc::now().to_rfc3339(),
        label: targets_str.join(", "),
        targets: targets_str.to_vec(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        duration_secs,
        hosts_total: hosts.len() as u32,
        hosts_alive,
        hosts_found: hosts.len() as u32,
        ports_total,
        hosts: hosts.iter().map(|h| StoredHostInfo {
            ip: h.ip.to_string(),
            hostname: h.hostname.clone(),
            os_guess: h.os_guess.clone(),
            alive: h.alive,
            ports: h.ports.iter().map(|p| StoredPortInfo {
                port: p.port,
                service: p.service_name.clone(),
                version: p.service_version.clone(),
                banner: p.banner.clone(),
            }).collect(),
        }).collect(),
    }
}

pub fn targets_to_strings(targets: &[ScanTarget]) -> Vec<String> {
    targets.iter().map(|t| match t {
        ScanTarget::Ip(ip) => ip.to_string(),
        ScanTarget::Cidr(c) => c.clone(),
        ScanTarget::Hostname(h) => h.clone(),
        ScanTarget::Range(start, end) => format!("{}-{}", start, end),
    }).collect()
}
