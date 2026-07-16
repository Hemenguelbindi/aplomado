//! Shared scan engine for desktop/mobile platforms.
//! Provides deduplicated scanning logic: target resolution, host scanning,
//! banner version extraction.
//!
//! This module is only available on non-WASM targets (desktop, mobile).
//! The web platform uses the server-side API path instead.

#![cfg(not(target_arch = "wasm32"))]

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::models::{HostInfo, PortInfo, ScanTarget};

/// Per-host timeout: if a host doesn't respond within this duration, mark as dead.
const HOST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Resolve a ScanTarget to a list of IP addresses.
pub fn resolve_targets(target: &ScanTarget) -> Vec<IpAddr> {
    match target {
        ScanTarget::Ip(ip) => vec![*ip],
        ScanTarget::Hostname(h) => (h.as_str(), 0)
            .to_socket_addrs()
            .ok()
            .into_iter()
            .flat_map(|addrs| addrs.map(|s| s.ip()))
            .collect(),
        ScanTarget::Cidr(c) => kestrel_core::scanner::expand_cidr(c),
        ScanTarget::Range(start, end) => {
            kestrel_core::scanner::expand_range(&start.to_string(), &end.to_string())
        }
    }
}

/// Scan a single host: ping, port scan (concurrent with semaphore), banner grabbing,
/// OS fingerprint via TTL, and CVE matching.
/// Host is marked dead if ping doesn't respond within HOST_TIMEOUT.
pub async fn scan_single_target(
    ip: IpAddr,
    ports: &[u16],
    progress_tx: Option<tokio::sync::watch::Sender<Option<kestrel_core::scanner::progress::ScanProgress>>>,
) -> HostInfo {
    use kestrel_core::scanner::progress::{ScanPhase, ScanProgress};

    let mut host = HostInfo {
        ip,
        hostname: None,
        ttl: None,
        os_guess: None,
        ports: Vec::new(),
        alive: false,
        route: Vec::new(),
    };

    // Ping — parallel probe across all ports with per-host timeout
    if let Some(ref tx) = progress_tx {
        let _ = tx.send(Some(ScanProgress {
            total_hosts: 0,
            scanned_hosts: 0,
            current_host: ip.to_string(),
            found_ports: 0,
            elapsed_secs: 0,
            phase: ScanPhase::Ping,
        }));
    }

    host.alive = tokio::time::timeout(
        HOST_TIMEOUT,
        kestrel_core::scanner::ping::is_alive(ip),
    )
    .await
    .unwrap_or(false);

    if !host.alive {
        return host;
    }

    // Port scan + banner grabbing with concurrency limit
    if let Some(ref tx) = progress_tx {
        let _ = tx.send(Some(ScanProgress {
            total_hosts: 0,
            scanned_hosts: 0,
            current_host: ip.to_string(),
            found_ports: 0,
            elapsed_secs: 0,
            phase: ScanPhase::PortScan,
        }));
    }

    let semaphore = Arc::new(Semaphore::new(100));
    let futs: Vec<_> = ports
        .iter()
        .map(|&p| {
            let sem = Arc::clone(&semaphore);
            async move {
                let _permit = sem.acquire().await.ok()?;
                let state = kestrel_core::scanner::port::scan_port(ip, p).await;
                if state == kestrel_core::scanner::model::PortState::Open {
                    let svc = kestrel_core::scanner::port::known_service(p);
                    let banner =
                        kestrel_core::fingerprint::banner::grab_banner(&ip.to_string(), p).await;
                    let version = banner.as_ref().and_then(|b| {
                        kestrel_core::scanner::model::extract_version(svc, b)
                    });
                    Some(PortInfo {
                        port: p,
                        service_name: svc.to_string(),
                        service_version: version,
                        banner,
                        cpe: None,
                        cves: vec![],
                    })
                } else {
                    None
                }
            }
        })
        .collect();

    host.ports = futures::future::join_all(futs)
        .await
        .into_iter()
        .flatten()
        .collect();

    // OS Fingerprint — banner-based detection
    let ports_for_os: Vec<(u16, String, Option<String>)> = host.ports
        .iter()
        .map(|p| (p.port, p.service_name.clone(), p.banner.clone()))
        .collect();
    host.os_guess = kestrel_core::fingerprint::os::guess_os(&ports_for_os);

    // CVE matching
    if let Some(db) = kestrel_core::cve::matcher::get_cve_db() {
        for port_info in &mut host.ports {
            if let Some(ref banner) = port_info.banner {
                let matched = kestrel_core::cve::matcher::match_cves(
                    &db,
                    &port_info.service_name,
                    banner,
                );
                port_info.cves = matched
                    .into_iter()
                    .map(|c| crate::models::CveSummary {
                        id: c.id.clone(),
                        severity: c.severity.as_str().to_string(),
                        cvss_score: c.cvss_score,
                    })
                    .collect();
            }
        }
    }

    if let Some(ref tx) = progress_tx {
        let _ = tx.send(Some(ScanProgress {
            total_hosts: 0,
            scanned_hosts: 0,
            current_host: ip.to_string(),
            found_ports: host.ports.len() as u32,
            elapsed_secs: 0,
            phase: ScanPhase::BannerGrab,
        }));
    }

    // Traceroute — реальный маршрут до хоста
    if host.alive {
        let hops = kestrel_core::traceroute::trace(ip).await;
        host.route = hops.into_iter().map(|h| crate::models::Hop {
            hop: h.hop,
            ip: h.ip,
            rtt_ms: h.rtt_ms,
        }).collect();
    }

    host
}
