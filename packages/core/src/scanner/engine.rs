//! Core scan engine — single-host scanner.
//!
//! Coordinates the full scan pipeline on one host:
//! ping → port scan → banner grab → OS fingerprint → CVE matching → traceroute.
//!
//! Concurrency is capped at 100 parallel ports via a semaphore.
//! Progress is reported through an optional watch channel.
//!
//! This module requires the `fingerprint` feature (which implies `scanner`).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::scanner::model::{HostInfo, PortInfo};
use crate::scanner::progress::{ScanPhase, ScanProgress};

/// Per-host timeout: if a host doesn't respond within this duration, mark as dead.
const HOST_TIMEOUT: Duration = Duration::from_secs(30);

/// Scan a single host: ping, port scan (concurrent with semaphore), banner grabbing,
/// OS fingerprint via banner, CVE matching, and traceroute.
/// Host is marked dead if ping doesn't respond within `HOST_TIMEOUT`.
pub async fn scan_single_target(
    ip: IpAddr,
    ports: &[u16],
    progress_tx: Option<tokio::sync::watch::Sender<Option<ScanProgress>>>,
) -> HostInfo {
    let mut host = HostInfo {
        ip,
        hostname: None,
        ttl: None,
        os_guess: None,
        ports: Vec::new(),
        alive: false,
        route: Vec::new(),
    };

    // ── Ping ──────────────────────────────────────────────────────────────
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

    host.alive = tokio::time::timeout(HOST_TIMEOUT, crate::scanner::ping::is_alive(ip))
        .await
        .unwrap_or(false);

    if !host.alive {
        return host;
    }

    // ── Port scan + banner grabbing (concurrent, limited) ────────────────
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
                let state = crate::scanner::port::scan_port(ip, p).await;
                if state == crate::scanner::model::PortState::Open {
                    let svc = crate::scanner::port::known_service(p);
                    let banner =
                        crate::fingerprint::banner::grab_banner(&ip.to_string(), p).await;
                    let version = banner.as_ref().and_then(|b| {
                        crate::scanner::model::extract_version(svc, b)
                    });
                    Some(PortInfo {
                        port: p,
                        protocol: crate::scanner::model::TransportProto::Tcp,
                        state: crate::scanner::model::PortState::Open,
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

    // ── OS fingerprint via banner ────────────────────────────────────────
    let ports_for_os: Vec<(u16, String, Option<String>)> = host
        .ports
        .iter()
        .map(|p| (p.port, p.service_name.clone(), p.banner.clone()))
        .collect();
    host.os_guess = crate::fingerprint::os::guess_os(&ports_for_os);

    // ── CVE matching ─────────────────────────────────────────────────────
    if let Some(db) = crate::cve::matcher::get_cve_db() {
        for port_info in &mut host.ports {
            if let Some(ref banner) = port_info.banner {
                let matched =
                    crate::cve::matcher::match_cves(&db, &port_info.service_name, banner);
                port_info.cves = matched
                    .into_iter()
                    .map(|c| crate::scanner::model::CveSummary {
                        id: c.id.clone(),
                        severity: c.severity.as_str().to_string(),
                        cvss_score: c.cvss_score,
                        fixed_version: c.fixed_version.clone(),
                        advisory_url: c.advisory_url.clone(),
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

    // ── Traceroute ───────────────────────────────────────────────────────
    if host.alive {
        host.route = crate::traceroute::trace(ip).await;
    }

    host
}
