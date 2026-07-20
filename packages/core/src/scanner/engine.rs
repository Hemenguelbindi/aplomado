use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::scanner::model::{HostInfo, PortInfo};
use crate::scanner::ping::HostReachability;
use crate::scanner::progress::{ScanPhase, ScanProgress};

const HOST_PING_TIMEOUT: Duration = Duration::from_secs(30);
const HOST_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn scan_single_target(
    ip: IpAddr,
    ports: &[u16],
    progress_tx: Option<tokio::sync::watch::Sender<Option<ScanProgress>>>,
) -> HostInfo {
    tokio::time::timeout(
        HOST_TOTAL_TIMEOUT,
        scan_single_target_inner(ip, ports, progress_tx),
    )
    .await
    .unwrap_or_else(|_| HostInfo {
        ip,
        hostname: None,
        ttl: None,
        os_guess: None,
        ports: Vec::new(),
        alive: false,
        route: Vec::new(),
    })
}

async fn scan_single_target_inner(
    ip: IpAddr,
    ports: &[u16],
    progress_tx: Option<tokio::sync::watch::Sender<Option<ScanProgress>>>,
) -> HostInfo {
    // Stage 1: ping discovery (bounded)
    let ping_fut = tokio::time::timeout(HOST_PING_TIMEOUT, crate::scanner::ping::probe_host(ip));

    // Stage 2: port scan (concurrent, limited) — runs in parallel with ping
    let port_fut = async {
        if ports.is_empty() {
            return Vec::new();
        }
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
                        let version = banner
                            .as_ref()
                            .and_then(|b| crate::scanner::model::extract_version(svc, b));
                        let cpe = crate::cve::client::get_cpe_for_service(svc)
                            .first()
                            .map(|s| s.to_string());
                        Some(PortInfo {
                            port: p,
                            protocol: crate::scanner::model::TransportProto::Tcp,
                            state: crate::scanner::model::PortState::Open,
                            service_name: svc.to_string(),
                            service_version: version,
                            banner,
                            cpe,
                            cves: vec![],
                        })
                    } else {
                        None
                    }
                }
            })
            .collect();
        futures::future::join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    };

    // Run ping and port scan concurrently
    let (ping_result, mut ports_result) = tokio::join!(ping_fut, port_fut);

    // Host alive = ping says alive OR any port is open
    let alive = match ping_result.unwrap_or(HostReachability::NoResponse) {
        HostReachability::Alive | HostReachability::PortClosed => true,
        HostReachability::NoResponse => !ports_result.is_empty(),
    };

    // Stage 3: OS fingerprint via banner
    if alive {
        let ports_for_os: Vec<(u16, String, Option<String>)> = ports_result
            .iter()
            .map(|p| (p.port, p.service_name.clone(), p.banner.clone()))
            .collect();
        let os_guess = crate::fingerprint::os::guess_os(&ports_for_os);

        // Stage 4: CVE matching
        if let Some(db) = crate::cve::matcher::get_cve_db() {
            for port_info in &mut ports_result {
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
                            confidence: "medium".into(),
                            method: "banner".into(),
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
                found_ports: ports_result.len() as u32,
                elapsed_secs: 0,
                phase: ScanPhase::BannerGrab,
            }));
        }

        // Stage 5: Traceroute
        let route = crate::traceroute::trace(ip).await;

        return HostInfo {
            ip,
            hostname: None,
            ttl: None,
            os_guess,
            ports: ports_result,
            alive,
            route,
        };
    }

    HostInfo {
        ip,
        hostname: None,
        ttl: None,
        os_guess: None,
        ports: ports_result,
        alive: false,
        route: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_scan_localhost() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let host = scan_single_target(ip, &[port], None).await;
        assert_eq!(host.ip, ip);
        assert!(host.alive);
        assert!(!host.ports.is_empty());
        assert_eq!(host.ports[0].port, port);
        drop(listener);
    }

    #[tokio::test]
    async fn test_scan_timeout_returns_dead() {
        // Use an unreachable IP to force timeout
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let host = scan_single_target(ip, &[80], None).await;
        assert_eq!(host.ip, ip);
        assert!(!host.alive);
    }
}
