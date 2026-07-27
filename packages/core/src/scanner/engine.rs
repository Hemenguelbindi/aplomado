use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::FuturesUnordered;
use futures::StreamExt;

use crate::scanner::config::ScanConfig;
use crate::scanner::model::HostInfo;
use crate::scanner::ping::HostReachability;
use crate::scanner::progress::{ScanPhase, ScanProgress, ProgressSender};
use crate::scanner::strategy::ScanStrategy;
use crate::scanner::strategy::TcpConnectStrategy;

const HOST_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Scan a single target using the default TCP connect strategy.
pub async fn scan_single_target(
    ip: IpAddr,
    ports: &[u16],
    progress_tx: Option<tokio::sync::watch::Sender<Option<ScanProgress>>>,
) -> HostInfo {
    let config = ScanConfig::default();
    let strategy = TcpConnectStrategy::new(&config);
    scan_with_strategy(&strategy, ip, ports, &config, progress_tx).await
}

/// Scan a single target with a specific strategy and config.
pub async fn scan_with_strategy(
    strategy: &dyn ScanStrategy,
    ip: IpAddr,
    ports: &[u16],
    config: &ScanConfig,
    progress_tx: Option<tokio::sync::watch::Sender<Option<ScanProgress>>>,
) -> HostInfo {
    tokio::time::timeout(
        HOST_TOTAL_TIMEOUT,
        scan_with_strategy_inner(strategy, ip, ports, config, progress_tx),
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

async fn scan_with_strategy_inner(
    strategy: &dyn ScanStrategy,
    ip: IpAddr,
    ports: &[u16],
    config: &ScanConfig,
    progress_tx: Option<tokio::sync::watch::Sender<Option<ScanProgress>>>,
) -> HostInfo {
    let progress: Option<ProgressSender> = progress_tx.clone().map(Arc::new);

    let ping_fut = strategy.probe_host(ip, config);
    let port_fut = strategy.scan_ports(ip, ports, config, progress);

    let (ping_result, mut ports_result) = tokio::join!(ping_fut, port_fut);

    let alive = match ping_result {
        HostReachability::Alive | HostReachability::PortClosed => true,
        HostReachability::NoResponse => !ports_result.is_empty(),
    };

    if alive {
        let ports_for_os: Vec<(u16, String, Option<String>)> = ports_result
            .iter()
            .map(|p| (p.port, p.service_name.clone(), p.banner.clone()))
            .collect();
        let os_guess = crate::fingerprint::os::guess_os(&ports_for_os);

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

/// Scan multiple hosts concurrently, bounded by `config.max_concurrent_hosts`.
pub async fn scan_hosts(
    ips: &[IpAddr],
    ports: &[u16],
    config: &ScanConfig,
    progress_tx: Option<tokio::sync::watch::Sender<Option<ScanProgress>>>,
) -> Vec<HostInfo> {
    let total = ips.len() as u32;

    if let Some(ref tx) = progress_tx {
        let _ = tx.send(Some(ScanProgress {
            total_hosts: total,
            scanned_hosts: 0,
            current_host: String::new(),
            found_ports: 0,
            elapsed_secs: 0,
            phase: ScanPhase::Ping,
        }));
    }

    let strategy = TcpConnectStrategy::new(config);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_hosts));
    let scanned = Arc::new(AtomicU32::new(0));

    let futs: FuturesUnordered<_> = ips
        .iter()
        .map(|&ip| {
            let strat: &dyn ScanStrategy = &strategy;
            let sem = Arc::clone(&semaphore);
            let tx = progress_tx.clone();
            let scanned = Arc::clone(&scanned);
            let ports = ports.to_vec();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let host = scan_with_strategy(strat, ip, &ports, config, tx.clone()).await;
                let s = scanned.fetch_add(1, Ordering::SeqCst) + 1;
                if let Some(ref tx) = tx {
                    let _ = tx.send(Some(ScanProgress {
                        total_hosts: total,
                        scanned_hosts: s,
                        current_host: ip.to_string(),
                        found_ports: host.ports.len() as u32,
                        elapsed_secs: 0,
                        phase: ScanPhase::Done,
                    }));
                }
                host
            }
        })
        .collect();

    futs.collect().await
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

    #[tokio::test]
    async fn test_scan_hosts_concurrent() {
        let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port1 = listener1.local_addr().unwrap().port();
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port2 = listener2.local_addr().unwrap().port();

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ips = vec![ip, ip];
        let ports = vec![port1, port2];
        let config = ScanConfig {
            max_concurrent_hosts: 1,
            connect_timeout: Duration::from_secs(2),
            ..ScanConfig::default()
        };

        let results = scan_hosts(&ips, &ports, &config, None).await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.alive));
        drop(listener1);
        drop(listener2);
    }

    #[tokio::test]
    async fn test_scan_hosts_respects_semaphore() {
        let mut listeners = Vec::new();
        let mut ports = Vec::new();
        for _ in 0..5 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            ports.push(listener.local_addr().unwrap().port());
            listeners.push(listener);
        }

        let ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); 5];
        let config = ScanConfig {
            max_concurrent_hosts: 2,
            connect_timeout: Duration::from_secs(2),
            ..ScanConfig::default()
        };

        let results = scan_hosts(&ips, &ports, &config, None).await;
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.alive));
        drop(listeners);
    }
}
