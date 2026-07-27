use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Semaphore;

use crate::scanner::config::ScanConfig;
use crate::scanner::model::{PortInfo, PortState, TransportProto};
use crate::scanner::ping::HostReachability;
use crate::scanner::progress::ProgressSender;

use super::ScanStrategy;

#[derive(Debug)]
pub struct TcpConnectStrategy;

impl TcpConnectStrategy {
    pub fn new(_config: &ScanConfig) -> Self {
        Self
    }
}

#[async_trait]
impl ScanStrategy for TcpConnectStrategy {
    fn name(&self) -> &'static str {
        "tcp_connect"
    }

    async fn probe_host(&self, ip: IpAddr, _config: &ScanConfig) -> HostReachability {
        crate::scanner::ping::probe_host(ip).await
    }

    async fn scan_ports(
        &self,
        ip: IpAddr,
        ports: &[u16],
        config: &ScanConfig,
        progress: Option<ProgressSender>,
    ) -> Vec<PortInfo> {
        if ports.is_empty() {
            return Vec::new();
        }

        if let Some(ref tx) = progress {
            let _ = tx.send(Some(crate::scanner::progress::ScanProgress {
                total_hosts: 0,
                scanned_hosts: 0,
                current_host: ip.to_string(),
                found_ports: 0,
                elapsed_secs: 0,
                phase: crate::scanner::progress::ScanPhase::PortScan,
            }));
        }

        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_ports));
        let futs: Vec<_> = ports
            .iter()
            .map(|&p| {
                let sem = Arc::clone(&semaphore);
                async move {
                    let _permit = sem.acquire().await.ok()?;
                    let state = crate::scanner::port::scan_port(ip, p).await;
                    if state == PortState::Open {
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
                            protocol: TransportProto::Tcp,
                            state: PortState::Open,
                            service_name: svc.to_string(),
                            service_version: version,
                            version_info: None,
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
    }

    async fn grab_banners(
        &self,
        ip: IpAddr,
        ports: &[PortInfo],
        _config: &ScanConfig,
    ) -> Vec<PortInfo> {
        let futs: Vec<_> = ports
            .iter()
            .map(|p| {
                if p.banner.is_some() {
                    return futures::future::Either::Left(futures::future::ready(p.clone()));
                }
                let ip_str = ip.to_string();
                let port = p.port;
                let svc = p.service_name.clone();
                let p_clone = p.clone();
                futures::future::Either::Right(async move {
                    let banner =
                        crate::fingerprint::banner::grab_banner(&ip_str, port).await;
                    let mut updated = p_clone;
                    if let Some(b) = banner {
                        let sv = crate::scanner::model::extract_version(&svc, &b);
                        updated.banner = Some(b);
                        updated.service_version = sv;
                    }
                    updated
                })
            })
            .collect();
        futures::future::join_all(futs).await
    }
}
