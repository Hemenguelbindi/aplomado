use std::net::IpAddr;

use async_trait::async_trait;

use crate::scanner::config::ScanConfig;
use crate::scanner::model::PortInfo;
use crate::scanner::ping::HostReachability;
use crate::scanner::progress::ProgressSender;

use super::ScanStrategy;

#[derive(Debug)]
pub struct MockStrategy {
    pub probe_host_result: HostReachability,
    pub scan_ports_result: Vec<PortInfo>,
    pub grab_banners_result: Vec<PortInfo>,
}

impl Default for MockStrategy {
    fn default() -> Self {
        Self {
            probe_host_result: HostReachability::Alive,
            scan_ports_result: Vec::new(),
            grab_banners_result: Vec::new(),
        }
    }
}

impl MockStrategy {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ScanStrategy for MockStrategy {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn probe_host(&self, _ip: IpAddr, _config: &ScanConfig) -> HostReachability {
        self.probe_host_result
    }

    async fn scan_ports(
        &self,
        _ip: IpAddr,
        _ports: &[u16],
        _config: &ScanConfig,
        _progress: Option<ProgressSender>,
    ) -> Vec<PortInfo> {
        self.scan_ports_result.clone()
    }

    async fn grab_banners(
        &self,
        _ip: IpAddr,
        _ports: &[PortInfo],
        _config: &ScanConfig,
    ) -> Vec<PortInfo> {
        self.grab_banners_result.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::scanner::model::{PortState, TransportProto};

    #[tokio::test]
    async fn test_mock_probe_host() {
        let strategy = MockStrategy {
            probe_host_result: HostReachability::Alive,
            ..Default::default()
        };
        let config = ScanConfig::default();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = strategy.probe_host(ip, &config).await;
        assert_eq!(result, HostReachability::Alive);
    }

    #[tokio::test]
    async fn test_mock_probe_host_no_response() {
        let strategy = MockStrategy {
            probe_host_result: HostReachability::NoResponse,
            ..Default::default()
        };
        let config = ScanConfig::default();
        let result = strategy
            .probe_host(IpAddr::V4(Ipv4Addr::UNSPECIFIED), &config)
            .await;
        assert_eq!(result, HostReachability::NoResponse);
    }

    #[tokio::test]
    async fn test_mock_scan_ports() {
        let port_info = PortInfo {
            port: 80,
            protocol: TransportProto::Tcp,
            state: PortState::Open,
            service_name: "http".into(),
            service_version: None,
            version_info: None,
            banner: None,
            cpe: None,
            cves: vec![],
        };
        let strategy = MockStrategy {
            scan_ports_result: vec![port_info.clone()],
            ..Default::default()
        };
        let config = ScanConfig::default();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = strategy.scan_ports(ip, &[80], &config, None).await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].port, 80);
        assert_eq!(result[0].state, PortState::Open);
    }

    #[tokio::test]
    async fn test_mock_scan_ports_empty() {
        let strategy = MockStrategy::new();
        let config = ScanConfig::default();
        let result = strategy
            .scan_ports(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                &[],
                &config,
                None,
            )
            .await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_mock_grab_banners() {
        let port_info = PortInfo {
            port: 443,
            protocol: TransportProto::Tcp,
            state: PortState::Open,
            service_name: "https".into(),
            service_version: None,
            version_info: None,
            banner: Some("TLS 1.3".into()),
            cpe: None,
            cves: vec![],
        };
        let strategy = MockStrategy {
            grab_banners_result: vec![port_info.clone()],
            ..Default::default()
        };
        let config = ScanConfig::default();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = strategy
            .grab_banners(ip, &[port_info], &config)
            .await;
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].banner.as_deref(),
            Some("TLS 1.3")
        );
    }

    #[tokio::test]
    async fn test_mock_scan_ports_with_progress() {
        use crate::scanner::progress::progress_channel;

        let port_info = PortInfo {
            port: 22,
            protocol: TransportProto::Tcp,
            state: PortState::Open,
            service_name: "ssh".into(),
            service_version: None,
            version_info: None,
            banner: None,
            cpe: None,
            cves: vec![],
        };
        let strategy = MockStrategy {
            scan_ports_result: vec![port_info],
            ..Default::default()
        };
        let config = ScanConfig::default();
        let (tx, rx) = progress_channel();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = strategy
            .scan_ports(ip, &[22], &config, Some(tx))
            .await;
        assert_eq!(result.len(), 1);
        // Progress message may have been sent
        let _ = rx.has_changed();
    }

    #[tokio::test]
    async fn test_mock_name() {
        let strategy = MockStrategy::new();
        assert_eq!(strategy.name(), "mock");
    }

    #[tokio::test]
    async fn test_mock_default_constructor() {
        let strategy = MockStrategy::new();
        assert_eq!(strategy.probe_host_result, HostReachability::Alive);
        assert!(strategy.scan_ports_result.is_empty());
        assert!(strategy.grab_banners_result.is_empty());
    }
}
