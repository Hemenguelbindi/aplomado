use std::net::IpAddr;

use async_trait::async_trait;

use crate::scanner::config::ScanConfig;
use crate::scanner::model::PortInfo;
use crate::scanner::ping::HostReachability;
use crate::scanner::progress::ProgressSender;

#[async_trait]
pub trait ScanStrategy: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &'static str;
    async fn probe_host(&self, ip: IpAddr, config: &ScanConfig) -> HostReachability;
    async fn scan_ports(
        &self,
        ip: IpAddr,
        ports: &[u16],
        config: &ScanConfig,
        progress: Option<ProgressSender>,
    ) -> Vec<PortInfo>;
    async fn grab_banners(
        &self,
        ip: IpAddr,
        ports: &[PortInfo],
        config: &ScanConfig,
    ) -> Vec<PortInfo>;
}

#[cfg(feature = "fingerprint")]
mod tcp_connect;
#[cfg(feature = "fingerprint")]
pub use tcp_connect::TcpConnectStrategy;

#[cfg(test)]
pub mod mock;

#[cfg(feature = "fingerprint")]
pub fn default_strategy(config: &ScanConfig) -> Box<dyn ScanStrategy> {
    Box::new(TcpConnectStrategy::new(config))
}
