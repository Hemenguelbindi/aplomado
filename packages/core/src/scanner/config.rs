use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct ScanConfig {
    pub max_concurrent_hosts: usize,
    pub max_concurrent_ports: usize,
    pub connect_timeout: Duration,
    pub adaptive_timeouts: bool,
    pub fast_mode: bool,
    pub max_scan_duration: Duration,
    pub probe_chain_timeout: Duration,
    pub probe_chain_max_total: Duration,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_concurrent_hosts: 10,
            max_concurrent_ports: 100,
            connect_timeout: Duration::from_secs(3),
            adaptive_timeouts: true,
            fast_mode: false,
            max_scan_duration: Duration::from_secs(1800),
            probe_chain_timeout: Duration::from_secs(5),
            probe_chain_max_total: Duration::from_secs(30),
        }
    }
}

impl ScanConfig {
    pub fn fast() -> Self {
        Self {
            fast_mode: true,
            connect_timeout: Duration::from_millis(1500),
            max_concurrent_ports: 50,
            probe_chain_timeout: Duration::from_secs(2),
            probe_chain_max_total: Duration::from_secs(10),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_reasonable() {
        let cfg = ScanConfig::default();
        assert_eq!(cfg.max_concurrent_hosts, 10);
        assert_eq!(cfg.max_concurrent_ports, 100);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(3));
        assert!(cfg.adaptive_timeouts);
        assert!(!cfg.fast_mode);
        assert_eq!(cfg.max_scan_duration, Duration::from_secs(1800));
        assert_eq!(cfg.probe_chain_timeout, Duration::from_secs(5));
        assert_eq!(cfg.probe_chain_max_total, Duration::from_secs(30));
    }

    #[test]
    fn fast_mode_halves_timeouts() {
        let cfg = ScanConfig::fast();
        assert!(cfg.fast_mode);
        assert_eq!(cfg.connect_timeout, Duration::from_millis(1500));
        assert_eq!(cfg.probe_chain_timeout, Duration::from_secs(2));
    }

    #[test]
    fn fast_ports_reduced() {
        let cfg = ScanConfig::fast();
        assert_eq!(cfg.max_concurrent_ports, 50);
    }

    #[test]
    fn clone_roundtrip() {
        let a = ScanConfig::fast();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn partial_eq_works() {
        let a = ScanConfig::default();
        let b = ScanConfig::default();
        let c = ScanConfig::fast();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
