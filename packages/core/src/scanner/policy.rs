use std::net::IpAddr;

/// Server-side scan policy — controls which targets are allowed.
///
/// By default blocks:
/// - Loopback (127.0.0.0/8, ::1)
/// - Link-local (169.254.0.0/16, fe80::/10)
/// - Multicast (224.0.0.0/4, ff00::/8)
/// - Broadcast (255.255.255.255)
/// - Unspecified (0.0.0.0/8, ::)
/// - Documentation (TEST-NET 192.0.2.0/24, etc.)
#[derive(Debug, Clone)]
pub struct ScanPolicy {
    pub allow_loopback: bool,
    pub allow_link_local: bool,
    pub allow_multicast: bool,
    pub allow_broadcast: bool,
    pub allow_unspecified: bool,
    pub allow_documentation: bool,
    pub allow_private: bool,
    pub max_ips: usize,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            allow_loopback: false,
            allow_link_local: false,
            allow_multicast: false,
            allow_broadcast: false,
            allow_unspecified: false,
            allow_documentation: false,
            allow_private: true,
            max_ips: 65536,
        }
    }
}

impl ScanPolicy {
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() && !self.allow_loopback {
                    return false;
                }
                if v4.is_link_local() && !self.allow_link_local {
                    return false;
                }
                if v4.is_multicast() && !self.allow_multicast {
                    return false;
                }
                if v4.is_broadcast() && !self.allow_broadcast {
                    return false;
                }
                if v4.is_unspecified() && !self.allow_unspecified {
                    return false;
                }
                if v4.is_documentation() && !self.allow_documentation {
                    return false;
                }
                if v4.is_private() && !self.allow_private {
                    return false;
                }
                if v4.octets()[0] == 0 && !self.allow_unspecified {
                    return false;
                }
                true
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() && !self.allow_loopback {
                    return false;
                }
                if v6.is_unicast_link_local() && !self.allow_link_local {
                    return false;
                }
                if v6.is_multicast() && !self.allow_multicast {
                    return false;
                }
                if v6.is_unspecified() && !self.allow_unspecified {
                    return false;
                }
                true
            }
        }
    }

    /// Filter a list of IPs, keeping only those allowed by policy.
    pub fn filter(&self, ips: Vec<IpAddr>) -> Vec<IpAddr> {
        ips.into_iter().filter(|&ip| self.is_allowed(ip)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn default_policy_blocks_loopback_v4() {
        let policy = ScanPolicy::default();
        assert!(!policy.is_allowed(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn default_policy_blocks_loopback_v6() {
        let policy = ScanPolicy::default();
        assert!(!policy.is_allowed(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn default_policy_blocks_multicast() {
        let policy = ScanPolicy::default();
        assert!(!policy.is_allowed(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
    }

    #[test]
    fn default_policy_blocks_broadcast() {
        let policy = ScanPolicy::default();
        assert!(!policy.is_allowed(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn default_policy_allows_private() {
        let policy = ScanPolicy::default();
        assert!(policy.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(policy.is_allowed(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(policy.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
    }

    #[test]
    fn default_policy_blocks_unspecified() {
        let policy = ScanPolicy::default();
        assert!(!policy.is_allowed(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    }

    #[test]
    fn allow_loopback_when_enabled() {
        let policy = ScanPolicy {
            allow_loopback: true,
            ..Default::default()
        };
        assert!(policy.is_allowed(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn filter_removes_blocked() {
        let policy = ScanPolicy::default();
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        ];
        let allowed = policy.filter(ips);
        assert_eq!(allowed.len(), 2);
        assert_eq!(allowed[0].to_string(), "10.0.0.1");
        assert_eq!(allowed[1].to_string(), "192.168.1.1");
    }
}
