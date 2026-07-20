pub mod model;
pub mod policy;

#[cfg(feature = "scanner")]
pub mod ping;
#[cfg(feature = "scanner")]
pub mod port;

#[cfg(feature = "scanner")]
pub mod progress;

#[cfg(feature = "fingerprint")]
pub mod engine;

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use crate::scanner::model::ScanTarget;

// ---------------------------------------------------------------------------
// Typed resolution errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TargetResolveError {
    #[error("Invalid target string: {0}")]
    InvalidTarget(String),

    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),

    #[error("Invalid prefix length {0} in CIDR")]
    InvalidPrefix(u8),

    #[error("Unsupported address family (IPv6 CIDR not yet supported)")]
    UnsupportedAddressFamily,

    #[error("CIDR range too large (max {max} hosts, requested {requested})")]
    RangeTooLarge { max: u32, requested: u32 },

    #[error("Invalid IP range: end {end} < start {start}")]
    InvalidRange { start: String, end: String },

    #[error("DNS resolution failed for {0}")]
    DnsResolutionFailed(String),

    #[error("No addresses resolved from {0}")]
    NoAddressesResolved(String),
}

/// Maximum number of IPs to expand from a single CIDR.
pub const MAX_CIDR_TARGETS: u32 = 65536;

/// Развернуть CIDR в список IP-адресов.
/// Возвращает ошибку, если CIDR невалиден или диапазон слишком большой.
///
/// Семантика:
/// - `/32` → 1 адрес (сам IP)
/// - `/31` → 2 адреса (оба хостовых, как в RFC 3021 для point-to-point)
/// - network/broadcast исключаются для prefix > 30
pub fn expand_cidr(cidr: &str) -> Result<Vec<IpAddr>, TargetResolveError> {
    let (base_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| TargetResolveError::InvalidCidr(cidr.to_string()))?;

    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| TargetResolveError::InvalidCidr(cidr.to_string()))?;

    if prefix > 32 {
        return Err(TargetResolveError::InvalidPrefix(prefix));
    }

    let base: u32 = base_str
        .parse::<Ipv4Addr>()
        .map_err(|_| TargetResolveError::InvalidCidr(cidr.to_string()))
        .map(u32::from)?;

    if prefix == 32 {
        return Ok(vec![IpAddr::V4(Ipv4Addr::from(base))]);
    }

    let host_bits = 32 - prefix;

    // Check range size before bit shifting (avoid overflow for very small prefixes)
    let raw_total = 1u32.wrapping_shl(u32::from(host_bits.min(31)));
    if raw_total > MAX_CIDR_TARGETS || prefix < 16 {
        let displayed = 1u32.wrapping_shl(u32::from(host_bits.min(16)));
        return Err(TargetResolveError::RangeTooLarge {
            max: MAX_CIDR_TARGETS,
            requested: displayed,
        });
    }

    let network = base & (0xFFFFFFFFu32.wrapping_shl(u32::from(host_bits)));

    // RFC 3021: /31 allows both addresses as host addresses (no network/broadcast)
    let (start_offset, end_offset) = if prefix >= 31 {
        (0u32, (1u32 << host_bits).saturating_sub(1))
    } else {
        (1u32, (1u32 << host_bits).saturating_sub(2))
    };

    let host_count = end_offset.saturating_sub(start_offset).saturating_add(1);

    let mut ips = Vec::with_capacity(host_count as usize);
    for i in start_offset..=end_offset {
        ips.push(IpAddr::V4(Ipv4Addr::from(network.wrapping_add(i))));
    }
    Ok(ips)
}

/// Resolve a `ScanTarget` to a list of IP addresses.
pub fn resolve_targets(target: &ScanTarget) -> Result<Vec<IpAddr>, TargetResolveError> {
    match target {
        ScanTarget::Ip(ip) => Ok(vec![*ip]),
        ScanTarget::Hostname(h) => {
            let addrs: Vec<IpAddr> = (h.as_str(), 0)
                .to_socket_addrs()
                .map_err(|_| TargetResolveError::DnsResolutionFailed(h.clone()))?
                .map(|s| s.ip())
                .collect();
            if addrs.is_empty() {
                Err(TargetResolveError::NoAddressesResolved(h.clone()))
            } else {
                Ok(addrs)
            }
        }
        ScanTarget::Cidr(c) => expand_cidr(c),
        ScanTarget::Range(start, end) => expand_range(&start.to_string(), &end.to_string()),
    }
}

/// Resolve a raw string target to a list of IP addresses.
/// Accepts: single IP, CIDR notation, or hostname.
pub fn resolve_target_str(s: &str) -> Result<Vec<IpAddr>, TargetResolveError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(TargetResolveError::InvalidTarget("empty string".into()));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if s.contains('/') {
        return expand_cidr(s);
    }
    // Hostname — DNS resolve
    let addrs: Vec<IpAddr> = (s, 0u16)
        .to_socket_addrs()
        .map_err(|_| TargetResolveError::DnsResolutionFailed(s.to_string()))?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() {
        Err(TargetResolveError::NoAddressesResolved(s.to_string()))
    } else {
        Ok(addrs)
    }
}

/// Развернуть диапазон IP вида "10.2.2.1-10.2.2.254"
pub fn expand_range(start_str: &str, end_str: &str) -> Result<Vec<IpAddr>, TargetResolveError> {
    let start: u32 = start_str
        .parse::<Ipv4Addr>()
        .map_err(|_| TargetResolveError::InvalidTarget(format!("invalid start IP: {start_str}")))
        .map(u32::from)?;
    let end: u32 = end_str
        .parse::<Ipv4Addr>()
        .map_err(|_| TargetResolveError::InvalidTarget(format!("invalid end IP: {end_str}")))
        .map(u32::from)?;

    if end < start {
        return Err(TargetResolveError::InvalidRange {
            start: start_str.to_string(),
            end: end_str.to_string(),
        });
    }

    let count = end.saturating_sub(start).saturating_add(1);
    if count > MAX_CIDR_TARGETS {
        return Err(TargetResolveError::RangeTooLarge {
            max: MAX_CIDR_TARGETS,
            requested: count,
        });
    }

    Ok((start..=end)
        .map(|n| IpAddr::V4(Ipv4Addr::from(n)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_24() {
        let ips = expand_cidr("10.2.2.0/24").unwrap();
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0].to_string(), "10.2.2.1");
        assert_eq!(ips[253].to_string(), "10.2.2.254");
    }

    #[test]
    fn test_cidr_32() {
        let ips = expand_cidr("10.0.0.1/32").unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "10.0.0.1");
    }

    #[test]
    fn test_cidr_31() {
        let ips = expand_cidr("10.0.0.0/31").unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "10.0.0.0");
        assert_eq!(ips[1].to_string(), "10.0.0.1");
    }

    #[test]
    fn test_range() {
        let ips = expand_range("10.0.0.1", "10.0.0.5").unwrap();
        assert_eq!(ips.len(), 5);
        assert_eq!(ips[0].to_string(), "10.0.0.1");
        assert_eq!(ips[4].to_string(), "10.0.0.5");
    }

    #[test]
    fn test_cidr_0_returns_err() {
        let result = expand_cidr("10.0.0.0/0");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(TargetResolveError::RangeTooLarge { .. })
        ));
    }

    #[test]
    fn test_cidr_1_returns_err() {
        let result = expand_cidr("10.0.0.0/1");
        assert!(result.is_err());
    }

    #[test]
    fn test_cidr_8_returns_err() {
        let result = expand_cidr("10.0.0.0/8");
        assert!(result.is_err());
    }

    #[test]
    fn test_cidr_16_returns_ok() {
        let ips = expand_cidr("10.0.0.0/16").unwrap();
        assert_eq!(ips.len(), 65534);
        assert_eq!(ips[0].to_string(), "10.0.0.1");
        assert_eq!(ips[65533].to_string(), "10.0.255.254");
    }

    #[test]
    fn test_cidr_17_returns_ok() {
        let ips = expand_cidr("10.0.0.0/17").unwrap();
        assert_eq!(ips.len(), 32766);
    }

    #[test]
    fn test_cidr_invalid_prefix() {
        let result = expand_cidr("10.0.0.0/33");
        assert!(matches!(result, Err(TargetResolveError::InvalidPrefix(33))));
    }

    #[test]
    fn test_cidr_invalid_ip() {
        let result = expand_cidr("999.999.999.999/24");
        assert!(matches!(result, Err(TargetResolveError::InvalidCidr(_))));
    }

    #[test]
    fn test_cidr_no_slash() {
        let result = expand_cidr("10.0.0.1");
        assert!(matches!(result, Err(TargetResolveError::InvalidCidr(_))));
    }

    #[test]
    fn test_negative_range_returns_err() {
        let result = expand_range("10.0.0.10", "10.0.0.1");
        assert!(matches!(
            result,
            Err(TargetResolveError::InvalidRange { .. })
        ));
    }

    #[test]
    fn test_invalid_range_start() {
        let result = expand_range("not-an-ip", "10.0.0.1");
        assert!(matches!(result, Err(TargetResolveError::InvalidTarget(_))));
    }

    #[test]
    fn test_empty_target_str() {
        let result = resolve_target_str("");
        assert!(matches!(result, Err(TargetResolveError::InvalidTarget(_))));
    }
}
