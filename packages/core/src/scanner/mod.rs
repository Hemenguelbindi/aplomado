pub mod model;

#[cfg(feature = "scanner")]
pub mod ping;
#[cfg(feature = "scanner")]
pub mod port;

#[cfg(feature = "scanner")]
pub mod progress;

use std::net::{IpAddr, Ipv4Addr};

/// Развернуть CIDR в список IP-адресов.
/// Например "10.2.2.0/24" → [10.2.2.1, 10.2.2.2, ..., 10.2.2.254]
///
/// Ограничение: максимум 65536 адресов (защита от /8, /0 и т.д.)
pub fn expand_cidr(cidr: &str) -> Vec<IpAddr> {
    let (base_str, prefix_str) = match cidr.split_once('/') {
        Some(parts) => parts,
        None => return vec![],
    };

    let prefix: u8 = match prefix_str.parse() {
        Ok(p) if p <= 32 => p,
        _ => return vec![],
    };

    let base: u32 = match base_str.parse::<Ipv4Addr>() {
        Ok(ip) => u32::from(ip),
        Err(_) => return vec![],
    };

    if prefix == 32 {
        return vec![IpAddr::V4(Ipv4Addr::from(base))];
    }

    let host_bits = 32 - prefix;
    let network = base & (0xFFFFFFFFu32.wrapping_shl(host_bits as u32));

    let total_hosts = if host_bits <= 16 {
        (1u32 << host_bits).saturating_sub(2)
    } else {
        65534u32
    };

    let mut ips = Vec::with_capacity(total_hosts as usize);
    for i in 1..=total_hosts {
        ips.push(IpAddr::V4(Ipv4Addr::from(network.wrapping_add(i))));
    }
    ips
}

/// Развернуть диапазон IP вида "10.2.2.1-10.2.2.254"
pub fn expand_range(start_str: &str, end_str: &str) -> Vec<IpAddr> {
    let start: u32 = match start_str.parse::<Ipv4Addr>() {
        Ok(ip) => u32::from(ip),
        Err(_) => return vec![],
    };
    let end: u32 = match end_str.parse::<Ipv4Addr>() {
        Ok(ip) => u32::from(ip),
        Err(_) => return vec![],
    };

    if end < start || end.saturating_sub(start) > 65536 {
        return vec![];
    }

    (start..=end)
        .map(|n| IpAddr::V4(Ipv4Addr::from(n)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_24() {
        let ips = expand_cidr("10.2.2.0/24");
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0].to_string(), "10.2.2.1");
        assert_eq!(ips[253].to_string(), "10.2.2.254");
    }

    #[test]
    fn test_cidr_32() {
        let ips = expand_cidr("10.0.0.1/32");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "10.0.0.1");
    }

    #[test]
    fn test_range() {
        let ips = expand_range("10.0.0.1", "10.0.0.5");
        assert_eq!(ips.len(), 5);
        assert_eq!(ips[0].to_string(), "10.0.0.1");
        assert_eq!(ips[4].to_string(), "10.0.0.5");
    }

    #[test]
    fn test_cidr_0_caps_at_65534() {
        let ips = expand_cidr("10.0.0.0/0");
        assert_eq!(ips.len(), 65534);
    }

    #[test]
    fn test_cidr_1_caps_at_65534() {
        let ips = expand_cidr("10.0.0.0/1");
        assert_eq!(ips.len(), 65534);
    }

    #[test]
    fn test_cidr_8_caps_at_65534() {
        let ips = expand_cidr("10.0.0.0/8");
        assert_eq!(ips.len(), 65534);
    }

    #[test]
    fn test_cidr_16() {
        let ips = expand_cidr("10.0.0.0/16");
        assert_eq!(ips.len(), 65534);
    }

    #[test]
    fn test_cidr_invalid_prefix() {
        let ips = expand_cidr("10.0.0.0/33");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_cidr_invalid_ip() {
        let ips = expand_cidr("999.999.999.999/24");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_cidr_no_slash() {
        let ips = expand_cidr("10.0.0.1");
        assert!(ips.is_empty());
    }
}
