use crate::models::ScanTarget;

pub fn parse_target(s: &str) -> Option<ScanTarget> {
    let s = s.trim();
    if s.is_empty() { return None; }
    if s.contains('/') { return Some(ScanTarget::Cidr(s.to_string())); }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() { return Some(ScanTarget::Ip(ip)); }
    Some(ScanTarget::Hostname(s.to_string()))
}

pub fn parse_custom_ports(input: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if let Some(range) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (range.0.trim().parse::<u16>(), range.1.trim().parse::<u16>()) {
                if s <= e {
                    for p in s..=e {
                        if !ports.contains(&p) { ports.push(p); }
                    }
                }
            }
        } else {
            if let Ok(p) = part.parse::<u16>() {
                if !ports.contains(&p) { ports.push(p); }
            }
        }
    }
    ports.sort();
    ports
}
