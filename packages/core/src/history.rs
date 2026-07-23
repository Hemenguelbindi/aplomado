use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

/// Полный результат скана для сохранения
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanRecord {
    pub id: String,
    pub label: String,
    pub targets: Vec<String>,
    pub timestamp: String,
    pub duration_secs: u64,
    pub hosts_total: u32,
    pub hosts_alive: u32,
    pub hosts_found: u32,
    pub ports_total: u32,
    pub hosts: Vec<StoredHostInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredHostInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub alive: bool,
    pub ports: Vec<StoredPortInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredPortInfo {
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    #[serde(default)]
    pub cves: Vec<StoredCveSummary>,
}

/// Summary of a CVE vulnerability associated with a port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredCveSummary {
    pub id: String,
    pub severity: String,
    pub cvss_score: f32,
    #[serde(default)]
    pub fixed_version: Option<String>,
    #[serde(default)]
    pub advisory_url: Option<String>,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub method: String,
}

// ---- Diff types ----

/// The type of a change detected when comparing two scans.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChangeType {
    Added,
    Removed,
    ServiceChanged(String, String),
    VersionChanged(Option<String>, Option<String>),
}

/// A change to a single port between two scans.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortChange {
    pub host_ip: String,
    pub port: u16,
    pub change_type: ChangeType,
}

/// A change to a CVE entry between two scans.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveChange {
    pub host_ip: String,
    pub cve_id: String,
    pub change_type: ChangeType,
}

/// Result of comparing two scan records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanDiff {
    pub scan_a_id: String,
    pub scan_b_id: String,
    pub hosts_added: Vec<String>,
    pub hosts_removed: Vec<String>,
    pub hosts_unchanged: usize,
    pub port_changes: Vec<PortChange>,
    pub cve_changes: Vec<CveChange>,
    pub alive_change: i32,
    pub ports_total_change: i32,
}

/// Diff two scan records by host IP identity.
///
/// This is a pure function: no I/O, no mutation, no database access.
/// Hosts are matched by their `ip` field. Ports are matched by port number.
/// CVEs are matched by `StoredCveSummary.id`.
pub fn diff_scans(a: &ScanRecord, b: &ScanRecord) -> ScanDiff {
    let a_hosts: HashMap<&str, &StoredHostInfo> =
        a.hosts.iter().map(|h| (h.ip.as_str(), h)).collect();
    let b_hosts: HashMap<&str, &StoredHostInfo> =
        b.hosts.iter().map(|h| (h.ip.as_str(), h)).collect();

    let mut hosts_added: Vec<String> = Vec::new();
    let mut hosts_removed: Vec<String> = Vec::new();
    let mut port_changes: Vec<PortChange> = Vec::new();
    let mut cve_changes: Vec<CveChange> = Vec::new();

    // Hosts only in b (added)
    for ip in b_hosts.keys() {
        if !a_hosts.contains_key(ip) {
            hosts_added.push((*ip).to_string());
        }
    }

    // Hosts only in a (removed)
    for ip in a_hosts.keys() {
        if !b_hosts.contains_key(ip) {
            hosts_removed.push((*ip).to_string());
        }
    }

    // Hosts present in both — compare ports and CVEs
    let hosts_unchanged = a_hosts
        .keys()
        .filter(|ip| b_hosts.contains_key(*ip))
        .count();

    for ip in a_hosts.keys().filter(|ip| b_hosts.contains_key(*ip)) {
        let a_host = a_hosts[ip];
        let b_host = b_hosts[ip];

        let a_ports: HashMap<u16, &StoredPortInfo> =
            a_host.ports.iter().map(|p| (p.port, p)).collect();
        let b_ports: HashMap<u16, &StoredPortInfo> =
            b_host.ports.iter().map(|p| (p.port, p)).collect();

        // Ports added in b
        for &port in b_ports.keys() {
            if !a_ports.contains_key(&port) {
                port_changes.push(PortChange {
                    host_ip: ip.to_string(),
                    port,
                    change_type: ChangeType::Added,
                });
            }
        }

        // Ports removed from b
        for &port in a_ports.keys() {
            if !b_ports.contains_key(&port) {
                port_changes.push(PortChange {
                    host_ip: ip.to_string(),
                    port,
                    change_type: ChangeType::Removed,
                });
            }
        }

        // Ports in both — check for service / version changes
        for (&port, a_p) in &a_ports {
            if let Some(b_p) = b_ports.get(&port) {
                if a_p.service != b_p.service {
                    port_changes.push(PortChange {
                        host_ip: ip.to_string(),
                        port,
                        change_type: ChangeType::ServiceChanged(
                            a_p.service.clone(),
                            b_p.service.clone(),
                        ),
                    });
                }
                if a_p.version != b_p.version {
                    port_changes.push(PortChange {
                        host_ip: ip.to_string(),
                        port,
                        change_type: ChangeType::VersionChanged(
                            a_p.version.clone(),
                            b_p.version.clone(),
                        ),
                    });
                }
            }
        }

        // CVE diffing across all ports on this host
        let a_cve_ids: HashSet<&str> = a_host
            .ports
            .iter()
            .flat_map(|p| p.cves.iter().map(|c| c.id.as_str()))
            .collect();
        let b_cve_ids: HashSet<&str> = b_host
            .ports
            .iter()
            .flat_map(|p| p.cves.iter().map(|c| c.id.as_str()))
            .collect();

        for cve_id in &b_cve_ids {
            if !a_cve_ids.contains(cve_id) {
                cve_changes.push(CveChange {
                    host_ip: ip.to_string(),
                    cve_id: cve_id.to_string(),
                    change_type: ChangeType::Added,
                });
            }
        }

        for cve_id in &a_cve_ids {
            if !b_cve_ids.contains(cve_id) {
                cve_changes.push(CveChange {
                    host_ip: ip.to_string(),
                    cve_id: cve_id.to_string(),
                    change_type: ChangeType::Removed,
                });
            }
        }
    }

    let alive_change = b.hosts_alive as i32 - a.hosts_alive as i32;
    let ports_total_change = b.ports_total as i32 - a.ports_total as i32;

    ScanDiff {
        scan_a_id: a.id.clone(),
        scan_b_id: b.id.clone(),
        hosts_added,
        hosts_removed,
        hosts_unchanged,
        port_changes,
        cve_changes,
        alive_change,
        ports_total_change,
    }
}

/// Сохранить скан в SQLite.
pub fn save_scan(record: &ScanRecord) -> std::io::Result<()> {
    #[cfg(feature = "database")]
    {
        crate::database::save_scan(record).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(())
    }
    #[cfg(not(feature = "database"))]
    {
        let _ = record;
        eprintln!("Cannot save scan: database feature not enabled");
        Ok(())
    }
}

/// Загрузить историю из SQLite.
pub fn load_history() -> Vec<ScanRecord> {
    #[cfg(feature = "database")]
    {
        crate::database::load_history().unwrap_or_default()
    }
    #[cfg(not(feature = "database"))]
    {
        vec![]
    }
}

/// Загрузить последний скан из SQLite.
pub fn load_last_scan() -> Option<ScanRecord> {
    #[cfg(feature = "database")]
    {
        crate::database::load_last_scan().ok()?
    }
    #[cfg(not(feature = "database"))]
    {
        None
    }
}

/// Удалить запись из SQLite.
pub fn delete_scan(id: &str) -> std::io::Result<()> {
    #[cfg(feature = "database")]
    {
        crate::database::delete_scan(id).map_err(|e| std::io::Error::other(e.to_string()))
    }
    #[cfg(not(feature = "database"))]
    {
        let _ = id;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Conversions from stored types → aplomado_types public models
// ---------------------------------------------------------------------------

impl From<StoredCveSummary> for aplomado_types::CveSummary {
    fn from(s: StoredCveSummary) -> Self {
        Self {
            id: s.id,
            severity: s.severity,
            cvss_score: s.cvss_score,
            fixed_version: s.fixed_version,
            advisory_url: s.advisory_url,
            confidence: s.confidence,
            method: s.method,
        }
    }
}

impl From<StoredPortInfo> for aplomado_types::PortInfo {
    fn from(s: StoredPortInfo) -> Self {
        Self {
            port: s.port,
            protocol: aplomado_types::TransportProto::Tcp,
            state: aplomado_types::PortState::Open,
            service_name: s.service,
            service_version: s.version,
            banner: s.banner,
            cpe: None,
            cves: s.cves.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<StoredHostInfo> for aplomado_types::HostInfo {
    fn from(s: StoredHostInfo) -> Self {
        Self {
            ip: s.ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            hostname: s.hostname,
            ttl: None,
            os_guess: s.os_guess,
            ports: s.ports.into_iter().map(Into::into).collect(),
            alive: s.alive,
            route: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scan(id: &str, hosts: Vec<StoredHostInfo>) -> ScanRecord {
        let alive = hosts.iter().filter(|h| h.alive).count() as u32;
        let ports: u32 = hosts.iter().map(|h| h.ports.len() as u32).sum();
        ScanRecord {
            id: id.to_string(),
            label: format!("scan-{id}"),
            targets: vec![],
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            duration_secs: 0,
            hosts_total: hosts.len() as u32,
            hosts_alive: alive,
            hosts_found: hosts.len() as u32,
            ports_total: ports,
            hosts,
        }
    }

    fn host(ip: &str, alive: bool, ports: Vec<StoredPortInfo>) -> StoredHostInfo {
        StoredHostInfo {
            ip: ip.to_string(),
            hostname: None,
            os_guess: None,
            alive,
            ports,
        }
    }

    fn port(num: u16, service: &str, version: Option<&str>) -> StoredPortInfo {
        StoredPortInfo {
            port: num,
            service: service.to_string(),
            version: version.map(|s| s.to_string()),
            banner: None,
            cves: vec![],
        }
    }

    fn port_with_cves(
        num: u16,
        service: &str,
        version: Option<&str>,
        cves: Vec<StoredCveSummary>,
    ) -> StoredPortInfo {
        StoredPortInfo {
            port: num,
            service: service.to_string(),
            version: version.map(|s| s.to_string()),
            banner: None,
            cves,
        }
    }

    fn cve(id: &str) -> StoredCveSummary {
        StoredCveSummary {
            id: id.to_string(),
            severity: "UNKNOWN".to_string(),
            cvss_score: 0.0,
            fixed_version: None,
            advisory_url: None,
            confidence: String::new(),
            method: String::new(),
        }
    }

    #[test]
    fn identical_scans_produce_empty_diff() {
        let hosts = vec![
            host("10.0.0.1", true, vec![port(80, "http", Some("1.1"))]),
            host("10.0.0.2", false, vec![]),
        ];
        let a = make_scan("s1", hosts.clone());
        let b = make_scan("s2", hosts);
        let d = diff_scans(&a, &b);

        assert_eq!(d.scan_a_id, "s1");
        assert_eq!(d.scan_b_id, "s2");
        assert!(d.hosts_added.is_empty());
        assert!(d.hosts_removed.is_empty());
        assert_eq!(d.hosts_unchanged, 2);
        assert!(d.port_changes.is_empty());
        assert!(d.cve_changes.is_empty());
        assert_eq!(d.alive_change, 0);
        assert_eq!(d.ports_total_change, 0);
    }

    #[test]
    fn one_new_host_shows_in_hosts_added() {
        let a = make_scan("a", vec![host("10.0.0.1", true, vec![])]);
        let b = make_scan(
            "b",
            vec![
                host("10.0.0.1", true, vec![]),
                host("10.0.0.2", true, vec![]),
            ],
        );
        let d = diff_scans(&a, &b);

        assert_eq!(d.hosts_added, vec!["10.0.0.2".to_string()]);
        assert!(d.hosts_removed.is_empty());
        assert_eq!(d.hosts_unchanged, 1);
    }

    #[test]
    fn one_removed_host_shows_in_hosts_removed() {
        let a = make_scan(
            "a",
            vec![
                host("10.0.0.1", true, vec![]),
                host("10.0.0.2", true, vec![]),
            ],
        );
        let b = make_scan("b", vec![host("10.0.0.1", true, vec![])]);
        let d = diff_scans(&a, &b);

        assert!(d.hosts_added.is_empty());
        assert_eq!(d.hosts_removed, vec!["10.0.0.2".to_string()]);
        assert_eq!(d.hosts_unchanged, 1);
    }

    #[test]
    fn version_change_creates_version_changed() {
        let hosts_a = vec![host(
            "10.0.0.1",
            true,
            vec![port(80, "nginx", Some("1.18"))],
        )];
        let hosts_b = vec![host(
            "10.0.0.1",
            true,
            vec![port(80, "nginx", Some("1.20"))],
        )];
        let a = make_scan("a", hosts_a);
        let b = make_scan("b", hosts_b);
        let d = diff_scans(&a, &b);

        assert_eq!(d.port_changes.len(), 1);
        assert_eq!(d.port_changes[0].host_ip, "10.0.0.1");
        assert_eq!(d.port_changes[0].port, 80);
        assert_eq!(
            d.port_changes[0].change_type,
            ChangeType::VersionChanged(Some("1.18".into()), Some("1.20".into()))
        );
    }

    #[test]
    fn service_change_creates_service_changed() {
        let hosts_a = vec![host(
            "10.0.0.1",
            true,
            vec![port(80, "apache", Some("2.4"))],
        )];
        let hosts_b = vec![host("10.0.0.1", true, vec![port(80, "nginx", Some("2.4"))])];
        let a = make_scan("a", hosts_a);
        let b = make_scan("b", hosts_b);
        let d = diff_scans(&a, &b);

        assert_eq!(d.port_changes.len(), 1);
        assert_eq!(d.port_changes[0].host_ip, "10.0.0.1");
        assert_eq!(d.port_changes[0].port, 80);
        assert_eq!(
            d.port_changes[0].change_type,
            ChangeType::ServiceChanged("apache".into(), "nginx".into())
        );
    }

    #[test]
    fn two_empty_scans_produce_zero_diff() {
        let a = make_scan("a", vec![]);
        let b = make_scan("b", vec![]);
        let d = diff_scans(&a, &b);

        assert!(d.hosts_added.is_empty());
        assert!(d.hosts_removed.is_empty());
        assert_eq!(d.hosts_unchanged, 0);
        assert!(d.port_changes.is_empty());
        assert!(d.cve_changes.is_empty());
        assert_eq!(d.alive_change, 0);
        assert_eq!(d.ports_total_change, 0);
    }

    #[test]
    fn non_empty_scan_diffed_with_empty_scan() {
        let hosts = vec![
            host("10.0.0.1", true, vec![port(22, "ssh", None)]),
            host("10.0.0.2", false, vec![]),
        ];
        let a = make_scan("a", hosts);
        let b = make_scan("b", vec![]);
        let d = diff_scans(&a, &b);

        assert!(d.hosts_added.is_empty());
        let mut removed = d.hosts_removed.clone();
        removed.sort();
        assert_eq!(removed, vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(d.hosts_unchanged, 0);
        assert!(d.port_changes.is_empty());
        assert_eq!(d.alive_change, -1);
        assert_eq!(d.ports_total_change, -1);
    }

    #[test]
    fn cve_change_populates_cve_changes() {
        let hosts_a = vec![host(
            "10.0.0.1",
            true,
            vec![port_with_cves(
                80,
                "http",
                None,
                vec![cve("CVE-2024-0001"), cve("CVE-2024-0002")],
            )],
        )];
        let hosts_b = vec![host(
            "10.0.0.1",
            true,
            vec![port_with_cves(
                80,
                "http",
                None,
                vec![cve("CVE-2024-0001"), cve("CVE-2024-0003")],
            )],
        )];
        let a = make_scan("a", hosts_a);
        let b = make_scan("b", hosts_b);
        let d = diff_scans(&a, &b);

        assert_eq!(d.cve_changes.len(), 2);

        let added: Vec<&CveChange> = d
            .cve_changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Added)
            .collect();
        let removed: Vec<&CveChange> = d
            .cve_changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Removed)
            .collect();

        assert_eq!(added.len(), 1);
        assert_eq!(added[0].cve_id, "CVE-2024-0003");
        assert_eq!(added[0].host_ip, "10.0.0.1");

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].cve_id, "CVE-2024-0002");
        assert_eq!(removed[0].host_ip, "10.0.0.1");
    }

    #[test]
    fn multiple_hosts_added_and_removed() {
        let a = make_scan(
            "a",
            vec![
                host("10.0.0.1", true, vec![]),
                host("10.0.0.2", true, vec![]),
                host("10.0.0.3", true, vec![]),
            ],
        );
        let b = make_scan(
            "b",
            vec![
                host("10.0.0.2", true, vec![]),
                host("10.0.0.3", true, vec![]),
                host("10.0.0.4", true, vec![]),
                host("10.0.0.5", true, vec![]),
            ],
        );
        let d = diff_scans(&a, &b);

        assert_eq!(d.hosts_added.len(), 2);
        assert!(d.hosts_added.contains(&"10.0.0.4".to_string()));
        assert!(d.hosts_added.contains(&"10.0.0.5".to_string()));

        assert_eq!(d.hosts_removed.len(), 1);
        assert!(d.hosts_removed.contains(&"10.0.0.1".to_string()));

        assert_eq!(d.hosts_unchanged, 2);
        assert_eq!(d.alive_change, 1);
    }

    #[test]
    fn test_cve_round_trip() {
        let port = StoredPortInfo {
            port: 443,
            service: "https".into(),
            version: Some("1.1".into()),
            banner: None,
            cves: vec![
                StoredCveSummary {
                    id: "CVE-2024-0001".into(),
                    severity: "HIGH".into(),
                    cvss_score: 7.5,
                    fixed_version: None,
                    advisory_url: None,
                    confidence: String::new(),
                    method: String::new(),
                },
                StoredCveSummary {
                    id: "CVE-2024-0002".into(),
                    severity: "MEDIUM".into(),
                    cvss_score: 5.0,
                    fixed_version: None,
                    advisory_url: None,
                    confidence: String::new(),
                    method: String::new(),
                },
                StoredCveSummary {
                    id: "CVE-2024-0003".into(),
                    severity: "CRITICAL".into(),
                    cvss_score: 9.8,
                    fixed_version: None,
                    advisory_url: None,
                    confidence: String::new(),
                    method: String::new(),
                },
            ],
        };

        let json = serde_json::to_string(&port).unwrap();
        let deserialized: StoredPortInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.cves.len(), 3);
        assert_eq!(deserialized.cves[0].id, "CVE-2024-0001");
        assert_eq!(deserialized.cves[1].severity, "MEDIUM");
        assert!((deserialized.cves[2].cvss_score - 9.8).abs() < f32::EPSILON);
    }

    #[test]
    fn test_backward_compat_no_cves_field() {
        let old_json = r#"{
            "port": 80,
            "service": "http",
            "version": null,
            "banner": null
        }"#;

        let port: StoredPortInfo = serde_json::from_str(old_json).unwrap();
        assert!(port.cves.is_empty());
        assert_eq!(port.port, 80);
        assert_eq!(port.service, "http");
    }
}
