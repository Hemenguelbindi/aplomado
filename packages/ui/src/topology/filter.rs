use crate::models::HostInfo;
use crate::topology::graph::NodeSeverity;
use crate::topology::state::TopologyContext;

/// Apply all active filters from topology context to the host list.
/// Returns the filtered subset of alive hosts.
pub fn compute_filtered_hosts(hosts: &[HostInfo], ctx: &TopologyContext) -> Vec<HostInfo> {
    let severity_filter = (ctx.filter_severity)();
    let os_filter = (ctx.filter_os)();
    let query = (ctx.search_query)().to_lowercase();
    let port_filter_enabled = (ctx.port_filter_enabled)();
    let filter_services = (ctx.filter_services)();
    let only_cve = (ctx.only_cve)();

    let top_service_names: Vec<String> = {
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for h in hosts {
            for p in &h.ports {
                *counts.entry(p.service_name.clone()).or_insert(0) += 1;
            }
        }
        let mut v: Vec<(String, usize)> = counts.into_iter().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1));
        v.truncate(10);
        v.into_iter().map(|(n, _)| n).collect()
    };
    let port_has_other = filter_services.iter().any(|s| s == "__other__");

    hosts.iter()
        .filter(|h| h.alive)
        .filter(|h| {
            if severity_filter.is_empty() { return true; }
            let crit_ports = [22, 23, 135, 139, 445, 3389, 3306, 5432, 6379, 27017];
            let has_crit = h.ports.iter().any(|p| crit_ports.contains(&p.port));
            let sev = if has_crit {
                NodeSeverity::High
            } else if h.ports.is_empty() {
                NodeSeverity::Low
            } else {
                NodeSeverity::Medium
            };
            severity_filter.contains(&sev)
        })
        .filter(|h| {
            if os_filter.is_empty() { return true; }
            match h.os_guess {
                Some(ref os) => os_filter.contains(os),
                None => false,
            }
        })
        .filter(|h| {
            if !port_filter_enabled || filter_services.is_empty() { return true; }
            h.ports.iter().any(|p| {
                if filter_services.contains(&p.service_name) { return true; }
                port_has_other && !top_service_names.contains(&p.service_name)
            })
        })
        .filter(|h| { !only_cve || h.ports.iter().any(|p| !p.cves.is_empty()) })
        .filter(|h| {
            if query.is_empty() { return true; }
            let ip_match = h.ip.to_string().to_lowercase().contains(&query);
            let host_match = h.hostname.as_ref()
                .map(|hn| hn.to_lowercase().contains(&query))
                .unwrap_or(false);
            ip_match || host_match
        })
        .cloned()
        .collect()
}
