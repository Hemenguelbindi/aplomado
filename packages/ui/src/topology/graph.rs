use crate::models::HostInfo;
use petgraph::stable_graph::{NodeIndex, StableGraph};
use petgraph::Undirected;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeSeverity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    Route,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EdgeInfo {
    pub weight: f32,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostNode {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub open_ports: Vec<u16>,
    pub alive: bool,
    pub severity: NodeSeverity,
    pub depth: u32,
    pub subnet: String,
}

pub type TopologyGraph = StableGraph<HostNode, EdgeInfo, Undirected>;

/// Построить топологию по route (traceroute).
/// Рёбра = последовательные hop'ы от источника к цели.
pub fn build_topology(hosts: &[HostInfo]) -> TopologyGraph {
    let mut graph: TopologyGraph = StableGraph::with_capacity(0, 0);
    let mut node_map: HashMap<IpAddr, NodeIndex> = HashMap::new();

    for host in hosts {
        let mut hops = host.route.clone();
        hops.sort_by_key(|a| a.hop);

        for window in hops.windows(2) {
            let prev = window[0].ip;
            let next = window[1].ip;

            let prev_idx = get_or_create_node(&mut graph, &mut node_map, prev, host, window[0].hop);
            let next_idx = get_or_create_node(&mut graph, &mut node_map, next, host, window[1].hop);

            if !graph.contains_edge(prev_idx, next_idx) {
                graph.add_edge(
                    prev_idx,
                    next_idx,
                    EdgeInfo {
                        weight: 1.0,
                        kind: EdgeKind::Route,
                    },
                );
            }
        }

        let target_idx = get_or_create_node(&mut graph, &mut node_map, host.ip, host, 0);
        if let Some(last_hop) = hops.last() {
            let last_idx =
                get_or_create_node(&mut graph, &mut node_map, last_hop.ip, host, last_hop.hop);
            if !graph.contains_edge(last_idx, target_idx) {
                graph.add_edge(
                    last_idx,
                    target_idx,
                    EdgeInfo {
                        weight: 1.0,
                        kind: EdgeKind::Route,
                    },
                );
            }
        }
    }

    graph
}

fn get_or_create_node(
    graph: &mut TopologyGraph,
    node_map: &mut HashMap<IpAddr, NodeIndex>,
    ip: IpAddr,
    host: &HostInfo,
    depth: u32,
) -> NodeIndex {
    if let Some(&idx) = node_map.get(&ip) {
        // Update existing node with richer data from the current host
        if depth < graph[idx].depth {
            graph[idx].depth = depth;
        }
        if graph[idx].hostname.is_none() {
            graph[idx].hostname = host.hostname.clone();
        }
        if graph[idx].os_guess.is_none() {
            graph[idx].os_guess = host.os_guess.clone();
        }
        if graph[idx].open_ports.is_empty() {
            graph[idx].open_ports = host.ports.iter().map(|p| p.port).collect();
        }
        idx
    } else {
        let severity = severity_for_host(host);
        let ports: Vec<u16> = host.ports.iter().map(|p| p.port).collect();
        let idx = graph.add_node(HostNode {
            ip,
            hostname: host.hostname.clone(),
            os_guess: host.os_guess.clone(),
            open_ports: ports,
            alive: host.alive,
            severity,
            depth,
            subnet: ip_to_subnet(&ip),
        });
        node_map.insert(ip, idx);
        idx
    }
}

/// Extract /24 subnet prefix from an IP address.
fn ip_to_subnet(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}", s[0], s[1], s[2])
        }
    }
}

pub fn severity_for_host(host: &HostInfo) -> NodeSeverity {
    let critical = [22, 23, 135, 139, 445, 3389, 3306, 5432, 6379, 27017];
    let has_critical = host.ports.iter().any(|p| critical.contains(&p.port));
    if !host.alive {
        NodeSeverity::Unknown
    } else if has_critical {
        NodeSeverity::High
    } else if host.ports.is_empty() {
        NodeSeverity::Low
    } else {
        NodeSeverity::Medium
    }
}
