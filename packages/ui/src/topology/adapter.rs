use crate::models::HostInfo;
use crate::topology::graph::{severity_for_host, EdgeKind, NodeSeverity};
use crate::topology::layout::{node_radius, GraphLayout, LayoutEdge, LayoutNode};
use crate::topology::state::SizeMode;
use aplomado_types::{TopologyEdgeKind, TopologyGraph, TopologyNodeKind};
use std::collections::HashMap;
use std::net::IpAddr;

/// Build a [`GraphLayout`] directly from a hybrid [`TopologyGraph`].
///
/// Pure, deterministic, no I/O, no Dioxus Signals.  Host info is used
/// to enrich host nodes with severity, port count, and hostname.
pub fn build_hybrid_layout(
    hybrid: &TopologyGraph,
    hosts: &[HostInfo],
    width: f64,
    height: f64,
    size_mode: SizeMode,
) -> GraphLayout {
    let host_by_ip: HashMap<IpAddr, &HostInfo> = hosts
        .iter()
        .filter(|h| h.alive)
        .map(|h| (h.ip, h))
        .collect();

    let mut nodes = Vec::with_capacity(hybrid.nodes.len());
    // Maps TopologyNode.id → LayoutNode.id
    let mut node_id_map: HashMap<String, String> = HashMap::with_capacity(hybrid.nodes.len());

    for tn in &hybrid.nodes {
        let lid = layout_id_for_node(tn);
        node_id_map.insert(tn.id.clone(), lid.clone());

        let (severity, port_count, subnet, depth) = match tn.kind {
            TopologyNodeKind::Host => {
                if let Some(ip) = tn.ip {
                    if let Some(host) = host_by_ip.get(&ip) {
                        let sev = severity_for_host(host);
                        let sub = ip_to_subnet_short(&ip);
                        (sev, host.ports.len() as u32, sub, 0)
                    } else {
                        (NodeSeverity::Unknown, 0, ip_to_subnet_short(&ip), 0)
                    }
                } else {
                    (NodeSeverity::Unknown, 0, String::new(), 0)
                }
            }
            TopologyNodeKind::RouteHop => {
                if let Some(ip) = tn.ip {
                    (NodeSeverity::Unknown, 0, ip_to_subnet_short(&ip), 0)
                } else {
                    (NodeSeverity::Unknown, 0, String::new(), 0)
                }
            }
            TopologyNodeKind::LogicalSubnet => (NodeSeverity::Unknown, 0, String::new(), 0),
        };

        nodes.push(LayoutNode {
            id: lid,
            x: width / 2.0,
            y: height / 2.0,
            vx: 0.0,
            vy: 0.0,
            label: tn.label.clone(),
            severity: severity.clone(),
            radius: node_radius_for_kind(&tn.kind, severity, port_count, size_mode),
            depth,
            cluster_id: None,
            port_count,
            subnet,
            kind: tn.kind.clone(),
        });
    }

    let mut edges = Vec::with_capacity(hybrid.edges.len());
    for te in &hybrid.edges {
        let Some(from) = node_id_map.get(&te.source) else {
            continue;
        };
        let Some(to) = node_id_map.get(&te.target) else {
            continue;
        };
        let (kind, weight) = match te.kind {
            TopologyEdgeKind::ConfirmedRoute => (EdgeKind::Route, 1.0),
            TopologyEdgeKind::LogicalSubnetMembership => (EdgeKind::LogicalSubnetMembership, 0.5),
        };
        edges.push(LayoutEdge {
            from: from.clone(),
            to: to.clone(),
            weight,
            kind,
        });
    }

    GraphLayout {
        nodes,
        edges,
        width,
        height,
    }
}

/// Produce the `LayoutNode.id` string for a hybrid node.
///
/// Host and route-hop nodes use their IP string (backward-compatible with
/// existing selection/hover/tooltip look-ups).  Subnet nodes use their
/// full `TopologyNode.id` (e.g. `"subnet:ipv4:192.168.1.0/24"`).
fn layout_id_for_node(tn: &aplomado_types::TopologyNode) -> String {
    match tn.ip {
        Some(ip) => ip.to_string(),
        None => tn.id.clone(),
    }
}

/// Node radius for a given kind.
///
/// Host nodes use the existing severity + port-count formula.
/// Route hops get a fixed small circle.  Subnet nodes get tiny.
fn node_radius_for_kind(
    kind: &TopologyNodeKind,
    severity: NodeSeverity,
    port_count: u32,
    size_mode: SizeMode,
) -> f64 {
    match kind {
        TopologyNodeKind::Host => node_radius(&severity, port_count, size_mode),
        TopologyNodeKind::RouteHop => 6.0,
        TopologyNodeKind::LogicalSubnet => 4.0,
    }
}

/// Short /24 subnet prefix (e.g. `"192.168.1"` for `192.168.1.10`).
fn ip_to_subnet_short(ip: &IpAddr) -> String {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::graph::NodeSeverity;
    use crate::topology::state::LayoutType;
    use aplomado_core::topology::build_hybrid_topology;
    use aplomado_types::Hop;

    fn make_host(ip: &str, alive: bool, route: Vec<(u32, &str, Option<f32>)>) -> HostInfo {
        HostInfo {
            ip: ip.parse().unwrap(),
            hostname: None,
            ttl: None,
            os_guess: None,
            ports: vec![],
            alive,
            route: route
                .into_iter()
                .map(|(hop, ip, rtt)| Hop {
                    hop,
                    ip: ip.parse().unwrap(),
                    rtt_ms: rtt,
                })
                .collect(),
        }
    }

    #[test]
    fn empty_hybrid_graph_produces_empty_layout() {
        let hybrid = TopologyGraph {
            nodes: vec![],
            edges: vec![],
        };
        let layout = build_hybrid_layout(&hybrid, &[], 900.0, 600.0, SizeMode::Auto);
        assert!(layout.nodes.is_empty());
        assert!(layout.edges.is_empty());
    }

    #[test]
    fn single_alive_host_without_route() {
        let hosts = vec![make_host("192.168.1.10", true, vec![])];
        let hybrid = build_hybrid_topology(&hosts);
        let layout = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);

        let host_nodes: Vec<_> = layout
            .nodes
            .iter()
            .filter(|n| n.port_count == 0 && n.radius >= 6.0)
            .collect();
        assert_eq!(host_nodes.len(), 1, "one host node");
        assert_eq!(host_nodes[0].id, "192.168.1.10");

        let subnet_nodes: Vec<_> = layout.nodes.iter().filter(|n| n.radius < 6.0).collect();
        assert_eq!(subnet_nodes.len(), 1, "one subnet node");
        assert!(subnet_nodes[0].id.contains("subnet:"));

        let membership_edges: Vec<_> = layout
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::LogicalSubnetMembership)
            .collect();
        assert_eq!(membership_edges.len(), 1, "one membership edge");
    }

    #[test]
    fn two_hosts_same_subnet() {
        let hosts = vec![
            make_host("192.168.1.10", true, vec![]),
            make_host("192.168.1.20", true, vec![]),
        ];
        let hybrid = build_hybrid_topology(&hosts);
        let layout = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);

        let host_nodes: Vec<_> = layout.nodes.iter().filter(|n| n.radius >= 6.0).collect();
        assert_eq!(host_nodes.len(), 2);

        let subnet_nodes: Vec<_> = layout.nodes.iter().filter(|n| n.radius < 6.0).collect();
        assert_eq!(subnet_nodes.len(), 1);

        let membership_edges: Vec<_> = layout
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::LogicalSubnetMembership)
            .collect();
        assert_eq!(membership_edges.len(), 2);
    }

    #[test]
    fn host_with_three_hop_route() {
        let hosts = vec![make_host(
            "10.0.0.10",
            true,
            vec![
                (1, "10.0.0.1", Some(1.0)),
                (2, "10.0.0.2", Some(2.0)),
                (3, "10.0.0.3", Some(3.0)),
            ],
        )];
        let hybrid = build_hybrid_topology(&hosts);
        let layout = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);

        let route_edges = layout
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Route)
            .collect::<Vec<_>>();
        assert_eq!(route_edges.len(), 3, "three route edges for 3-hop path");

        let hop_ids: Vec<&str> = vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"];
        for hop_id in &hop_ids {
            assert!(
                layout.nodes.iter().any(|n| n.id == *hop_id),
                "hop node {hop_id} should exist"
            );
        }

        let host_node = layout.nodes.iter().find(|n| n.id == "10.0.0.10");
        assert!(host_node.is_some(), "host node should exist");
    }

    #[test]
    fn no_alive_hosts_produces_empty_layout() {
        let hosts = vec![make_host("192.168.1.10", false, vec![])];
        let hybrid = build_hybrid_topology(&hosts);
        let layout = build_hybrid_layout(&hybrid, &[], 900.0, 600.0, SizeMode::Auto);
        assert!(layout.nodes.is_empty());
        assert!(layout.edges.is_empty());
    }

    #[test]
    fn route_hop_nodes_have_fixed_small_radius() {
        let hosts = vec![make_host(
            "10.0.0.10",
            true,
            vec![(1, "10.0.0.1", Some(1.0)), (2, "10.0.0.2", Some(2.0))],
        )];
        let hybrid = build_hybrid_topology(&hosts);
        let layout = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);

        let hop = layout.nodes.iter().find(|n| n.id == "10.0.0.1").unwrap();
        assert_eq!(hop.radius, 6.0);
        assert_eq!(hop.port_count, 0);
        assert_eq!(hop.severity, NodeSeverity::Unknown);
    }

    #[test]
    fn subnet_nodes_are_tiny() {
        let hosts = vec![make_host("192.168.1.10", true, vec![])];
        let hybrid = build_hybrid_topology(&hosts);
        let layout = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);

        let subnet = layout.nodes.iter().find(|n| n.radius < 6.0).unwrap();
        assert_eq!(subnet.radius, 4.0);
        assert_eq!(subnet.port_count, 0);
        assert_eq!(subnet.severity, NodeSeverity::Unknown);
    }

    #[test]
    fn layout_is_deterministic() {
        let hosts = vec![make_host(
            "10.0.0.20",
            true,
            vec![(1, "10.0.0.1", Some(1.0))],
        )];
        let hybrid = build_hybrid_topology(&hosts);

        let a = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);
        let b = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);

        assert_eq!(a.nodes.len(), b.nodes.len());
        assert_eq!(a.edges.len(), b.edges.len());
        for (na, nb) in a.nodes.iter().zip(b.nodes.iter()) {
            assert_eq!(na.id, nb.id);
            assert_eq!(na.radius, nb.radius);
            assert_eq!(na.severity, nb.severity);
        }
    }

    #[test]
    fn dead_hosts_in_host_list_dont_affect_layout() {
        let hosts = vec![make_host("192.168.1.10", true, vec![])];
        let hybrid = build_hybrid_topology(&hosts);
        // Extra alive host that isn't in the hybrid graph
        let extra_hosts = vec![
            HostInfo {
                ip: "192.168.1.10".parse().unwrap(),
                hostname: None,
                ttl: None,
                os_guess: None,
                ports: vec![],
                alive: true,
                route: vec![],
            },
            HostInfo {
                ip: "10.0.0.1".parse().unwrap(),
                hostname: None,
                ttl: None,
                os_guess: None,
                ports: vec![],
                alive: true,
                route: vec![],
            },
        ];
        let layout = build_hybrid_layout(&hybrid, &extra_hosts, 900.0, 600.0, SizeMode::Auto);

        // Should still only have one host node + one subnet node
        let host_count = layout.nodes.iter().filter(|n| n.radius >= 6.0).count();
        assert_eq!(host_count, 1);
    }

    // -----------------------------------------------------------------------
    // Regression: 51-host real-world scenario
    // -----------------------------------------------------------------------

    fn make_single_route_host(ip: &str, alive: bool) -> HostInfo {
        let parts: Vec<&str> = ip.split('.').collect();
        // Each host gets a unique route-hop at the gateway 10.2.50.1
        let gw_ip = "10.2.50.1".to_string();
        let hop_n: u32 = parts.last().and_then(|s| s.parse().ok()).unwrap_or(1);
        HostInfo {
            ip: ip.parse().unwrap(),
            hostname: None,
            ttl: None,
            os_guess: None,
            ports: vec![],
            alive,
            route: vec![Hop {
                hop: 1,
                ip: gw_ip.parse().unwrap(),
                rtt_ms: Some(hop_n as f32),
            }],
        }
    }

    fn make_51_hosts() -> Vec<HostInfo> {
        let mut hosts = Vec::with_capacity(254);
        // First 51 = alive, rest = dead
        for i in 1..=254 {
            let ip = format!("10.2.50.{i}");
            let alive = i <= 51;
            hosts.push(make_single_route_host(&ip, alive));
        }
        // Filter to exactly 51 alive
        let alive: Vec<HostInfo> = hosts.into_iter().filter(|h| h.alive).collect();
        assert_eq!(alive.len(), 51, "must have exactly 51 alive hosts");
        alive
    }

    #[test]
    fn regression_51_hosts_force_layout() {
        let hosts = make_51_hosts();

        // 1. Build topology
        let hybrid = build_hybrid_topology(&hosts);
        let host_count = hybrid
            .nodes
            .iter()
            .filter(|n| n.kind == TopologyNodeKind::Host)
            .count();
        assert_eq!(host_count, 51, "topology must contain 51 host nodes");

        // 2. Build layout
        let mut layout = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);
        assert_eq!(
            layout.nodes.len(),
            hybrid.nodes.len(),
            "LayoutNode count must match TopologyGraph node count"
        );

        // 3. Check pre-compute positions (from build_hybrid_layout)
        for (i, node) in layout.nodes.iter().enumerate() {
            assert!(
                node.x.is_finite(),
                "pre-compute node[{i}] {} x={} is not finite",
                node.id,
                node.x
            );
            assert!(
                node.y.is_finite(),
                "pre-compute node[{i}] {} y={} is not finite",
                node.id,
                node.y
            );
        }
        // Pre-compute: all nodes start at center
        let center_count = layout
            .nodes
            .iter()
            .filter(|n| n.x == 450.0 && n.y == 300.0)
            .count();
        assert_eq!(
            center_count,
            layout.nodes.len(),
            "all nodes must start at center pre-compute, got {center_count}/{}",
            layout.nodes.len()
        );

        // 4. Compute force layout
        layout.compute_with_type(150, LayoutType::Force, SizeMode::Auto);

        // 5. Check POST-compute positions
        let n = layout.nodes.len();
        assert!(n > 0, "layout must have nodes");

        for (i, node) in layout.nodes.iter().enumerate() {
            assert!(
                node.x.is_finite(),
                "post-compute node[{i}] {} x={} is not finite",
                node.id,
                node.x
            );
            assert!(
                node.y.is_finite(),
                "post-compute node[{i}] {} y={} is not finite",
                node.id,
                node.y
            );
            assert!(
                node.radius > 0.0,
                "post-compute node[{i}] {} radius=0",
                node.id
            );
        }

        // Count unique positions
        let positions: Vec<(i64, i64)> = layout
            .nodes
            .iter()
            .map(|n| (n.x.round() as i64, n.y.round() as i64))
            .collect();
        let unique_count = {
            let mut set = std::collections::BTreeSet::new();
            for p in &positions {
                set.insert(p);
            }
            set.len()
        };
        assert!(
            unique_count > 1,
            "nodes must have more than 1 unique position, got {unique_count}"
        );
        // At least 90% of nodes must have unique positions
        let unique_ratio = unique_count as f64 / n as f64;
        assert!(
            unique_ratio >= 0.9,
            "at least 90% of nodes must have unique positions, got {unique_ratio:.2} ({unique_count}/{n})"
        );

        // 5. Bounds check
        let min_x = layout
            .nodes
            .iter()
            .map(|n| n.x)
            .fold(f64::INFINITY, f64::min);
        let max_x = layout
            .nodes
            .iter()
            .map(|n| n.x)
            .fold(f64::NEG_INFINITY, f64::max);
        let min_y = layout
            .nodes
            .iter()
            .map(|n| n.y)
            .fold(f64::INFINITY, f64::min);
        let max_y = layout
            .nodes
            .iter()
            .map(|n| n.y)
            .fold(f64::NEG_INFINITY, f64::max);

        assert!(min_x.is_finite(), "min_x must be finite");
        assert!(max_x.is_finite(), "max_x must be finite");
        assert!(min_y.is_finite(), "min_y must be finite");
        assert!(max_y.is_finite(), "max_y must be finite");

        let bounds_width = max_x - min_x;
        let bounds_height = max_y - min_y;
        assert!(
            bounds_width > 0.0,
            "bounds width must be > 0, got {bounds_width}"
        );
        assert!(
            bounds_height > 0.0,
            "bounds height must be > 0, got {bounds_height}"
        );

        // All host nodes should be within canvas bounds (with some margin)
        let canvas_w = 900.0;
        let canvas_h = 600.0;
        let margin = 100.0;
        for (i, node) in layout.nodes.iter().enumerate() {
            assert!(
                node.x >= -margin && node.x <= canvas_w + margin,
                "node[{i}] {} x={} outside canvas [-{margin}, {}+{margin}]",
                node.id,
                node.x,
                canvas_w
            );
            assert!(
                node.y >= -margin && node.y <= canvas_h + margin,
                "node[{i}] {} y={} outside canvas [-{margin}, {}+{margin}]",
                node.id,
                node.y,
                canvas_h
            );
        }
    }

    #[test]
    fn regression_51_hosts_circular_layout() {
        let hosts = make_51_hosts();
        let hybrid = build_hybrid_topology(&hosts);
        let mut layout = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);
        layout.compute_with_type(0, LayoutType::Circular, SizeMode::Auto);

        let n = layout.nodes.len();
        assert!(n > 0);
        for node in &layout.nodes {
            assert!(node.x.is_finite());
            assert!(node.y.is_finite());
        }

        let positions: Vec<(i64, i64)> = layout
            .nodes
            .iter()
            .map(|n| (n.x.round() as i64, n.y.round() as i64))
            .collect();
        let mut set = std::collections::BTreeSet::new();
        for p in &positions {
            set.insert(p);
        }
        assert!(set.len() > 1, "circular layout must have unique positions");
        let ratio = set.len() as f64 / n as f64;
        assert!(
            ratio >= 0.9,
            "circular: at least 90% unique, got {ratio:.2}"
        );
    }

    #[test]
    fn regression_51_hosts_hierarchical_layout() {
        let hosts = make_51_hosts();
        let hybrid = build_hybrid_topology(&hosts);
        let mut layout = build_hybrid_layout(&hybrid, &hosts, 900.0, 600.0, SizeMode::Auto);
        layout.compute_with_type(0, LayoutType::Hierarchical, SizeMode::Auto);

        let n = layout.nodes.len();
        assert!(n > 0);
        for node in &layout.nodes {
            assert!(node.x.is_finite());
            assert!(node.y.is_finite());
        }

        let positions: Vec<(i64, i64)> = layout
            .nodes
            .iter()
            .map(|n| (n.x.round() as i64, n.y.round() as i64))
            .collect();
        let mut set = std::collections::BTreeSet::new();
        for p in &positions {
            set.insert(p);
        }
        assert!(
            set.len() > 1,
            "hierarchical layout must have unique positions"
        );
        let ratio = set.len() as f64 / n as f64;
        assert!(
            ratio >= 0.9,
            "hierarchical: at least 90% unique, got {ratio:.2}"
        );
    }
}
