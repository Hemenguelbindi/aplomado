//! Pure hybrid topology builder.
//!
//! Builds a semantic [`TopologyGraph`] from [`aplomado_types::HostInfo`]
//! slices.  The graph contains host nodes, route-hop nodes, logical subnet
//! nodes, confirmed-route edges, and logical-subnet-membership edges.
//!
//! # Determinism
//!
//! The builder is a pure function: identical input produces identical output.
//! All internal collections use `BTreeMap`/`BTreeSet` so iteration order is
//! stable.  Node IDs, edge endpoints, subnet groupings – everything is
//! derived deterministically from the input.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use aplomado_types::{
    Hop, HostInfo, TopologyEdge, TopologyEdgeKind, TopologyGraph, TopologyNode, TopologyNodeKind,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a hybrid topology graph from scanned hosts.
///
/// ## Semantics
///
/// *   **Host nodes** – one per unique alive host IP.
/// *   **Route-hop nodes** – one per unique non-host IP appearing in any
///     host's `route` field.  If a route hop IP is also a host IP the node
///     kind is `Host` (host takes priority).
/// *   **Logical subnet nodes** – one per /24 IPv4 or /64 IPv6 prefix that
///     contains at least one host or hop.
/// *   **ConfirmedRoute edges** – between consecutive route hops and from
///     the last hop to the target host (if different).  No self-loops.
/// *   **LogicalSubnetMembership edges** – from every host and hop to its
///     /24 or /64 subnet group.
///
/// ## Route semantics
///
/// `HostInfo.route` is a traceroute result.  Hops are ordered 1..N.  The
/// last hop may or may not equal the target host IP.  Edges are created for
/// every consecutive pair of hops.  If the last hop differs from the target
/// host IP an additional edge is added; otherwise no self-loop is created.
pub fn build_hybrid_topology(hosts: &[HostInfo]) -> TopologyGraph {
    let alive: Vec<&HostInfo> = hosts.iter().filter(|h| h.alive).collect();
    if alive.is_empty() {
        return TopologyGraph {
            nodes: vec![],
            edges: vec![],
        };
    }

    // Phase 1 — deduplicate hosts by IP
    let mut merged: BTreeMap<IpAddr, MergedHost> = BTreeMap::new();
    for h in &alive {
        merged
            .entry(h.ip)
            .and_modify(|m| m.merge(h))
            .or_insert_with(|| MergedHost::from(*h));
    }

    let host_ips: BTreeSet<IpAddr> = merged.keys().copied().collect();

    // Phase 2 — create host nodes
    let mut node_map: BTreeMap<String, TopologyNode> = BTreeMap::new();
    for (ip, mh) in &merged {
        let nid = host_node_id(ip);
        let sid = ip_to_subnet_id(ip);
        node_map.insert(
            nid.clone(),
            TopologyNode {
                id: nid,
                kind: TopologyNodeKind::Host,
                ip: Some(*ip),
                label: mh.hostname.clone().unwrap_or_else(|| ip.to_string()),
                group_id: Some(sid),
            },
        );
    }

    // Phase 3 — process routes
    let mut edge_set: BTreeSet<(String, String, TopologyEdgeKind)> = BTreeSet::new();

    for (ip, mh) in &merged {
        let host_id = host_node_id(ip);
        let rt = &mh.route;

        if rt.is_empty() {
            continue;
        }

        // edges between consecutive hops
        for pair in rt.windows(2) {
            let a_id = ip_to_node_id(&pair[0].ip, &host_ips);
            let b_id = ip_to_node_id(&pair[1].ip, &host_ips);

            ensure_hop_node(&mut node_map, &pair[0].ip, &host_ips);
            ensure_hop_node(&mut node_map, &pair[1].ip, &host_ips);

            if a_id != b_id {
                edge_set.insert((a_id, b_id, TopologyEdgeKind::ConfirmedRoute));
            }
        }

        // edge from last hop to target (if different)
        if let Some(last) = rt.last() {
            ensure_hop_node(&mut node_map, &last.ip, &host_ips);
            let last_id = ip_to_node_id(&last.ip, &host_ips);
            if last_id != host_id {
                edge_set.insert((last_id, host_id, TopologyEdgeKind::ConfirmedRoute));
            }
        }
    }

    // Phase 4 — create subnet nodes and membership edges
    let mut subnet_nodes: BTreeMap<String, TopologyNode> = BTreeMap::new();
    let node_ids: Vec<String> = node_map.keys().cloned().collect();
    for nid in &node_ids {
        if let Some(node) = node_map.get(nid) {
            if let Some(sid) = &node.group_id {
                subnet_nodes
                    .entry(sid.clone())
                    .or_insert_with(|| TopologyNode {
                        id: sid.clone(),
                        kind: TopologyNodeKind::LogicalSubnet,
                        ip: None,
                        label: subnet_label(sid),
                        group_id: None,
                    });
                edge_set.insert((
                    nid.clone(),
                    sid.clone(),
                    TopologyEdgeKind::LogicalSubnetMembership,
                ));
            }
        }
    }

    node_map.extend(subnet_nodes);

    TopologyGraph {
        nodes: node_map.into_values().collect(),
        edges: edge_set
            .into_iter()
            .map(|(s, t, k)| TopologyEdge {
                source: s,
                target: t,
                kind: k,
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn host_node_id(ip: &IpAddr) -> String {
    let family = ip_family(ip);
    format!("host:{family}:{ip}")
}

fn hop_node_id(ip: &IpAddr) -> String {
    let family = ip_family(ip);
    format!("hop:{family}:{ip}")
}

fn ip_to_subnet_id(ip: &IpAddr) -> String {
    let family = ip_family(ip);
    let prefix = subnet_prefix(ip);
    format!("subnet:{family}:{prefix}")
}

fn ip_family(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

fn subnet_prefix(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:04x}:{:04x}:{:04x}:{:04x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

fn subnet_label(subnet_id: &str) -> String {
    // subnet_id format: "subnet:ipv4:1.2.3.0/24"
    subnet_id
        .strip_prefix("subnet:ipv4:")
        .or_else(|| subnet_id.strip_prefix("subnet:ipv6:"))
        .unwrap_or(subnet_id)
        .to_string()
}

fn ip_to_node_id(ip: &IpAddr, host_ips: &BTreeSet<IpAddr>) -> String {
    if host_ips.contains(ip) {
        host_node_id(ip)
    } else {
        hop_node_id(ip)
    }
}

fn ensure_hop_node(
    node_map: &mut BTreeMap<String, TopologyNode>,
    ip: &IpAddr,
    host_ips: &BTreeSet<IpAddr>,
) {
    if host_ips.contains(ip) {
        return;
    }
    let nid = hop_node_id(ip);
    if !node_map.contains_key(&nid) {
        let sid = ip_to_subnet_id(ip);
        node_map.insert(
            nid.clone(),
            TopologyNode {
                id: nid,
                kind: TopologyNodeKind::RouteHop,
                ip: Some(*ip),
                label: ip.to_string(),
                group_id: Some(sid),
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Merged host (deduplication support)
// ---------------------------------------------------------------------------

/// Intermediate representation for deduplicating hosts that share an IP.
struct MergedHost {
    hostname: Option<String>,
    route: Vec<Hop>,
}

impl From<&HostInfo> for MergedHost {
    fn from(h: &HostInfo) -> Self {
        Self {
            hostname: h.hostname.clone(),
            route: h.route.clone(),
        }
    }
}

impl MergedHost {
    /// Merge a duplicate `HostInfo` into this record.
    ///
    /// Rules (deterministic, order-independent):
    /// *   `alive` — OR (handled before this point by the alive filter).
    /// *   `hostname` — keep existing if present; otherwise take the new one.
    /// *   `route` — keep the longer route (more hops = more informative).
    fn merge(&mut self, other: &HostInfo) {
        if self.hostname.is_none() {
            self.hostname = other.hostname.clone();
        }
        if other.route.len() > self.route.len() {
            self.route = other.route.clone();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aplomado_types::{Hop, HostInfo};

    // ---- helpers ---------------------------------------------------------

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

    fn host_node_ids(g: &TopologyGraph) -> Vec<String> {
        g.nodes
            .iter()
            .filter(|n| n.kind == TopologyNodeKind::Host)
            .map(|n| n.id.clone())
            .collect()
    }

    fn hop_node_ids(g: &TopologyGraph) -> Vec<String> {
        g.nodes
            .iter()
            .filter(|n| n.kind == TopologyNodeKind::RouteHop)
            .map(|n| n.id.clone())
            .collect()
    }

    fn subnet_node_ids(g: &TopologyGraph) -> Vec<String> {
        g.nodes
            .iter()
            .filter(|n| n.kind == TopologyNodeKind::LogicalSubnet)
            .map(|n| n.id.clone())
            .collect()
    }

    fn confirmed_route_edges(g: &TopologyGraph) -> Vec<(String, String)> {
        let mut pairs: Vec<_> = g
            .edges
            .iter()
            .filter(|e| e.kind == TopologyEdgeKind::ConfirmedRoute)
            .map(|e| (e.source.clone(), e.target.clone()))
            .collect();
        pairs.sort();
        pairs
    }

    // ---- 1. single_alive_host_without_route -------------------------------

    #[test]
    fn single_alive_host_without_route() {
        let hosts = vec![make_host("192.168.1.10", true, vec![])];
        let g = build_hybrid_topology(&hosts);

        assert_eq!(
            host_node_ids(&g),
            vec!["host:ipv4:192.168.1.10"],
            "one host node"
        );
        assert!(confirmed_route_edges(&g).is_empty(), "no route edges");
    }

    // ---- 2. two_hosts_same_ipv4_subnet ------------------------------------

    #[test]
    fn two_hosts_same_ipv4_subnet() {
        let hosts = vec![
            make_host("192.168.1.10", true, vec![]),
            make_host("192.168.1.20", true, vec![]),
        ];
        let g = build_hybrid_topology(&hosts);

        let hosts = host_node_ids(&g);
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains(&"host:ipv4:192.168.1.10".into()));
        assert!(hosts.contains(&"host:ipv4:192.168.1.20".into()));

        let subnets = subnet_node_ids(&g);
        assert_eq!(subnets, vec!["subnet:ipv4:192.168.1.0/24"]);

        assert!(confirmed_route_edges(&g).is_empty());
    }

    // ---- 3. hosts_from_two_ipv4_subnets -----------------------------------

    #[test]
    fn hosts_from_two_ipv4_subnets() {
        let hosts = vec![
            make_host("192.168.1.10", true, vec![]),
            make_host("192.168.2.10", true, vec![]),
        ];
        let g = build_hybrid_topology(&hosts);

        let subnets = subnet_node_ids(&g);
        assert_eq!(subnets.len(), 2);
        assert!(subnets.contains(&"subnet:ipv4:192.168.1.0/24".into()));
        assert!(subnets.contains(&"subnet:ipv4:192.168.2.0/24".into()));
    }

    // ---- 4. one_host_with_three_hop_route ---------------------------------

    #[test]
    fn one_host_with_three_hop_route() {
        let hosts = vec![make_host(
            "10.0.0.10",
            true,
            vec![
                (1, "10.0.0.1", Some(1.0)),
                (2, "10.0.0.2", Some(2.0)),
                (3, "10.0.0.3", Some(3.0)),
            ],
        )];
        let g = build_hybrid_topology(&hosts);

        assert!(host_node_ids(&g).contains(&"host:ipv4:10.0.0.10".into()));

        let hops = hop_node_ids(&g);
        assert_eq!(hops.len(), 3);
        assert!(hops.contains(&"hop:ipv4:10.0.0.1".into()));
        assert!(hops.contains(&"hop:ipv4:10.0.0.2".into()));
        assert!(hops.contains(&"hop:ipv4:10.0.0.3".into()));

        let edges = confirmed_route_edges(&g);
        assert!(edges.contains(&("hop:ipv4:10.0.0.1".into(), "hop:ipv4:10.0.0.2".into())));
        assert!(edges.contains(&("hop:ipv4:10.0.0.2".into(), "hop:ipv4:10.0.0.3".into())));
        assert!(edges.contains(&("hop:ipv4:10.0.0.3".into(), "host:ipv4:10.0.0.10".into())));
        assert_eq!(edges.len(), 3);
    }

    // ---- 5. route_already_contains_target ---------------------------------

    #[test]
    fn route_already_contains_target() {
        let hosts = vec![make_host(
            "10.0.0.10",
            true,
            vec![
                (1, "10.0.0.1", Some(1.0)),
                (2, "10.0.0.2", Some(2.0)),
                (3, "10.0.0.10", Some(3.0)),
            ],
        )];
        let g = build_hybrid_topology(&hosts);

        // target 10.0.0.10 is a Host node, not duplicated as RouteHop
        let hops = hop_node_ids(&g);
        assert_eq!(hops, vec!["hop:ipv4:10.0.0.1", "hop:ipv4:10.0.0.2"]);

        let edges = confirmed_route_edges(&g);
        assert!(edges.contains(&("hop:ipv4:10.0.0.1".into(), "hop:ipv4:10.0.0.2".into())));
        assert!(edges.contains(&("hop:ipv4:10.0.0.2".into(), "host:ipv4:10.0.0.10".into())));
        // no self-loop
        assert!(!edges.contains(&("host:ipv4:10.0.0.10".into(), "host:ipv4:10.0.0.10".into())));
        assert_eq!(edges.len(), 2);
    }

    // ---- 6. two_hosts_with_shared_hops ------------------------------------

    #[test]
    fn two_hosts_with_shared_hops() {
        let hosts = vec![
            make_host(
                "10.0.0.10",
                true,
                vec![
                    (1, "10.0.0.1", Some(1.0)),
                    (2, "10.0.0.2", Some(2.0)),
                    (3, "10.0.0.3", Some(3.0)),
                ],
            ),
            make_host(
                "10.0.0.20",
                true,
                vec![
                    (1, "10.0.0.1", Some(1.0)),
                    (2, "10.0.0.2", Some(2.0)),
                    (3, "10.0.0.4", Some(4.0)),
                ],
            ),
        ];
        let g = build_hybrid_topology(&hosts);

        // Shared: A(10.0.0.1), B(10.0.0.2); unique: C(10.0.0.3), D(10.0.0.4)
        let hops = hop_node_ids(&g);
        assert_eq!(hops.len(), 4);
        assert!(hops.contains(&"hop:ipv4:10.0.0.1".into()));
        assert!(hops.contains(&"hop:ipv4:10.0.0.2".into()));
        assert!(hops.contains(&"hop:ipv4:10.0.0.3".into()));
        assert!(hops.contains(&"hop:ipv4:10.0.0.4".into()));

        let edges = confirmed_route_edges(&g);
        // A→B appears once
        assert!(edges.contains(&("hop:ipv4:10.0.0.1".into(), "hop:ipv4:10.0.0.2".into())));
        // B→C (host 1)
        assert!(edges.contains(&("hop:ipv4:10.0.0.2".into(), "hop:ipv4:10.0.0.3".into())));
        // C→H1
        assert!(edges.contains(&("hop:ipv4:10.0.0.3".into(), "host:ipv4:10.0.0.10".into())));
        // B→D (host 2)
        assert!(edges.contains(&("hop:ipv4:10.0.0.2".into(), "hop:ipv4:10.0.0.4".into())));
        // D→H2
        assert!(edges.contains(&("hop:ipv4:10.0.0.4".into(), "host:ipv4:10.0.0.20".into())));
        assert_eq!(edges.len(), 5);
    }

    // ---- 7. isolated_and_routed_hosts -------------------------------------

    #[test]
    fn isolated_and_routed_hosts() {
        let hosts = vec![
            make_host("192.168.1.10", true, vec![]),
            make_host("10.0.0.10", true, vec![(1, "10.0.0.1", Some(1.0))]),
        ];
        let g = build_hybrid_topology(&hosts);

        let hosts = host_node_ids(&g);
        assert!(hosts.contains(&"host:ipv4:192.168.1.10".into()));
        assert!(hosts.contains(&"host:ipv4:10.0.0.10".into()));

        // isolated host still present
        assert_eq!(hosts.len(), 2);
    }

    // ---- 8. dead_hosts_are_excluded ---------------------------------------

    #[test]
    fn dead_hosts_are_excluded() {
        let hosts = vec![
            make_host("192.168.1.10", false, vec![]),
            make_host("192.168.1.20", false, vec![]),
        ];
        let g = build_hybrid_topology(&hosts);

        assert!(host_node_ids(&g).is_empty());
        assert!(g.nodes.is_empty());
    }

    // ---- 9. mixed_alive_and_dead ------------------------------------------

    #[test]
    fn mixed_alive_and_dead() {
        let hosts = vec![
            make_host("192.168.1.10", true, vec![]),
            make_host("192.168.1.20", false, vec![]),
        ];
        let g = build_hybrid_topology(&hosts);

        let hosts = host_node_ids(&g);
        assert!(hosts.contains(&"host:ipv4:192.168.1.10".into()));
        assert!(!hosts.contains(&"host:ipv4:192.168.1.20".into()));
        assert_eq!(hosts.len(), 1);
    }

    // ---- 10. input_order_does_not_change_graph ----------------------------

    #[test]
    fn input_order_does_not_change_graph() {
        let hosts_a = vec![
            make_host("192.168.1.10", true, vec![]),
            make_host("192.168.1.20", true, vec![]),
        ];
        let hosts_b: Vec<HostInfo> = hosts_a.iter().cloned().rev().collect();

        let ga = build_hybrid_topology(&hosts_a);
        let gb = build_hybrid_topology(&hosts_b);

        assert_eq!(ga, gb);
    }

    // ---- 11. ipv6_host_is_supported ---------------------------------------

    #[test]
    fn ipv6_host_is_supported() {
        let hosts = vec![make_host("2001:db8:abcd:1::10", true, vec![])];
        let g = build_hybrid_topology(&hosts);

        assert!(host_node_ids(&g).contains(&"host:ipv6:2001:db8:abcd:1::10".into()));

        let subnets = subnet_node_ids(&g);
        assert!(
            subnets.contains(&"subnet:ipv6:2001:0db8:abcd:0001::/64".into()),
            "got: {subnets:?}"
        );
    }

    // ---- 12. duplicate_host_ip_is_deduplicated ----------------------------

    #[test]
    fn duplicate_host_ip_is_deduplicated() {
        let hosts = vec![
            HostInfo {
                ip: "192.168.1.10".parse().unwrap(),
                hostname: Some("first".into()),
                ttl: None,
                os_guess: None,
                ports: vec![],
                alive: true,
                route: vec![],
            },
            HostInfo {
                ip: "192.168.1.10".parse().unwrap(),
                hostname: Some("second".into()),
                ttl: None,
                os_guess: None,
                ports: vec![],
                alive: true,
                route: vec![Hop {
                    hop: 1,
                    ip: "10.0.0.1".parse().unwrap(),
                    rtt_ms: Some(1.0),
                }],
            },
        ];
        let g = build_hybrid_topology(&hosts);

        // single host node
        assert_eq!(host_node_ids(&g).len(), 1);

        // route from the more informative entry (the one with route)
        let edges = confirmed_route_edges(&g);
        assert!(edges.contains(&("hop:ipv4:10.0.0.1".into(), "host:ipv4:192.168.1.10".into())));
    }

    // ---- 13. no_self_loops ------------------------------------------------

    #[test]
    fn no_self_loops() {
        let hosts = vec![make_host(
            "10.0.0.10",
            true,
            vec![
                (1, "10.0.0.1", Some(1.0)),
                (2, "10.0.0.2", Some(2.0)),
                (3, "10.0.0.10", Some(3.0)),
            ],
        )];
        let g = build_hybrid_topology(&hosts);

        for edge in &g.edges {
            assert_ne!(
                edge.source, edge.target,
                "self-loop: {} -> {}",
                edge.source, edge.target
            );
        }
    }

    // ---- 14. no_duplicate_edges -------------------------------------------

    #[test]
    fn no_duplicate_edges() {
        let hosts = vec![
            make_host(
                "10.0.0.10",
                true,
                vec![(1, "10.0.0.1", Some(1.0)), (2, "10.0.0.2", Some(2.0))],
            ),
            make_host(
                "10.0.0.20",
                true,
                vec![(1, "10.0.0.1", Some(1.0)), (2, "10.0.0.2", Some(2.0))],
            ),
        ];
        let g = build_hybrid_topology(&hosts);

        // A→B edge should appear only once
        let ab: Vec<_> = g
            .edges
            .iter()
            .filter(|e| {
                e.source == "hop:ipv4:10.0.0.1"
                    && e.target == "hop:ipv4:10.0.0.2"
                    && e.kind == TopologyEdgeKind::ConfirmedRoute
            })
            .collect();
        assert_eq!(ab.len(), 1, "A→B must appear exactly once");
    }

    // ---- 15. deterministic_node_and_edge_order ----------------------------

    #[test]
    fn deterministic_node_and_edge_order() {
        let hosts = vec![
            make_host("10.0.0.20", true, vec![(1, "10.0.0.1", Some(1.0))]),
            make_host("192.168.1.10", true, vec![]),
        ];
        let g1 = build_hybrid_topology(&hosts);
        let g2 = build_hybrid_topology(&hosts);

        assert_eq!(g1, g2);
    }

    // ---- 16. alive_invariant ----------------------------------------------

    #[test]
    fn alive_invariant() {
        let hosts = vec![make_host("192.168.1.10", true, vec![])];
        let g = build_hybrid_topology(&hosts);

        assert!(
            g.nodes.iter().any(|n| n.kind == TopologyNodeKind::Host),
            "alive host must produce at least one Host node"
        );
    }

    // ---- 17. empty_hosts_returns_empty_graph -------------------------------

    #[test]
    fn empty_hosts_returns_empty_graph() {
        let g = build_hybrid_topology(&[]);
        assert!(g.nodes.is_empty(), "no hosts → no nodes");
        assert!(g.edges.is_empty(), "no hosts → no edges");
    }

    // ---- 18. subnet_membership_edges_created -------------------------------

    #[test]
    fn subnet_membership_edges_created() {
        let hosts = vec![
            make_host("192.168.1.10", true, vec![]),
            make_host("192.168.1.20", true, vec![]),
        ];
        let g = build_hybrid_topology(&hosts);

        let membership: Vec<_> = g
            .edges
            .iter()
            .filter(|e| e.kind == TopologyEdgeKind::LogicalSubnetMembership)
            .collect();
        // Both hosts in the same /24 → 2 membership edges
        assert_eq!(membership.len(), 2, "two hosts → two membership edges");
        for m in &membership {
            assert!(
                m.source.starts_with("host:"),
                "membership source must be a host node: {}",
                m.source
            );
            assert!(
                m.target.starts_with("subnet:"),
                "membership target must be a subnet node: {}",
                m.target
            );
        }
    }

    // ---- 19. hop_is_host_takes_priority_over_routehop ----------------------

    #[test]
    fn hop_is_host_takes_priority_over_routehop() {
        // A host whose route lists itself as hop — the node must be Host kind.
        let hosts = vec![make_host(
            "10.0.0.10",
            true,
            vec![(1, "10.0.0.1", Some(1.0)), (2, "10.0.0.10", Some(2.0))],
        )];
        let g = build_hybrid_topology(&hosts);

        let host_node = g
            .nodes
            .iter()
            .find(|n| n.id == "host:ipv4:10.0.0.10")
            .expect("host node must exist");
        assert_eq!(
            host_node.kind,
            TopologyNodeKind::Host,
            "10.0.0.10 must be Host even when it appears as route hop"
        );

        // No RouteHop node for 10.0.0.10
        assert!(
            g.nodes.iter().all(|n| n.id != "hop:ipv4:10.0.0.10"),
            "must not create RouteHop node for host IP"
        );
    }

    // ---- 20. route_hop_deduplication ---------------------------------------

    #[test]
    fn route_hop_deduplication() {
        // Two hosts sharing the same route hop IP → only one RouteHop node.
        let hosts = vec![
            make_host(
                "10.0.0.10",
                true,
                vec![(1, "10.0.0.1", Some(1.0)), (2, "10.0.0.2", Some(2.0))],
            ),
            make_host(
                "10.0.0.20",
                true,
                vec![(1, "10.0.0.1", Some(1.0)), (2, "10.0.0.3", Some(3.0))],
            ),
        ];
        let g = build_hybrid_topology(&hosts);

        let hop_count = g
            .nodes
            .iter()
            .filter(|n| n.kind == TopologyNodeKind::RouteHop)
            .count();
        assert_eq!(hop_count, 3, "A(10.0.0.1), B(10.0.0.2), D(10.0.0.3)");

        // Edge A→B appears exactly once
        let ab: Vec<_> = g
            .edges
            .iter()
            .filter(|e| {
                e.source == "hop:ipv4:10.0.0.1"
                    && e.target == "hop:ipv4:10.0.0.2"
                    && e.kind == TopologyEdgeKind::ConfirmedRoute
            })
            .collect();
        assert_eq!(ab.len(), 1, "shared edge A→B appears once");
    }

    // ---- 21. ipv6_subnet_grouping ------------------------------------------

    #[test]
    fn ipv6_subnet_grouping() {
        let hosts = vec![
            make_host("2001:db8:abcd:1::10", true, vec![]),
            make_host("2001:db8:abcd:1::20", true, vec![]),
        ];
        let g = build_hybrid_topology(&hosts);

        let subnets = subnet_node_ids(&g);
        assert_eq!(
            subnets.len(),
            1,
            "two hosts in same /64 subnet → one subnet"
        );
        assert!(
            subnets[0].contains("2001:0db8:abcd:0001"),
            "subnet should be /64 of ::10: {}",
            subnets[0]
        );
    }

    // ---- 22. route_hop_and_subnet_edges_coexist ----------------------------

    #[test]
    fn route_hop_and_subnet_edges_coexist() {
        let hosts = vec![make_host(
            "10.0.0.10",
            true,
            vec![(1, "10.0.0.1", Some(1.0))],
        )];
        let g = build_hybrid_topology(&hosts);

        let route_edges: Vec<_> = g
            .edges
            .iter()
            .filter(|e| e.kind == TopologyEdgeKind::ConfirmedRoute)
            .collect();
        assert_eq!(route_edges.len(), 1, "one route edge");

        let membership_edges: Vec<_> = g
            .edges
            .iter()
            .filter(|e| e.kind == TopologyEdgeKind::LogicalSubnetMembership)
            .collect();
        // Host + route hop → 2 membership edges
        assert_eq!(membership_edges.len(), 2, "host + hop, both in subnets");
    }
}
