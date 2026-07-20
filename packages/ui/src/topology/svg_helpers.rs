use std::collections::HashSet;
use crate::topology::layout::LayoutEdge;

/// Bounding box for a subnet group rectangle.
#[derive(Clone, Debug, PartialEq)]
pub struct SubnetGroup {
    pub subnet: String,
    pub min_x: f64,
    pub min_y: f64,
    pub width: f64,
    pub height: f64,
}

/// Compute subnet grouping rectangles from clustered nodes.
pub fn compute_subnet_groups(
    cluster_map: std::collections::HashMap<usize, Vec<usize>>,
    nodes: &[crate::topology::layout::LayoutNode],
    padding: f64,
) -> Vec<SubnetGroup> {
    cluster_map
        .into_values()
        .filter(|group| group.len() >= 2)
        .map(|indices| {
            let subnet = nodes[indices[0]].subnet.clone();
            let min_x = indices
                .iter()
                .map(|&i| nodes[i].x - nodes[i].radius)
                .fold(f64::INFINITY, f64::min)
                - padding;
            let min_y = indices
                .iter()
                .map(|&i| nodes[i].y - nodes[i].radius)
                .fold(f64::INFINITY, f64::min)
                - padding;
            let max_x = indices
                .iter()
                .map(|&i| nodes[i].x + nodes[i].radius)
                .fold(f64::NEG_INFINITY, f64::max)
                + padding;
            let max_y = indices
                .iter()
                .map(|&i| nodes[i].y + nodes[i].radius)
                .fold(f64::NEG_INFINITY, f64::max)
                + padding;
            SubnetGroup {
                subnet,
                min_x,
                min_y,
                width: max_x - min_x,
                height: max_y - min_y,
            }
        })
        .collect()
}

/// Build a set of connected node IDs for highlighting (from + to).
pub fn compute_connected_ids(edges: &[LayoutEdge], active_ip: Option<&str>) -> HashSet<String> {
    let Some(ip) = active_ip else { return HashSet::new() };
    let mut set = HashSet::new();
    set.insert(ip.to_string());
    for edge in edges {
        if edge.from == *ip {
            set.insert(edge.to.clone());
        }
        if edge.to == *ip {
            set.insert(edge.from.clone());
        }
    }
    set
}

/// Viewport culling bounds.
pub fn compute_visible_bounds(
    pan_x: f64,
    pan_y: f64,
    zoom: f64,
    layout_width: f64,
    layout_height: f64,
    threshold: usize,
    node_count: usize,
) -> Option<(f64, f64, f64, f64)> {
    if node_count <= threshold {
        return None;
    }
    let vis_left = -pan_x / zoom - 100.0;
    let vis_right = (layout_width - pan_x) / zoom + 100.0;
    let vis_top = -pan_y / zoom - 100.0;
    let vis_bottom = (layout_height - pan_y) / zoom + 100.0;
    Some((vis_left, vis_right, vis_top, vis_bottom))
}

/// Count how many nodes are within the visible bounds.
pub fn visible_count(
    nodes: &[crate::topology::layout::LayoutNode],
    bounds: Option<(f64, f64, f64, f64)>,
) -> usize {
    match bounds {
        Some((l, r, t, b)) => nodes
            .iter()
            .filter(|n| n.x >= l && n.x <= r && n.y >= t && n.y <= b)
            .count(),
        None => nodes.len(),
    }
}
