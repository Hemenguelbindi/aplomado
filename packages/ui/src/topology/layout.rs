use crate::topology::graph::{EdgeKind, NodeSeverity, TopologyGraph};
use crate::topology::state::{LayoutType, SizeMode};
use petgraph::visit::{EdgeRef, IntoEdgeReferences, IntoNodeReferences};
use std::collections::HashMap;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct LayoutNode {
    pub id: String,
    pub x: f64,
    pub y: f64,
    pub vx: f64,
    pub vy: f64,
    pub label: String,
    pub severity: NodeSeverity,
    pub radius: f64,
    pub depth: u32,
    pub cluster_id: Option<usize>,
    pub port_count: u32,
    pub subnet: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct LayoutEdge {
    pub from: String,
    pub to: String,
    pub weight: f32,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct GraphLayout {
    pub nodes: Vec<LayoutNode>,
    pub edges: Vec<LayoutEdge>,
    pub width: f64,
    pub height: f64,
}

impl GraphLayout {
    /// Построить layout из графа топологии.
    pub fn from_graph(graph: &TopologyGraph, width: f64, height: f64, size_mode: SizeMode) -> Self {
        let mut nodes = Vec::new();

        for (_idx, node_weight) in graph.node_references() {
            let ip_str = node_weight.ip.to_string();
            let port_count = node_weight.open_ports.len() as u32;

            nodes.push(LayoutNode {
                id: ip_str,
                x: width / 2.0,
                y: height / 2.0,
                vx: 0.0,
                vy: 0.0,
                label: node_weight
                    .hostname
                    .as_deref()
                    .unwrap_or(&node_weight.ip.to_string())
                    .to_string(),
                severity: node_weight.severity.clone(),
                radius: node_radius(&node_weight.severity, port_count, size_mode),
                depth: node_weight.depth,
                cluster_id: None,
                port_count,
                subnet: node_weight.subnet.clone(),
            });
        }

        let mut edges = Vec::new();
        for edge in graph.edge_references() {
            let from_weight = &graph[edge.source()];
            let to_weight = &graph[edge.target()];
            edges.push(LayoutEdge {
                from: from_weight.ip.to_string(),
                to: to_weight.ip.to_string(),
                weight: edge.weight().weight,
                kind: edge.weight().kind.clone(),
            });
        }

        let mut layout = Self {
            nodes,
            edges,
            width,
            height,
        };
        layout.compute(0, size_mode);
        layout
    }

    /// Backward-compatible compute: defaults to Circular layout.
    pub fn compute(&mut self, iterations: usize, size_mode: SizeMode) {
        self.compute_with_type(iterations, LayoutType::Circular, size_mode);
    }

    /// Compute layout with specified algorithm.
    pub fn compute_with_type(
        &mut self,
        iterations: usize,
        layout_type: LayoutType,
        size_mode: SizeMode,
    ) {
        if self.nodes.is_empty() {
            return;
        }

        // Recompute radii based on current size mode
        for node in &mut self.nodes {
            node.radius = node_radius(&node.severity, node.port_count, size_mode);
        }

        match layout_type {
            LayoutType::Force => self.compute_force(iterations.max(100)),
            LayoutType::Circular => self.layout_circular(self.nodes.len()),
            LayoutType::Hierarchical => {
                let max_depth = self.nodes.iter().map(|n| n.depth).max().unwrap_or(0);
                self.layout_hierarchical(max_depth);
            }
        }

        self.compute_subnet_clusters();
    }

    // ─── Force-directed layout ───────────────────────────────────────────

    /// Spring-electric force-directed simulation.
    fn compute_force(&mut self, iterations: usize) {
        let n = self.nodes.len() as f64;
        if n < 1.0 {
            return;
        }

        let area = self.width * self.height;
        let k = (area / n).sqrt(); // ideal spring length
        let margin = 60.0;

        // Initialize positions in a grid pattern
        let cols = (n.sqrt() as usize).max(1);
        for (i, node) in self.nodes.iter_mut().enumerate() {
            let row = i / cols;
            let col = i % cols;
            node.x = margin + (self.width - 2.0 * margin) * (col as f64 / (cols as f64).max(1.0));
            node.y = margin
                + (self.height - 2.0 * margin)
                    * (row as f64 / ((n as usize / cols.max(1)).max(1) as f64).max(1.0));
            node.vx = 0.0;
            node.vy = 0.0;
        }

        // Build adjacency lookup for attraction
        let mut adjacency: HashMap<usize, Vec<usize>> = HashMap::new();
        for edge in &self.edges {
            if let (Some(from_idx), Some(to_idx)) = (
                self.nodes.iter().position(|n| n.id == edge.from),
                self.nodes.iter().position(|n| n.id == edge.to),
            ) {
                adjacency.entry(from_idx).or_default().push(to_idx);
                adjacency.entry(to_idx).or_default().push(from_idx);
            }
        }

        let cooling = 0.85;
        let center_x = self.width / 2.0;
        let center_y = self.height / 2.0;

        for _iter in 0..iterations {
            // Reset forces
            for node in self.nodes.iter_mut() {
                node.vx = 0.0;
                node.vy = 0.0;
            }

            // Repulsion between all pairs
            for i in 0..self.nodes.len() {
                for j in (i + 1)..self.nodes.len() {
                    let dx = self.nodes[j].x - self.nodes[i].x;
                    let dy = self.nodes[j].y - self.nodes[i].y;
                    let dist = (dx * dx + dy * dy).sqrt().max(0.1);
                    let mut force = k * k / dist;
                    force = force.min(100.0); // cap repulsion

                    let fx = (dx / dist) * force;
                    let fy = (dy / dist) * force;

                    self.nodes[i].vx -= fx;
                    self.nodes[i].vy -= fy;
                    self.nodes[j].vx += fx;
                    self.nodes[j].vy += fy;
                }
            }

            // Attraction along edges
            for i in 0..self.nodes.len() {
                if let Some(neighbors) = adjacency.get(&i) {
                    for &j in neighbors {
                        if i == j {
                            continue;
                        }
                        let dx = self.nodes[j].x - self.nodes[i].x;
                        let dy = self.nodes[j].y - self.nodes[i].y;
                        let dist = (dx * dx + dy * dy).sqrt().max(0.1);
                        let force = dist * dist / k;

                        let fx = (dx / dist) * force;
                        let fy = (dy / dist) * force;

                        self.nodes[i].vx += fx;
                        self.nodes[i].vy += fy;
                    }
                }
            }

            // Centering force
            for node in self.nodes.iter_mut() {
                node.vx += (center_x - node.x) * 0.01;
                node.vy += (center_y - node.y) * 0.01;
            }

            // Apply velocities with damping
            for node in self.nodes.iter_mut() {
                node.vx *= cooling;
                node.vy *= cooling;
                node.x += node.vx;
                node.y += node.vy;
            }
        }

        // Normalize positions to fit within bounds
        self.normalize_positions(margin);
    }

    /// Normalize node positions to fit within [margin, width-margin] × [margin, height-margin].
    fn normalize_positions(&mut self, margin: f64) {
        if self.nodes.is_empty() {
            return;
        }

        let min_x = self.nodes.iter().map(|n| n.x).fold(f64::INFINITY, f64::min);
        let max_x = self
            .nodes
            .iter()
            .map(|n| n.x)
            .fold(f64::NEG_INFINITY, f64::max);
        let min_y = self.nodes.iter().map(|n| n.y).fold(f64::INFINITY, f64::min);
        let max_y = self
            .nodes
            .iter()
            .map(|n| n.y)
            .fold(f64::NEG_INFINITY, f64::max);

        let range_x = (max_x - min_x).max(1.0);
        let range_y = (max_y - min_y).max(1.0);
        let target_w = self.width - 2.0 * margin;
        let target_h = self.height - 2.0 * margin;

        for node in self.nodes.iter_mut() {
            node.x = margin + ((node.x - min_x) / range_x) * target_w;
            node.y = margin + ((node.y - min_y) / range_y) * target_h;
        }
    }

    // ─── Subnet clustering ───────────────────────────────────────────────

    /// Group nodes by /24 subnet and apply visual clustering.
    fn compute_subnet_clusters(&mut self) {
        if self.nodes.is_empty() {
            return;
        }

        // Group nodes by subnet
        let mut subnet_groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, node) in self.nodes.iter().enumerate() {
            subnet_groups
                .entry(node.subnet.clone())
                .or_default()
                .push(i);
        }

        // Assign cluster IDs and compute centers
        let mut cluster_centers: Vec<(f64, f64)> = Vec::new();

        for (cluster_idx, (_subnet, indices)) in subnet_groups.iter().enumerate() {
            // Assign cluster ID
            for &idx in indices {
                self.nodes[idx].cluster_id = Some(cluster_idx);
            }

            // Compute center of this cluster
            let cx: f64 =
                indices.iter().map(|&i| self.nodes[i].x).sum::<f64>() / indices.len() as f64;
            let cy: f64 =
                indices.iter().map(|&i| self.nodes[i].y).sum::<f64>() / indices.len() as f64;
            cluster_centers.push((cx, cy));
        }

        // Only cluster if more than one subnet
        if cluster_centers.len() <= 1 {
            return;
        }

        // Shift nodes 5% toward their cluster center
        for node in self.nodes.iter_mut() {
            if let Some(cluster_id) = node.cluster_id {
                if let Some(&(cx, cy)) = cluster_centers.get(cluster_id) {
                    let pull = 0.05;
                    node.x += (cx - node.x) * pull;
                    node.y += (cy - node.y) * pull;
                }
            }
        }
    }

    // ─── Circular layout ─────────────────────────────────────────────────

    fn layout_circular(&mut self, n: usize) {
        let cx = self.width / 2.0;
        let cy = self.height / 2.0;

        let radius = (self.width.min(self.height) * 0.35).max(120.0);
        let radius = if n <= 5 { radius * 1.3 } else { radius };

        for (i, node) in self.nodes.iter_mut().enumerate() {
            let angle = (i as f64 / n as f64) * std::f64::consts::TAU - std::f64::consts::FRAC_PI_2;
            node.x = cx + angle.cos() * radius;
            node.y = cy + angle.sin() * radius;
        }
    }

    // ─── Hierarchical layout ─────────────────────────────────────────────

    fn layout_hierarchical(&mut self, max_depth: u32) {
        let h_margin = 50.0;
        let v_margin = 50.0;
        let w = self.width - h_margin * 2.0;
        let h = self.height - v_margin * 2.0;

        let mut by_depth: HashMap<u32, Vec<usize>> = HashMap::new();
        for (i, node) in self.nodes.iter().enumerate() {
            by_depth.entry(node.depth).or_default().push(i);
        }

        let unique_depths = by_depth.len();
        if unique_depths <= 2 {
            self.layout_circular(self.nodes.len());
            return;
        }

        for (depth, indices) in &by_depth {
            let y = v_margin + h * (1.0 - *depth as f64 / max_depth as f64);

            let count = indices.len();
            for (i, &node_idx) in indices.iter().enumerate() {
                let x = if count > 1 {
                    h_margin + w * (i as f64 / (count - 1) as f64)
                } else {
                    self.width / 2.0
                };
                self.nodes[node_idx].x = x;
                self.nodes[node_idx].y = y;
            }
        }
    }
}

/// Node radius based on severity and port count.
fn node_radius(severity: &NodeSeverity, port_count: u32, size_mode: SizeMode) -> f64 {
    match size_mode {
        SizeMode::Auto => {
            let base = match severity {
                NodeSeverity::Critical => 14.0,
                NodeSeverity::High => 12.0,
                NodeSeverity::Medium => 10.0,
                NodeSeverity::Low => 8.0,
                NodeSeverity::Unknown => 6.0,
            };
            let port_bonus = (port_count as f64 / 3.0).min(10.0);
            (base + port_bonus).clamp(6.0, 24.0)
        }
        SizeMode::Uniform => 14.0,
    }
}
