use crate::topology::graph::NodeSeverity;
use dioxus::prelude::*;

/// Layout algorithm selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutType {
    /// Spring-electric force-directed simulation.
    Force,
    /// Nodes evenly distributed on a circle.
    Circular,
    /// Nodes grouped by traceroute depth (Y-axis).
    Hierarchical,
}

impl std::fmt::Display for LayoutType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LayoutType::Force => write!(f, "Force"),
            LayoutType::Circular => write!(f, "Circular"),
            LayoutType::Hierarchical => write!(f, "Hierarchical"),
        }
    }
}

/// Node size mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeMode {
    /// Sizes vary by port count (current behavior).
    Auto,
    /// All nodes render at fixed 14px radius.
    Uniform,
}

impl std::fmt::Display for SizeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SizeMode::Auto => write!(f, "Auto"),
            SizeMode::Uniform => write!(f, "Uniform"),
        }
    }
}

/// Shared topology visualization state, provided via context.
///
/// All child components (controls, tooltip, host_panel, SVG) read/write
/// through this single context, avoiding prop-drilling.
#[derive(Clone, Debug)]
pub struct TopologyContext {
    /// Current zoom level (1.0 = 100%).
    pub zoom: Signal<f64>,
    /// Horizontal pan offset in SVG units.
    pub pan_x: Signal<f64>,
    /// Vertical pan offset in SVG units.
    pub pan_y: Signal<f64>,
    /// IP address string of the currently selected host (for detail panel).
    pub selected_host: Signal<Option<String>>,
    /// IP address string of the currently hovered host (for tooltip).
    pub hovered_host: Signal<Option<String>>,
    /// Mouse position (x, y) in screen coords for tooltip positioning.
    pub hover_pos: Signal<(f64, f64)>,
    /// Free-text search query (matches IP or hostname).
    pub search_query: Signal<String>,
    /// Active severity filters. Empty = show all.
    pub filter_severity: Signal<Vec<NodeSeverity>>,
    /// Active OS filters. Empty = show all.
    pub filter_os: Signal<Vec<String>>,
    /// Whether to show text labels next to nodes.
    pub show_labels: Signal<bool>,
    /// Current layout algorithm.
    pub layout_type: Signal<LayoutType>,
    /// Node size mode (Auto / Uniform).
    pub size_mode: Signal<SizeMode>,
    /// Whether to cluster nodes by /24 subnet.
    pub cluster_mode: Signal<bool>,
    /// Controls panel collapsed state.
    pub controls_collapsed: Signal<bool>,

    // ─── Port / Service Filter ──────────────────────────────────────────
    /// Master toggle for port-based filtering.
    pub port_filter_enabled: Signal<bool>,
    /// Active service name filters. Empty = show all.
    pub filter_services: Signal<Vec<String>>,
    /// When true, only show hosts with at least one CVE on a port.
    pub only_cve: Signal<bool>,
}

/// Create and provide the topology context. Call once from the top-level topology component.
pub fn provide_topology_context() -> TopologyContext {
    let ctx = TopologyContext {
        zoom: use_signal(|| 1.0),
        pan_x: use_signal(|| 0.0),
        pan_y: use_signal(|| 0.0),
        selected_host: use_signal(|| None),
        hovered_host: use_signal(|| None),
        hover_pos: use_signal(|| (0.0, 0.0)),
        search_query: use_signal(String::new),
        filter_severity: use_signal(Vec::new),
        filter_os: use_signal(Vec::new),
        show_labels: use_signal(|| true),
        layout_type: use_signal(|| LayoutType::Force),
        size_mode: use_signal(|| SizeMode::Auto),
        cluster_mode: use_signal(|| false),
        controls_collapsed: use_signal(|| false),
        port_filter_enabled: use_signal(|| true),
        filter_services: use_signal(Vec::new),
        only_cve: use_signal(|| false),
    };
    use_context_provider(|| ctx.clone());
    ctx
}

/// Consume the topology context from any child component.
pub fn use_topology_context() -> TopologyContext {
    use_context::<TopologyContext>()
}
