use crate::models::HostInfo;
use crate::theme::use_theme;
use crate::topology::canvas::SvgCanvas;
use crate::topology::controls::TopologyControls;
use crate::topology::controls_panel::ControlsPanel;
use crate::topology::filter::compute_filtered_hosts;
use crate::topology::graph::build_topology;
use crate::topology::layout::GraphLayout;
use crate::topology::state::{provide_topology_context, LayoutType, SizeMode};
use crate::topology::svg_helpers::{compute_connected_ids, compute_visible_bounds, visible_count};
use crate::topology::tooltip::TopologyTooltip;
use crate::HostDetailPanel;
use dioxus::prelude::*;
use web_time::Instant;

#[derive(Props, Clone, PartialEq)]
pub struct TopologyViewProps {
    pub hosts: Vec<HostInfo>,
    pub on_select_host: EventHandler<String>,
}

#[component]
pub fn TopologyView(props: TopologyViewProps) -> Element {
    let theme = use_theme();
    let mut ctx = provide_topology_context();
    let total_alive = props.hosts.iter().filter(|h| h.alive).count();
    let filtered_hosts = compute_filtered_hosts(&props.hosts, &ctx);
    let display_hosts = filtered_hosts.len();
    let showing_filtered = display_hosts < total_alive;

    let layout_width = 900.0f64;
    let layout_height = 600.0f64;
    let layout = use_memo(move || {
        let hosts = filtered_hosts.clone();
        let lt = (ctx.layout_type)();
        let _cluster = (ctx.cluster_mode)();
        let sm = (ctx.size_mode)();
        let graph = build_topology(&hosts);
        let mut layout = GraphLayout::from_graph(&graph, layout_width, layout_height, sm);
        layout.compute_with_type(if lt == LayoutType::Force { 150 } else { 0 }, lt, sm);
        layout
    });
    let nodes = layout.read().nodes.clone();
    let edges = layout.read().edges.clone();

    let subnet_groups = use_memo(move || {
        let nodes = &layout.read().nodes;
        let mut cluster_map: std::collections::HashMap<usize, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, node) in nodes.iter().enumerate() {
            if let Some(cid) = node.cluster_id {
                cluster_map.entry(cid).or_default().push(i);
            }
        }
        crate::topology::svg_helpers::compute_subnet_groups(cluster_map, nodes, 20.0)
    });

    let selected_ip = (ctx.selected_host)();
    let hovered_ip = (ctx.hovered_host)();
    let active_ip = selected_ip.as_ref().or(hovered_ip.as_ref());
    let connected_ids = compute_connected_ids(&edges, active_ip.map(|s| s.as_str()));
    let has_selection = active_ip.is_some();
    let dim_opacity = "0.15";
    let hover_opacity = "0.35";

    let mut zoom = ctx.zoom;
    let mut pan_x = ctx.pan_x;
    let mut pan_y = ctx.pan_y;
    let mut dragging = use_signal(|| false);
    let transition_style = if dragging() {
        "none".to_string()
    } else {
        "transform 0.05s".to_string()
    };
    let cursor_style = if dragging() {
        "grabbing".to_string()
    } else {
        "grab".to_string()
    };
    let mut drag_start = use_signal(|| (0.0f64, 0.0f64));
    let mut pan_start = use_signal(|| (0.0f64, 0.0f64));
    let mut last_zoom_time = use_signal(Instant::now);
    let mut last_pan_time = use_signal(Instant::now);

    let all_hosts = props.hosts.clone();
    let tooltip_host = hovered_ip
        .as_ref()
        .and_then(|ip| all_hosts.iter().find(|h| h.ip.to_string() == *ip).cloned());
    let panel_host = selected_ip
        .as_ref()
        .and_then(|ip| all_hosts.iter().find(|h| h.ip.to_string() == *ip).cloned());

    let col = &theme.colors;
    let (cc, ch, cm, cl, cu, cp) = (
        col.severity_critical.clone(),
        col.severity_high.clone(),
        col.severity_medium.clone(),
        col.severity_low.clone(),
        col.severity_unknown.clone(),
        col.primary.clone(),
    );

    let zoom_val = zoom();
    let pan_x_val = pan_x();
    let pan_y_val = pan_y();
    let cull_bounds = compute_visible_bounds(
        pan_x_val,
        pan_y_val,
        zoom_val,
        layout_width,
        layout_height,
        80,
        nodes.len(),
    );
    let (vmin_x, vmax_x, vmin_y, vmax_y) =
        cull_bounds.unwrap_or((-1000.0, 1000.0, -1000.0, 1000.0));
    let use_culling = cull_bounds.is_some();
    let node_vis_count = visible_count(&nodes, cull_bounds);
    let on_sel = props.on_select_host;

    rsx! {
        div {
            class: "relative w-full h-96 rounded overflow-hidden border",
            style: "background: var(--color-surface); border-color: var(--color-border);",
            onwheel: move |e: Event<WheelData>| {
                let now = Instant::now();
                if now.duration_since(last_zoom_time()).as_millis() < 150 { return; }
                last_zoom_time.set(now);
                let delta = e.data().delta().strip_units().y;
                let z = zoom();
                zoom.set((if delta > 0.0 { z * 0.9 } else { z * 1.1 }).clamp(0.1, 5.0));
            },
            onmousedown: move |e: Event<MouseData>| {
                dragging.set(true);
                let client = e.data().client_coordinates();
                drag_start.set((client.x, client.y));
                pan_start.set((pan_x(), pan_y()));
            },
            onmousemove: move |e: Event<MouseData>| {
                if dragging() {
                    let now = Instant::now();
                    if now.duration_since(last_pan_time()).as_millis() < 50 { return; }
                    last_pan_time.set(now);
                    let (sx, sy) = drag_start();
                    let (px, py) = pan_start();
                    let client = e.data().client_coordinates();
                    pan_x.set(px + client.x - sx);
                    pan_y.set(py + client.y - sy);
                }
                let client = e.data().client_coordinates();
                ctx.hover_pos.set((client.x, client.y));
            },
            onmouseup: move |_| { dragging.set(false); },
            onmouseleave: move |_| { dragging.set(false); ctx.hovered_host.set(None); },

            SvgCanvas {
                zoom: zoom(), pan_x: pan_x(), pan_y: pan_y(),
                transition_style: transition_style.clone(), cursor_style: cursor_style.clone(),
                layout_width, layout_height,
                nodes: nodes.clone(), edges: edges.clone(),
                cluster_mode: (ctx.cluster_mode)(),
                subnet_groups: subnet_groups(),
                connected_ids: connected_ids.clone(),
                has_selection, show_labels: (ctx.show_labels)(),
                dim_opacity: dim_opacity.to_string(), hover_opacity: hover_opacity.to_string(),
                selected_ip: selected_ip.clone(), hovered_ip: hovered_ip.clone(),
                color_critical: cc, color_high: ch, color_medium: cm,
                color_low: cl, color_unknown: cu, color_primary: cp,
                use_culling, visible_min_x: vmin_x, visible_max_x: vmax_x,
                visible_min_y: vmin_y, visible_max_y: vmax_y,
                selected_host: ctx.selected_host, hovered_host: ctx.hovered_host,
                on_select_host: on_sel,
            }

            TopologyControls {
                hosts: props.hosts.clone(),
                on_reset_view: move |_| {
                    zoom.set(1.0); pan_x.set(0.0); pan_y.set(0.0);
                    ctx.selected_host.set(None); ctx.hovered_host.set(None);
                    ctx.filter_severity.set(Vec::new()); ctx.filter_os.set(Vec::new());
                    ctx.search_query.set(String::new()); ctx.layout_type.set(LayoutType::Force);
                    ctx.size_mode.set(SizeMode::Auto); ctx.cluster_mode.set(false);
                    ctx.port_filter_enabled.set(true); ctx.filter_services.set(Vec::new());
                    ctx.only_cve.set(false);
                },
            }

            ControlsPanel {
                zoom, pan_x, pan_y, use_culling, node_vis_count,
                total_nodes: nodes.len(), showing_filtered, display_hosts, total_alive,
            }

            TopologyTooltip { host: tooltip_host, pos: (ctx.hover_pos)(), visible: (ctx.hovered_host)().is_some() }
            if let Some(host) = panel_host {
                div { class: "mt-4 border rounded-lg p-4 border-border bg-surface",
                    HostDetailPanel { host, on_close: move |_| { ctx.selected_host.set(None); } }
                }
            }
        }
    }
}
