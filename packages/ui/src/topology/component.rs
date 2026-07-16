use dioxus::prelude::*;
use std::time::Instant;
use crate::models::HostInfo;
use crate::theme::use_theme;
use crate::topology::graph::{build_topology, NodeSeverity};
use crate::topology::layout::GraphLayout;
use crate::topology::state::{LayoutType, SizeMode, provide_topology_context, use_topology_context};
use crate::topology::tooltip::TopologyTooltip;
use crate::topology::host_panel::HostDetailPanel;
use crate::topology::controls::TopologyControls;

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

    // ─── Filtering ──────────────────────────────────────────────────────
    let filtered_hosts: Vec<HostInfo> = {
        let severity_filter = (ctx.filter_severity)();
        let os_filter = (ctx.filter_os)();
        let query = (ctx.search_query)().to_lowercase();
        let port_filter_enabled = (ctx.port_filter_enabled)();
        let filter_services = (ctx.filter_services)();
        let only_cve = (ctx.only_cve)();
        let show_labels = (ctx.show_labels)();
        let _ = show_labels;

        // Top 10 most common services for "Other" catch-all in port filter
        let top_service_names: Vec<String> = {
            let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for h in &props.hosts {
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

        props.hosts.iter()
            .filter(|h| h.alive)
            .filter(|h| {
                if severity_filter.is_empty() {
                    return true;
                }
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
                if os_filter.is_empty() {
                    return true;
                }
                match h.os_guess {
                    Some(ref os) => os_filter.contains(os),
                    None => false,
                }
            })
            .filter(|h| {
                if !port_filter_enabled || filter_services.is_empty() {
                    return true;
                }
                h.ports.iter().any(|p| {
                    if filter_services.contains(&p.service_name) {
                        return true;
                    }
                    if port_has_other && !top_service_names.contains(&p.service_name) {
                        return true;
                    }
                    false
                })
            })
            .filter(|h| {
                if !only_cve {
                    return true;
                }
                h.ports.iter().any(|p| !p.cves.is_empty())
            })
            .filter(|h| {
                if query.is_empty() {
                    return true;
                }
                let ip_match = h.ip.to_string().to_lowercase().contains(&query);
                let host_match = h.hostname.as_ref()
                    .map(|hn| hn.to_lowercase().contains(&query))
                    .unwrap_or(false);
                ip_match || host_match
            })
            .cloned()
            .collect()
    };

    let display_hosts = filtered_hosts.len();
    let showing_filtered = display_hosts < total_alive;

    // ─── Graph + Layout ─────────────────────────────────────────────────
    let layout_width = 900.0f64;
    let layout_height = 600.0f64;

    let layout = use_memo(move || {
        let hosts = filtered_hosts.clone();
        let lt = (ctx.layout_type)();
        let cluster = (ctx.cluster_mode)();
        let _ = cluster;
        let sm = (ctx.size_mode)();

        let graph = build_topology(&hosts);
        let mut layout = GraphLayout::from_graph(&graph, layout_width, layout_height, sm);
        let iters = if lt == LayoutType::Force { 150 } else { 0 };
        layout.compute_with_type(iters, lt, sm);
        layout
    });

    let nodes = layout.read().nodes.clone();
    let edges = layout.read().edges.clone();

    // ─── Subnet grouping rectangles ──────────────────────────────────
    #[derive(Clone, Debug, PartialEq)]
    struct SubnetGroup {
        subnet: String,
        min_x: f64,
        min_y: f64,
        width: f64,
        height: f64,
    }

    let subnet_groups = use_memo(move || {
        let padding = 20.0;
        let nodes = &layout.read().nodes;

        let mut cluster_map: std::collections::HashMap<usize, Vec<&_>> =
            std::collections::HashMap::new();
        for node in nodes {
            if let Some(cid) = node.cluster_id {
                cluster_map.entry(cid).or_default().push(node);
            }
        }

        cluster_map
            .into_values()
            .filter(|group| group.len() >= 2)
            .map(|group| {
                let subnet = group[0].subnet.clone();
                let min_x = group
                    .iter()
                    .map(|n| n.x - n.radius)
                    .fold(f64::INFINITY, f64::min)
                    - padding;
                let min_y = group
                    .iter()
                    .map(|n| n.y - n.radius)
                    .fold(f64::INFINITY, f64::min)
                    - padding;
                let max_x = group
                    .iter()
                    .map(|n| n.x + n.radius)
                    .fold(f64::NEG_INFINITY, f64::max)
                    + padding;
                let max_y = group
                    .iter()
                    .map(|n| n.y + n.radius)
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
            .collect::<Vec<_>>()
    });

    // ─── Selection set (connected node IDs for highlighting) ────────────
    let selected_ip = (ctx.selected_host)();
    let hovered_ip = (ctx.hovered_host)();

    let active_ip = selected_ip.as_ref().or(hovered_ip.as_ref());
    let connected_ids: std::collections::HashSet<String> = if let Some(ip) = active_ip.as_deref() {
        let mut set = std::collections::HashSet::new();
        set.insert(ip.to_string());
        for edge in &edges {
            if edge.from == *ip {
                set.insert(edge.to.clone());
            }
            if edge.to == *ip {
                set.insert(edge.from.clone());
            }
        }
        set
    } else {
        std::collections::HashSet::new()
    };
    let has_selection = active_ip.is_some();

    let dim_opacity = "0.15";
    let hover_opacity = "0.35";

    // ─── Zoom/Pan state ────────────────────────────────────────────────
    let mut zoom = ctx.zoom;
    let mut pan_x = ctx.pan_x;
    let mut pan_y = ctx.pan_y;
    let mut dragging = use_signal(|| false);

    // Pre-compute style values to avoid nested braces in RSX format strings
    let transition_style = if dragging() { "none".to_string() } else { "transform 0.05s".to_string() };
    let cursor_style = if dragging() { "grabbing".to_string() } else { "grab".to_string() };
    let mut drag_start = use_signal(|| (0.0f64, 0.0f64));
    let mut pan_start = use_signal(|| (0.0f64, 0.0f64));
    let mut last_zoom_time = use_signal(Instant::now);
    let mut last_pan_time = use_signal(Instant::now);

    // Host lookup for tooltip and panel
    let all_hosts = props.hosts.clone();
    let tooltip_host = hovered_ip.as_ref().and_then(|ip| {
        all_hosts.iter().find(|h| h.ip.to_string() == *ip).cloned()
    });
    let panel_host = selected_ip.as_ref().and_then(|ip| {
        all_hosts.iter().find(|h| h.ip.to_string() == *ip).cloned()
    });

    // Theme colors
    let color_critical = theme.colors.severity_critical.clone();
    let color_high = theme.colors.severity_high.clone();
    let color_medium = theme.colors.severity_medium.clone();
    let color_low = theme.colors.severity_low.clone();
    let color_unknown = theme.colors.severity_unknown.clone();
    let color_primary = theme.colors.primary.clone();

    let zoom_val = zoom();
    let pan_x_val = pan_x();
    let pan_y_val = pan_y();

    // ─── Viewport culling ──────────────────────────────────────────────
    let cull_threshold = 80;
    let use_culling = nodes.len() > cull_threshold;
    let (visible_min_x, visible_max_x, visible_min_y, visible_max_y) = if use_culling {
        let vis_left = -pan_x_val / zoom_val - 100.0;
        let vis_right = (layout_width - pan_x_val) / zoom_val + 100.0;
        let vis_top = -pan_y_val / zoom_val - 100.0;
        let vis_bottom = (layout_height - pan_y_val) / zoom_val + 100.0;
        (vis_left, vis_right, vis_top, vis_bottom)
    } else {
        (-1000.0, 1000.0, -1000.0, 1000.0)
    };

    let visible_count = if use_culling {
        nodes.iter().filter(|n| n.x >= visible_min_x && n.x <= visible_max_x && n.y >= visible_min_y && n.y <= visible_max_y).count()
    } else {
        nodes.len()
    };

    rsx! {
        div {
            class: "relative w-full h-96 rounded overflow-hidden border",
            style: "background: var(--color-surface); border-color: var(--color-border);",

            // ─── Zoom wheel ───
            onwheel: move |e: Event<WheelData>| {
                let now = Instant::now();
                if now.duration_since(last_zoom_time()).as_millis() < 150 {
                    return;
                }
                last_zoom_time.set(now);

                let delta = e.data().delta().strip_units().y;
                let z = zoom();
                let new_z = if delta > 0.0 { z * 0.9 } else { z * 1.1 };
                zoom.set(new_z.clamp(0.1, 5.0));
            },

            // ─── Drag pan handlers ───
            onmousedown: move |e: Event<MouseData>| {
                // Don't start drag if clicking on controls or panel
                dragging.set(true);
                let client = e.data().client_coordinates();
                drag_start.set((client.x, client.y));
                pan_start.set((pan_x(), pan_y()));
            },
            onmousemove: move |e: Event<MouseData>| {
                if dragging() {
                    let now = Instant::now();
                    if now.duration_since(last_pan_time()).as_millis() < 50 {
                        return;
                    }
                    last_pan_time.set(now);

                    let (sx, sy) = drag_start();
                    let (px, py) = pan_start();
                    let client = e.data().client_coordinates();
                    let dx = client.x - sx;
                    let dy = client.y - sy;
                    pan_x.set(px + dx);
                    pan_y.set(py + dy);
                }
                // Update hover position for tooltip
                let client = e.data().client_coordinates();
                ctx.hover_pos.set((client.x, client.y));
            },
            onmouseup: move |_| { dragging.set(false); },
            onmouseleave: move |_| {
                dragging.set(false);
                ctx.hovered_host.set(None);
            },

            // ─── SVG ───
            svg {
                class: "w-full h-full",
                view_box: "0 0 {layout_width} {layout_height}",
                style: "transform: scale({zoom_val}) translate({pan_x_val}px, {pan_y_val}px); \
                        transform-origin: 0 0; transition: {transition_style}; \
                        cursor: {cursor_style};",

                // ─── Animation styles ───
                style {
                    r#type: "text/css",
                    "@keyframes fadeIn {{ from {{ opacity: 0; transform: scale(0.3); }} to {{ opacity: 1; transform: scale(1); }} }}"
                }

                // ─── Subnet grouping rects ───
                {(ctx.cluster_mode)().then(|| {
                    let groups = subnet_groups();
                    rsx! {
                        {groups.iter().map(|sg| {
                            rsx! {
                                g {
                                    key: "subnet-{sg.subnet}",
                                    rect {
                                        x: "{sg.min_x}",
                                        y: "{sg.min_y}",
                                        width: "{sg.width}",
                                        height: "{sg.height}",
                                        rx: "8",
                                        ry: "8",
                                        style: "fill: rgba(128,128,128,0.05); stroke: rgba(128,128,128,0.3); stroke-dasharray: 4 4; stroke-width: 1;",
                                    }
                                    text {
                                        x: "{sg.min_x + 8.0}",
                                        y: "{sg.min_y + 14.0}",
                                        style: "fill: var(--color-text-muted); font-size: 10px; font-family: monospace;",
                                        "{sg.subnet}"
                                    }
                                }
                            }
                        })}
                    }
                })}

                // ─── Edges ───
                {edges.iter().map(|edge| {
                    let from = nodes.iter().find(|n| n.id == edge.from);
                    let to = nodes.iter().find(|n| n.id == edge.to);
                    if let (Some(f), Some(t)) = (from, to) {
                        let is_highlighted = has_selection && (connected_ids.contains(&edge.from) && connected_ids.contains(&edge.to));
                        let stroke = if is_highlighted {
                            color_primary.clone()
                        } else {
                            "rgba(88,166,255,0.6)".to_string()
                        };
                        let opacity = if has_selection && !is_highlighted { dim_opacity } else { "0.8" };
                        rsx! {
                            line {
                                key: "{edge.from}-{edge.to}",
                                x1: "{f.x}", y1: "{f.y}",
                                x2: "{t.x}", y2: "{t.y}",
                                style: "stroke: {stroke}; opacity: {opacity}; transition: opacity 0.3s;",
                                stroke_width: "{edge.weight * 1.5}",
                            }
                        }
                    } else { rsx! {} }
                })}

                // ─── Nodes ───
                {nodes.iter().enumerate().map(|(index, node)| {
                    let is_visible = !use_culling || (node.x >= visible_min_x && node.x <= visible_max_x && node.y >= visible_min_y && node.y <= visible_max_y);
                    if !is_visible { return rsx! {}; }

                    let fill = match node.severity {
                        NodeSeverity::Critical => color_critical.as_str(),
                        NodeSeverity::High => color_high.as_str(),
                        NodeSeverity::Medium => color_medium.as_str(),
                        NodeSeverity::Low => color_low.as_str(),
                        NodeSeverity::Unknown => color_unknown.as_str(),
                    };

                    let id = node.id.clone();
                    let id2 = node.id.clone();
                    let id3 = node.id.clone();
                    let ip_for_click = node.id.clone();
                    let ip_for_enter = node.id.clone();
                    let ip_for_leave = node.id.clone();

                    let is_connected = !has_selection || connected_ids.contains(&node.id);
                    let opacity = if has_selection && !is_connected {
                        if hovered_ip.is_some() { hover_opacity } else { dim_opacity }
                    } else { "1.0" };

                    let label_text = if (ctx.show_labels)() {
                        Some(node.label.clone())
                    } else {
                        None
                    };

                    let stroke_color = if selected_ip.as_deref() == Some(&node.id) {
                        color_primary.clone()
                    } else {
                        "none".to_string()
                    };

                    rsx! {
                        g {
                            key: "{id}",
                            class: "cursor-pointer",
                            style: "opacity: {opacity}; transition: opacity 0.3s; --i: {index}; animation: fadeIn 0.3s ease-out forwards; animation-delay: calc(var(--i) * 30ms);",

                            // Selection ring
                            if selected_ip.as_deref() == Some(&id2) {
                                circle {
                                    cx: "{node.x}", cy: "{node.y}",
                                    r: "{node.radius + 4.0}",
                                    style: "fill: none; stroke: {stroke_color}; stroke-width: 2;",
                                }
                            }

                            // Main circle
                            circle {
                                cx: "{node.x}", cy: "{node.y}",
                                r: "{node.radius}",
                                style: "fill: {fill}; transition: cx 0.3s, cy 0.3s, r 0.2s;",
                            }

                            // Subnet cluster indicator (small ring)
                            if (ctx.cluster_mode)() {
                                if let Some(cid) = node.cluster_id {
                                    circle {
                                        cx: "{node.x}", cy: "{node.y}",
                                        r: "{node.radius + 2.0}",
                                        style: "fill: none; stroke: var(--color-text-muted); stroke-width: 0.5; stroke-dasharray: 2 2; opacity: 0.3;",
                                    }
                                }
                            }

                            // Label
                            if let Some(label) = label_text {
                                text {
                                    x: "{node.x + node.radius + 4.0}", y: "{node.y + 3.0}",
                                    style: "fill: var(--color-text-secondary); font-size: 11px; font-family: monospace;",
                                    "{label}"
                                }
                            }

                            // Invisible hit area (larger click target)
                            circle {
                                cx: "{node.x}", cy: "{node.y}",
                                r: "{node.radius + 6.0}",
                                style: "fill: transparent; stroke: none;",
                                onclick: move |_| { ctx.selected_host.set(Some(ip_for_click.clone())); props.on_select_host.call(ip_for_click.clone()); },
                                onmouseenter: move |_| { ctx.hovered_host.set(Some(ip_for_enter.clone())); },
                                onmouseleave: move |_| { ctx.hovered_host.set(None); },
                            }
                        }
                    }
                })}
            }

            // ─── Controls panel ───
            TopologyControls {
                hosts: props.hosts.clone(),
                on_reset_view: move |_| {
                    zoom.set(1.0);
                    pan_x.set(0.0);
                    pan_y.set(0.0);
                    ctx.selected_host.set(None);
                    ctx.hovered_host.set(None);
                    ctx.filter_severity.set(Vec::new());
                    ctx.filter_os.set(Vec::new());
                    ctx.search_query.set(String::new());
                    ctx.layout_type.set(LayoutType::Force);
                    ctx.size_mode.set(SizeMode::Auto);
                    ctx.cluster_mode.set(false);
                    ctx.port_filter_enabled.set(true);
                    ctx.filter_services.set(Vec::new());
                    ctx.only_cve.set(false);
                },
            }

            // ─── Zoom buttons ───
            div {
                style: "position: absolute; top: 8px; right: 8px; z-index: 30; display: flex; gap: 4px;",

                // Zoom in
                button {
                    style: "width: 28px; height: 28px; border-radius: 6px; border: 1px solid var(--color-border); \
                            background: var(--color-surface); color: var(--color-text-primary); \
                            font-size: 16px; cursor: pointer; display: flex; align-items: center; \
                            justify-content: center; box-shadow: 0 1px 4px rgba(0,0,0,0.15);",
                    onclick: move |_| { zoom.set((zoom() * 1.2).min(5.0)); },
                    "+"
                }

                // Zoom out
                button {
                    style: "width: 28px; height: 28px; border-radius: 6px; border: 1px solid var(--color-border); \
                            background: var(--color-surface); color: var(--color-text-primary); \
                            font-size: 16px; cursor: pointer; display: flex; align-items: center; \
                            justify-content: center; box-shadow: 0 1px 4px rgba(0,0,0,0.15);",
                    onclick: move |_| { zoom.set((zoom() / 1.2).max(0.1)); },
                    "−"
                }

                // Reset view
                button {
                    style: "width: 28px; height: 28px; border-radius: 6px; border: 1px solid var(--color-border); \
                            background: var(--color-surface); color: var(--color-text-primary); \
                            font-size: 12px; cursor: pointer; display: flex; align-items: center; \
                            justify-content: center; box-shadow: 0 1px 4px rgba(0,0,0,0.15);",
                    onclick: move |_| {
                        zoom.set(1.0);
                        pan_x.set(0.0);
                        pan_y.set(0.0);
                    },
                    "⟲"
                }
            }

            // ─── Node count badge (when culling) ───
            if use_culling {
                div {
                    style: "position: absolute; bottom: 8px; left: 8px; z-index: 30; \
                            padding: 3px 8px; border-radius: 4px; font-size: 11px; \
                            background: var(--color-surface); border: 1px solid var(--color-border); \
                            color: var(--color-text-muted);",
                    "Показано {visible_count} из {nodes.len()} узлов"
                }
            }

            // ─── Filtered info badge ───
            if showing_filtered {
                div {
                    style: "position: absolute; top: 8px; left: 260px; z-index: 25; \
                            padding: 3px 8px; border-radius: 4px; font-size: 11px; \
                            background: var(--color-surface); border: 1px solid var(--color-border); \
                            color: var(--color-text-muted);",
                    "Живых: {display_hosts} / {total_alive}"
                }
            }

            // ─── Tooltip overlay ───
            TopologyTooltip {
                host: tooltip_host,
                pos: (ctx.hover_pos)(),
                visible: (ctx.hovered_host)().is_some(),
            }

            // ─── Host detail panel ───
            HostDetailPanel {
                host: panel_host,
                on_close: move |_| { ctx.selected_host.set(None); },
            }
        }
    }
}
