use dioxus::prelude::*;
use std::collections::HashSet;
use crate::topology::graph::NodeSeverity;
use crate::topology::layout::LayoutNode;

/// Render SVG nodes (circles) with labels, selection rings, and click hit areas.
pub fn render_nodes(
    nodes: &[LayoutNode],
    selected_ip: &Option<String>,
    hovered_ip: &Option<String>,
    connected_ids: &HashSet<String>,
    has_selection: bool,
    dim_opacity: &str,
    hover_opacity: &str,
    color_critical: &str,
    color_high: &str,
    color_medium: &str,
    color_low: &str,
    color_unknown: &str,
    color_primary: &str,
    cluster_mode: bool,
    show_labels: bool,
    use_culling: bool,
    visible_min_x: f64,
    visible_max_x: f64,
    visible_min_y: f64,
    visible_max_y: f64,
    mut selected_host: Signal<Option<String>>,
    mut hovered_host: Signal<Option<String>>,
    on_select_host: EventHandler<String>,
) -> Element {
    // Clone per-node event handler so each move closure owns a copy
    rsx! {
        {nodes.iter().enumerate().map(|(index, node)| {
            let is_visible = !use_culling
                || (node.x >= visible_min_x
                    && node.x <= visible_max_x
                    && node.y >= visible_min_y
                    && node.y <= visible_max_y);
            if !is_visible { return rsx! {}; }

            let fill = match node.severity {
                NodeSeverity::Critical => color_critical,
                NodeSeverity::High => color_high,
                NodeSeverity::Medium => color_medium,
                NodeSeverity::Low => color_low,
                NodeSeverity::Unknown => color_unknown,
            };

            let id = node.id.clone();
            let ip_for_click = node.id.clone();
            let ip_for_enter = node.id.clone();
            let is_connected = !has_selection || connected_ids.contains(&node.id);
            let opacity = if has_selection && !is_connected {
                if hovered_ip.is_some() { hover_opacity } else { dim_opacity }
            } else { "1.0" };

            let stroke_color = if selected_ip.as_deref() == Some(&node.id) {
                color_primary.to_string()
            } else {
                "none".to_string()
            };

            let on_sel = on_select_host.clone();

            rsx! {
                g {
                    key: "{id}",
                    class: "cursor-pointer",
                    style: "opacity: {opacity}; transition: opacity 0.3s; --i: {index}; animation: fadeIn 0.3s ease-out forwards; animation-delay: calc(var(--i) * 30ms);",

                    // Selection ring
                    if selected_ip.as_deref() == Some(&id) {
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
                    if cluster_mode {
                        if let Some(_cid) = node.cluster_id {
                            circle {
                                cx: "{node.x}", cy: "{node.y}",
                                r: "{node.radius + 2.0}",
                                style: "fill: none; stroke: var(--color-text-muted); stroke-width: 0.5; stroke-dasharray: 2 2; opacity: 0.3;",
                            }
                        }
                    }

                    // Label
                    if show_labels {
                        text {
                            x: "{node.x + node.radius + 4.0}",
                            y: "{node.y + 3.0}",
                            style: "fill: var(--color-text-secondary); font-size: 11px; font-family: monospace;",
                            "{node.label}"
                        }
                    }

                    // Invisible hit area (larger click target)
                    circle {
                        cx: "{node.x}", cy: "{node.y}",
                        r: "{node.radius + 6.0}",
                        style: "fill: transparent; stroke: none;",
                        onclick: move |_| {
                            selected_host.set(Some(ip_for_click.clone()));
                            on_sel.call(ip_for_click.clone());
                        },
                        onmouseenter: move |_| { hovered_host.set(Some(ip_for_enter.clone())); },
                        onmouseleave: move |_| { hovered_host.set(None); },
                    }
                }
            }
        })}
    }
}
