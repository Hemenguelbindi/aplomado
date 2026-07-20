use crate::topology::layout::{LayoutEdge, LayoutNode};
use crate::topology::render_edges::render_edges;
use crate::topology::render_nodes::render_nodes;
use crate::topology::svg_helpers::SubnetGroup;
use dioxus::prelude::*;
use std::collections::HashSet;

#[derive(Props, Clone, PartialEq)]
pub struct SvgCanvasProps {
    pub zoom: f64,
    pub pan_x: f64,
    pub pan_y: f64,
    pub transition_style: String,
    pub cursor_style: String,
    pub layout_width: f64,
    pub layout_height: f64,
    pub nodes: Vec<LayoutNode>,
    pub edges: Vec<LayoutEdge>,
    pub cluster_mode: bool,
    pub subnet_groups: Vec<SubnetGroup>,
    pub connected_ids: HashSet<String>,
    pub has_selection: bool,
    pub show_labels: bool,
    pub dim_opacity: String,
    pub hover_opacity: String,
    pub selected_ip: Option<String>,
    pub hovered_ip: Option<String>,
    pub color_critical: String,
    pub color_high: String,
    pub color_medium: String,
    pub color_low: String,
    pub color_unknown: String,
    pub color_primary: String,
    pub use_culling: bool,
    pub visible_min_x: f64,
    pub visible_max_x: f64,
    pub visible_min_y: f64,
    pub visible_max_y: f64,
    pub selected_host: Signal<Option<String>>,
    pub hovered_host: Signal<Option<String>>,
    pub on_select_host: EventHandler<String>,
}

/// Pure SVG canvas that renders the topology: subnet groups, edges, and nodes,
/// with zoom/pan transforms applied to the root `<svg>` element.
#[component]
pub fn SvgCanvas(props: SvgCanvasProps) -> Element {
    rsx! {
        svg {
            class: "w-full h-full",
            view_box: "0 0 {props.layout_width} {props.layout_height}",
            style: "transform: scale({props.zoom}) translate({props.pan_x}px, {props.pan_y}px); \
                    transform-origin: 0 0; transition: {props.transition_style}; \
                    cursor: {props.cursor_style};",

            style {
                key: "canvas-style",
                r#type: "text/css",
                "@keyframes fadeIn {{ from {{ opacity: 0; transform: scale(0.3); }} to {{ opacity: 1; transform: scale(1); }} }}"
            }

            {(props.cluster_mode).then(|| {
                let groups = &props.subnet_groups;
                rsx! {
                    {groups.iter().map(|sg| {
                        rsx! {
                            g {
                                key: "subnet-{sg.subnet}",
                                rect {
                                    x: "{sg.min_x}", y: "{sg.min_y}",
                                    width: "{sg.width}", height: "{sg.height}",
                                    rx: "8", ry: "8",
                                    style: "fill: rgba(128,128,128,0.05); stroke: rgba(128,128,128,0.3); stroke-dasharray: 4 4; stroke-width: 1;",
                                }
                                text {
                                    x: "{sg.min_x + 8.0}", y: "{sg.min_y + 14.0}",
                                    style: "fill: var(--color-text-muted); font-size: 10px; font-family: monospace;",
                                    "{sg.subnet}"
                                }
                            }
                        }
                    })}
                }
            })}

            {render_edges(
                &props.edges, &props.nodes, &props.connected_ids,
                props.has_selection, &props.dim_opacity, &props.color_primary,
            )}

            {render_nodes(
                &props.nodes,
                &props.selected_ip, &props.hovered_ip,
                &props.connected_ids, props.has_selection,
                &props.dim_opacity, &props.hover_opacity,
                &props.color_critical, &props.color_high, &props.color_medium,
                &props.color_low, &props.color_unknown, &props.color_primary,
                props.cluster_mode, props.show_labels,
                props.use_culling,
                props.visible_min_x, props.visible_max_x, props.visible_min_y, props.visible_max_y,
                props.selected_host,
                props.hovered_host,
                props.on_select_host,
            )}
        }
    }
}
