use dioxus::prelude::*;
use std::collections::HashSet;
use crate::topology::layout::{LayoutEdge, LayoutNode};

/// Render SVG lines for all edges between nodes.
pub fn render_edges<'a>(
    edges: &'a [LayoutEdge],
    nodes: &'a [LayoutNode],
    connected_ids: &'a HashSet<String>,
    has_selection: bool,
    dim_opacity: &'a str,
    color_primary: &'a str,
) -> Element {
    rsx! {
        {edges.iter().map(|edge| {
            let from = nodes.iter().find(|n| n.id == edge.from);
            let to = nodes.iter().find(|n| n.id == edge.to);
            if let (Some(f), Some(t)) = (from, to) {
                let is_highlighted = has_selection
                    && connected_ids.contains(&edge.from)
                    && connected_ids.contains(&edge.to);
                let stroke = if is_highlighted {
                    color_primary.to_string()
                } else {
                    "rgba(88,166,255,0.6)".to_string()
                };
                let opacity = if has_selection && !is_highlighted {
                    dim_opacity
                } else {
                    "0.8"
                };
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
    }
}
