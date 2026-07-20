use crate::topology::layout::LayoutNode;
use dioxus::prelude::*;

/// Render SVG text labels for all visible nodes.
///
/// Can be used independently when labels are rendered outside node groups,
/// or left unused when labels are embedded inside `render_nodes`.
pub fn render_labels(nodes: &[LayoutNode], show_labels: bool) -> Element {
    if !show_labels {
        return rsx! {};
    }
    rsx! {
        {nodes.iter().map(|node| {
            rsx! {
                text {
                    key: "label-{node.id}",
                    x: "{node.x + node.radius + 4.0}",
                    y: "{node.y + 3.0}",
                    style: "fill: var(--color-text-secondary); font-size: 11px; font-family: monospace;",
                    "{node.label}"
                }
            }
        })}
    }
}
