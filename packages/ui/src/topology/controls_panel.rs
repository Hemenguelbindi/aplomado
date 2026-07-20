use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct ControlsPanelProps {
    pub zoom: Signal<f64>,
    pub pan_x: Signal<f64>,
    pub pan_y: Signal<f64>,
    pub use_culling: bool,
    pub node_vis_count: usize,
    pub total_nodes: usize,
    pub showing_filtered: bool,
    pub display_hosts: usize,
    pub total_alive: usize,
}

/// Floating overlay controls: zoom in/out/reset buttons, culling badge, and filtered-info badge.
#[component]
pub fn ControlsPanel(props: ControlsPanelProps) -> Element {
    let mut zoom = props.zoom;
    let mut pan_x = props.pan_x;
    let mut pan_y = props.pan_y;

    rsx! {
        // ─── Zoom buttons ───
        div {
            style: "position: absolute; top: 8px; right: 8px; z-index: 30; display: flex; gap: 4px;",
            button {
                style: "width: 28px; height: 28px; border-radius: 6px; border: 1px solid var(--color-border); \
                        background: var(--color-surface); color: var(--color-text-primary); \
                        font-size: 16px; cursor: pointer; display: flex; align-items: center; \
                        justify-content: center; box-shadow: 0 1px 4px rgba(0,0,0,0.15);",
                onclick: move |_| { zoom.set((zoom() * 1.2).min(5.0)); },
                "+"
            }
            button {
                style: "width: 28px; height: 28px; border-radius: 6px; border: 1px solid var(--color-border); \
                        background: var(--color-surface); color: var(--color-text-primary); \
                        font-size: 16px; cursor: pointer; display: flex; align-items: center; \
                        justify-content: center; box-shadow: 0 1px 4px rgba(0,0,0,0.15);",
                onclick: move |_| { zoom.set((zoom() / 1.2).max(0.1)); },
                "−"
            }
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
        if props.use_culling {
            div {
                style: "position: absolute; bottom: 8px; left: 8px; z-index: 30; \
                        padding: 3px 8px; border-radius: 4px; font-size: 11px; \
                        background: var(--color-surface); border: 1px solid var(--color-border); \
                        color: var(--color-text-muted);",
                "Показано {props.node_vis_count} из {props.total_nodes} узлов"
            }
        }

        // ─── Filtered info badge ───
        if props.showing_filtered {
            div {
                style: "position: absolute; top: 8px; left: 260px; z-index: 25; \
                        padding: 3px 8px; border-radius: 4px; font-size: 11px; \
                        background: var(--color-surface); border: 1px solid var(--color-border); \
                        color: var(--color-text-muted);",
                "Живых: {props.display_hosts} / {props.total_alive}"
            }
        }
    }
}
