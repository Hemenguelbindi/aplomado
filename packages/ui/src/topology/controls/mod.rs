//! Панель фильтров и управления топологией.
//!
//! Собирает все логические секции (поиск, раскладка, severity, ОС, порты,
//! опции отображения, легенда, сброс) в единое collapsible-окно.

use dioxus::prelude::*;

use crate::models::HostInfo;
use crate::topology::state::use_topology_context;

mod sections;
use sections::{
    compute_os_values, compute_present_severities, compute_service_counts, render_layout_selector,
    render_legend, render_os_filter, render_port_filter, render_reset_buttons,
    render_search_filter, render_severity_filter, render_view_options,
};

#[derive(Props, Clone, PartialEq)]
pub struct TopologyControlsProps {
    pub hosts: Vec<HostInfo>,
    pub on_reset_view: EventHandler<()>,
}

#[component]
pub fn TopologyControls(props: TopologyControlsProps) -> Element {
    let ctx = use_topology_context();
    let collapsed = (ctx.controls_collapsed)();
    let mut collapsed_state = ctx.controls_collapsed;

    // Compute derived data
    let os_values = compute_os_values(&props.hosts);
    let present_severities = compute_present_severities(&props.hosts);
    let all_service_counts = compute_service_counts(&props.hosts);
    let has_extra_services = all_service_counts.len() > 10;
    let display_services: Vec<String> = all_service_counts
        .iter()
        .take(10)
        .map(|(n, _)| n.clone())
        .collect();

    rsx! {
        div {
            style: "position: absolute; top: 8px; left: 8px; z-index: 30; \
                    background: var(--color-surface); border: 1px solid var(--color-border); \
                    border-radius: 8px; font-size: 12px; \
                    box-shadow: 0 2px 8px rgba(0,0,0,0.15);",

            // Toggle button
            button {
                style: "display: flex; align-items: center; gap: 4px; padding: 6px 10px; \
                        background: none; border: none; color: var(--color-text-secondary); \
                        cursor: pointer; font-size: 12px; width: 100%; \
                        border-bottom: 1px solid var(--color-border); border-radius: 8px 8px 0 0;",
                onclick: move |_| { collapsed_state.set(!collapsed_state()); },
                span { style: "font-size: 14px;", if collapsed { "▶" } else { "▼" } }
                "Фильтры"
            }

            if !collapsed {
                div {
                    style: "padding: 10px; max-height: 520px; overflow-y: auto; width: 230px;",

                    // Sections
                    {render_search_filter(ctx.search_query)}

                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    {render_layout_selector(ctx.layout_type)}

                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    {render_severity_filter(ctx.filter_severity)}

                    {render_os_filter(ctx.filter_os, os_values)}

                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    {render_port_filter(
                        ctx.port_filter_enabled,
                        ctx.filter_services,
                        ctx.only_cve,
                        display_services,
                        has_extra_services,
                    )}

                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    {render_view_options(ctx.show_labels, ctx.cluster_mode, ctx.size_mode)}

                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    {render_legend(present_severities)}

                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    {render_reset_buttons(
                        props.on_reset_view,
                        ctx.filter_severity,
                        ctx.filter_os,
                        ctx.search_query,
                        ctx.filter_services,
                        ctx.only_cve,
                    )}
                }
            }
        }
    }
}
