use dioxus::prelude::*;
use crate::models::HostInfo;
use crate::topology::graph::NodeSeverity;
use crate::topology::state::{LayoutType, SizeMode, use_topology_context};

#[derive(Props, Clone, PartialEq)]
pub struct TopologyControlsProps {
    pub hosts: Vec<HostInfo>,
    pub on_reset_view: EventHandler<()>,
}

#[component]
pub fn TopologyControls(props: TopologyControlsProps) -> Element {
    let mut ctx = use_topology_context();
    let collapsed = (ctx.controls_collapsed)();

    // Collect unique OS values
    let os_values: Vec<String> = {
        let mut set = std::collections::HashSet::new();
        for h in props.hosts.iter() {
            if let Some(ref os) = h.os_guess {
                set.insert(os.clone());
            }
        }
        let mut v: Vec<String> = set.into_iter().collect();
        v.sort();
        v
    };

    // Collect present severities from alive hosts
    let present_severities: Vec<NodeSeverity> = {
        let mut set = std::collections::HashSet::new();
        for h in props.hosts.iter().filter(|h| h.alive) {
            let crit_ports = [22, 23, 135, 139, 445, 3389, 3306, 5432, 6379, 27017];
            let has_crit = h.ports.iter().any(|p| crit_ports.contains(&p.port));
            let sev = if has_crit {
                NodeSeverity::High
            } else if h.ports.is_empty() {
                NodeSeverity::Low
            } else {
                NodeSeverity::Medium
            };
            set.insert(sev);
        }
        set.into_iter().collect()
    };

    let severity_colors = |s: &NodeSeverity| -> &'static str {
        match s {
            NodeSeverity::Critical => "var(--color-severity-critical)",
            NodeSeverity::High => "var(--color-severity-high)",
            NodeSeverity::Medium => "var(--color-severity-medium)",
            NodeSeverity::Low => "var(--color-severity-low)",
            NodeSeverity::Unknown => "var(--color-severity-unknown)",
        }
    };

    let severity_label = |s: &NodeSeverity| -> &'static str {
        match s {
            NodeSeverity::Critical => "Critical",
            NodeSeverity::High => "High",
            NodeSeverity::Medium => "Medium",
            NodeSeverity::Low => "Low",
            NodeSeverity::Unknown => "Unknown",
        }
    };

    // Collect unique service names with counts for port filter chips
    let all_service_counts: Vec<(String, usize)> = {
        let mut counts = std::collections::HashMap::new();
        for h in props.hosts.iter() {
            for p in &h.ports {
                *counts.entry(p.service_name.clone()).or_insert(0usize) += 1;
            }
        }
        let mut v: Vec<(String, usize)> = counts.into_iter().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1));
        v
    };
    let has_extra_services = all_service_counts.len() > 10;
    let display_services: Vec<&str> = all_service_counts.iter().take(10).map(|(n, _)| n.as_str()).collect();

    let all_severities = [
        NodeSeverity::Critical,
        NodeSeverity::High,
        NodeSeverity::Medium,
        NodeSeverity::Low,
        NodeSeverity::Unknown,
    ];

    // Toggle collapse
    let mut collapsed_state = ctx.controls_collapsed;

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

                    // ─── Search ───
                    div {
                        style: "margin-bottom: 10px;",
                        div {
                            style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 3px; font-weight: 600;",
                            "Поиск"
                        }
                        div {
                            style: "display: flex; gap: 4px;",
                            input {
                                r#type: "text",
                                style: "flex: 1; padding: 4px 8px; border-radius: 4px; border: 1px solid var(--color-border); \
                                        background: var(--color-bg); color: var(--color-text-primary); font-size: 12px; outline: none;",
                                placeholder: "IP или хостнейм...",
                                value: "{(ctx.search_query)()}",
                                oninput: move |e: Event<FormData>| { ctx.search_query.set(e.value()); },
                            }
                            if !(ctx.search_query)().is_empty() {
                                button {
                                    style: "padding: 4px 6px; background: none; border: 1px solid var(--color-border); \
                                            border-radius: 4px; color: var(--color-text-muted); cursor: pointer; font-size: 12px;",
                                    onclick: move |_| { ctx.search_query.set(String::new()); },
                                    "×"
                                }
                            }
                        }
                    }

                    // ─── Divider ───
                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    // ─── Layout Type ───
                    div {
                        style: "margin-bottom: 10px;",
                        div {
                            style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600;",
                            "Раскладка"
                        }
                        div {
                            style: "display: flex; gap: 3px;",
                            {[
                                (LayoutType::Force, "Force"),
                                (LayoutType::Circular, "Circle"),
                                (LayoutType::Hierarchical, "Tree"),
                            ].iter().map(|(lt, label)| {
                                let is_active = (ctx.layout_type)() == *lt;
                                let lt_clone = *lt;
                                let mut layout_signal = ctx.layout_type;
                                let btn_style = if is_active {
                                    "background: var(--color-primary); color: white; border-color: var(--color-primary);"
                                } else {
                                    "background: transparent; color: var(--color-text-muted); border-color: var(--color-border);"
                                };
                                rsx! {
                                    button {
                                        key: "{label}",
                                        style: "flex: 1; padding: 4px 6px; border-radius: 4px; font-size: 11px; \
                                                cursor: pointer; transition: all 0.15s; border: 1px solid; {btn_style}",
                                        onclick: move |_| { layout_signal.set(lt_clone); },
                                        "{label}"
                                    }
                                }
                            })}
                        }
                    }

                    // ─── Divider ───
                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    // ─── Severity Filter ───
                    div {
                        style: "margin-bottom: 10px;",
                        div {
                            style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600; \
                                    display: flex; justify-content: space-between; align-items: center;",
                            span { "Severity" }
                            if !(ctx.filter_severity)().is_empty() {
                                button {
                                    style: "background: none; border: none; color: var(--color-primary); \
                                            cursor: pointer; font-size: 10px; padding: 0;",
                                    onclick: move |_| { ctx.filter_severity.set(Vec::new()); },
                                    "All"
                                }
                            }
                        }
                        div {
                            style: "display: flex; gap: 3px; flex-wrap: wrap;",
                            {all_severities.iter().map(|sev| {
                                let is_active = (ctx.filter_severity)().contains(sev);
                                let color = severity_colors(sev);
                                let label = severity_label(sev);
                                let sev_clone = sev.clone();
                                let mut filter_signal = ctx.filter_severity;
                                let chip_style = if is_active {
                                    format!("background: {color}; color: white; border: 1px solid {color};")
                                } else {
                                    "background: transparent; color: var(--color-text-muted); border: 1px solid var(--color-border);".to_string()
                                };
                                rsx! {
                                    button {
                                        key: "{label}",
                                        style: "padding: 2px 8px; border-radius: 4px; font-size: 10px; \
                                                cursor: pointer; transition: all 0.15s; {chip_style}",
                                        onclick: move |_| {
                                            let mut current = filter_signal();
                                            if let Some(pos) = current.iter().position(|s| s == &sev_clone) {
                                                current.remove(pos);
                                            } else {
                                                current.push(sev_clone.clone());
                                            }
                                            filter_signal.set(current);
                                        },
                                        "{label}"
                                    }
                                }
                            })}
                        }
                    }

                    // ─── OS Filter ───
                    if !os_values.is_empty() {
                        div {
                            style: "margin-bottom: 10px;",
                            div {
                                style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600; \
                                        display: flex; justify-content: space-between; align-items: center;",
                                span { "ОС" }
                                if !(ctx.filter_os)().is_empty() {
                                    button {
                                        style: "background: none; border: none; color: var(--color-primary); \
                                                cursor: pointer; font-size: 10px; padding: 0;",
                                        onclick: move |_| { ctx.filter_os.set(Vec::new()); },
                                        "All"
                                    }
                                }
                            }
                            div {
                                style: "display: flex; gap: 3px; flex-wrap: wrap;",
                                {os_values.iter().map(|os| {
                                    let is_active = (ctx.filter_os)().contains(os);
                                    let os_clone = os.clone();
                                    let mut os_signal = ctx.filter_os;
                                    let chip_style = if is_active {
                                        "background: var(--color-primary); color: white; border: 1px solid var(--color-primary);".to_string()
                                    } else {
                                        "background: transparent; color: var(--color-text-muted); border: 1px solid var(--color-border);".to_string()
                                    };
                                    rsx! {
                                        button {
                                            key: "{os}",
                                            style: "padding: 2px 8px; border-radius: 4px; font-size: 10px; \
                                                    cursor: pointer; transition: all 0.15s; {chip_style}",
                                            onclick: move |_| {
                                                let mut current = os_signal();
                                                if let Some(pos) = current.iter().position(|s| s == &os_clone) {
                                                    current.remove(pos);
                                                } else {
                                                    current.push(os_clone.clone());
                                                }
                                                os_signal.set(current);
                                            },
                                            "{os}"
                                        }
                                    }
                                })}
                            }
                        }
                    }

                    // ─── Divider ───
                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    // ─── Port / Service Filter ───
                    div {
                        style: "margin-bottom: 10px;",
                        div {
                            style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600; \
                                    display: flex; justify-content: space-between; align-items: center;",
                            span { "Порты" }
                            if !(ctx.filter_services)().is_empty() {
                                button {
                                    style: "background: none; border: none; color: var(--color-primary); \
                                            cursor: pointer; font-size: 10px; padding: 0;",
                                    onclick: move |_| { ctx.filter_services.set(Vec::new()); },
                                    "All"
                                }
                            }
                        }

                        {
                            let enabled = (ctx.port_filter_enabled)();
                            let mut signal = ctx.port_filter_enabled;
                            rsx! {
                                label {
                                    style: "display: flex; align-items: center; gap: 6px; cursor: pointer; \
                                            color: var(--color-text-secondary); font-size: 11px; margin-bottom: 6px;",
                                    input {
                                        r#type: "checkbox",
                                        checked: "{enabled}",
                                        onchange: move |_| { signal.set(!signal()); },
                                        style: "accent-color: var(--color-primary);",
                                    }
                                    "Фильтр портов"
                                }
                            }
                        }

                        {
                            let port_filter_enabled = (ctx.port_filter_enabled)();
                            if port_filter_enabled {
                                rsx! {
                                    div {
                                        style: "display: flex; gap: 3px; flex-wrap: wrap;",
                                        {display_services.iter().map(|svc| {
                                            let is_active = (ctx.filter_services)().contains(&svc.to_string());
                                            let svc_str = svc.to_string();
                                            let mut filter_signal = ctx.filter_services;
                                            let chip_style = if is_active {
                                                "background: var(--color-primary); color: white; border: 1px solid var(--color-primary);".to_string()
                                            } else {
                                                "background: transparent; color: var(--color-text-muted); border: 1px solid var(--color-border);".to_string()
                                            };
                                            rsx! {
                                                button {
                                                    key: "{svc_str}",
                                                    style: "padding: 2px 8px; border-radius: 4px; font-size: 10px; \
                                                            cursor: pointer; transition: all 0.15s; {chip_style}",
                                                    onclick: move |_| {
                                                        let mut current = filter_signal();
                                                        if let Some(pos) = current.iter().position(|s| s == &svc_str) {
                                                            current.remove(pos);
                                                        } else {
                                                            current.push(svc_str.clone());
                                                        }
                                                        filter_signal.set(current);
                                                    },
                                                    "{svc_str}"
                                                }
                                            }
                                        })}

                                        // "Other" catch-all chip
                                        {if has_extra_services {
                                            let is_other_active = (ctx.filter_services)().contains(&"__other__".to_string());
                                            let mut filter_signal = ctx.filter_services;
                                            let other_style = if is_other_active {
                                                "background: var(--color-primary); color: white; border: 1px solid var(--color-primary);".to_string()
                                            } else {
                                                "background: transparent; color: var(--color-text-muted); border: 1px solid var(--color-border);".to_string()
                                            };
                                            rsx! {
                                                button {
                                                    style: "padding: 2px 8px; border-radius: 4px; font-size: 10px; \
                                                            cursor: pointer; transition: all 0.15s; {other_style}",
                                                    onclick: move |_| {
                                                        let mut current = filter_signal();
                                                        if let Some(pos) = current.iter().position(|s| s == "__other__") {
                                                            current.remove(pos);
                                                        } else {
                                                            current.push("__other__".to_string());
                                                        }
                                                        filter_signal.set(current);
                                                    },
                                                    "Other"
                                                }
                                            }
                                        } else {
                                            rsx! {}
                                        }}
                                    }

                                    div {
                                        style: "margin-top: 6px;",
                                        {
                                            let cve_only = (ctx.only_cve)();
                                            let mut signal = ctx.only_cve;
                                            rsx! {
                                                label {
                                                    style: "display: flex; align-items: center; gap: 6px; cursor: pointer; \
                                                            color: var(--color-text-secondary); font-size: 11px;",
                                                    input {
                                                        r#type: "checkbox",
                                                        checked: "{cve_only}",
                                                        onchange: move |_| { signal.set(!signal()); },
                                                        style: "accent-color: var(--color-primary);",
                                                    }
                                                    "Only CVEs"
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                rsx! {}
                            }
                        }
                    }

                    // ─── Divider ───
                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    // ─── View Options ───
                    div {
                        style: "margin-bottom: 10px;",
                        div {
                            style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600;",
                            "Вид"
                        }

                        // Show labels toggle
                        {
                            let show = (ctx.show_labels)();
                            let mut signal = ctx.show_labels;
                            rsx! {
                                label {
                                    style: "display: flex; align-items: center; gap: 6px; cursor: pointer; \
                                            color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px;",
                                    input {
                                        r#type: "checkbox",
                                        checked: "{show}",
                                        onchange: move |_| { signal.set(!signal()); },
                                        style: "accent-color: var(--color-primary);",
                                    }
                                    "Метки"
                                }
                            }
                        }

                        // Cluster mode toggle
                        {
                            let cluster = (ctx.cluster_mode)();
                            let mut signal = ctx.cluster_mode;
                            rsx! {
                                label {
                                    style: "display: flex; align-items: center; gap: 6px; cursor: pointer; \
                                            color: var(--color-text-secondary); font-size: 11px;",
                                    input {
                                        r#type: "checkbox",
                                        checked: "{cluster}",
                                        onchange: move |_| { signal.set(!signal()); },
                                        style: "accent-color: var(--color-primary);",
                                    }
                                    "Подсети"
                                }
                            }
                        }

                        // Size mode toggle (Auto / Uniform)
                        div {
                            style: "display: flex; gap: 3px; margin-top: 6px;",
                            {[
                                (SizeMode::Auto, "Auto"),
                                (SizeMode::Uniform, "Uniform"),
                            ].iter().map(|(sm, label)| {
                                let is_active = (ctx.size_mode)() == *sm;
                                let sm_clone = *sm;
                                let mut size_signal = ctx.size_mode;
                                let btn_style = if is_active {
                                    "background: var(--color-primary); color: white; border-color: var(--color-primary);"
                                } else {
                                    "background: transparent; color: var(--color-text-muted); border-color: var(--color-border);"
                                };
                                rsx! {
                                    button {
                                        key: "{label}",
                                        style: "flex: 1; padding: 4px 6px; border-radius: 4px; font-size: 11px; \
                                                cursor: pointer; transition: all 0.15s; border: 1px solid; {btn_style}",
                                        onclick: move |_| { size_signal.set(sm_clone); },
                                        "{label}"
                                    }
                                }
                            })}
                        }
                    }

                    // ─── Divider ───
                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    // ─── Legend ───
                    div {
                        style: "margin-bottom: 10px;",
                        div {
                            style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600;",
                            "Легенда"
                        }
                        div {
                            style: "display: flex; flex-wrap: wrap; gap: 6px;",
                            {present_severities.iter().map(|sev| {
                                let color = severity_colors(sev);
                                let label = severity_label(sev);
                                rsx! {
                                    span {
                                        key: "{label}",
                                        style: "display: flex; align-items: center; gap: 3px; font-size: 10px; \
                                                color: var(--color-text-muted);",
                                        span {
                                            style: "width: 8px; height: 8px; border-radius: 2px; background: {color};",
                                        }
                                        "{label}"
                                    }
                                }
                            })}
                            // Route line sample
                            span {
                                style: "display: flex; align-items: center; gap: 3px; font-size: 10px; \
                                        color: var(--color-text-muted);",
                                span {
                                    style: "width: 16px; height: 2px; background: rgba(88,166,255,0.6); border-radius: 1px;",
                                }
                                "Route"
                            }
                        }
                    }

                    // ─── Divider ───
                    div { style: "border-top: 1px solid var(--color-border); margin: 8px 0;" }

                    // ─── Reset ───
                    div {
                        style: "display: flex; gap: 4px;",
                        button {
                            style: "flex: 1; padding: 4px 8px; border-radius: 4px; font-size: 11px; \
                                    background: var(--color-primary); color: white; border: none; \
                                    cursor: pointer; transition: opacity 0.15s;",
                            onclick: move |_| props.on_reset_view.call(()),
                            "Сброс вид"
                        }
                        button {
                            style: "flex: 1; padding: 4px 8px; border-radius: 4px; font-size: 11px; \
                                    background: transparent; color: var(--color-text-muted); \
                                    border: 1px solid var(--color-border); cursor: pointer;",
                            onclick: move |_| {
                                ctx.filter_severity.set(Vec::new());
                                ctx.filter_os.set(Vec::new());
                                ctx.search_query.set(String::new());
                                ctx.filter_services.set(Vec::new());
                                ctx.only_cve.set(false);
                            },
                            "Сброс фильтры"
                        }
                    }
                }
            }
        }
    }
}
