//! Разделённые render-функции панели фильтров топологии.
//! Каждая функция принимает только те сигналы, которые ей нужны,
//! и возвращает Element для встраивания в общий rsx!.

use dioxus::prelude::*;

use crate::models::HostInfo;
use crate::topology::graph::NodeSeverity;
use crate::topology::state::{LayoutType, SizeMode};

const ALL_SEVERITIES: [NodeSeverity; 5] = [
    NodeSeverity::Critical,
    NodeSeverity::High,
    NodeSeverity::Medium,
    NodeSeverity::Low,
    NodeSeverity::Unknown,
];

fn severity_color(s: &NodeSeverity) -> &'static str {
    match s {
        NodeSeverity::Critical => "var(--color-severity-critical)",
        NodeSeverity::High => "var(--color-severity-high)",
        NodeSeverity::Medium => "var(--color-severity-medium)",
        NodeSeverity::Low => "var(--color-severity-low)",
        NodeSeverity::Unknown => "var(--color-severity-unknown)",
    }
}

fn severity_label(s: &NodeSeverity) -> &'static str {
    match s {
        NodeSeverity::Critical => "Critical",
        NodeSeverity::High => "High",
        NodeSeverity::Medium => "Medium",
        NodeSeverity::Low => "Low",
        NodeSeverity::Unknown => "Unknown",
    }
}

fn active_btn_style(is_active: bool) -> &'static str {
    if is_active {
        "background: var(--color-primary); color: white; border-color: var(--color-primary);"
    } else {
        "background: transparent; color: var(--color-text-muted); border-color: var(--color-border);"
    }
}

// ─── Search ─────────────────────────────────────────────────────────────────

pub fn render_search_filter(
    mut search_query: Signal<String>,
) -> Element {
    let has_query = !search_query().is_empty();

    rsx! {
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
                    value: "{search_query()}",
                    oninput: move |e: Event<FormData>| { search_query.set(e.value()); },
                }
                if has_query {
                    button {
                        style: "padding: 4px 6px; background: none; border: 1px solid var(--color-border); \
                                border-radius: 4px; color: var(--color-text-muted); cursor: pointer; font-size: 12px;",
                        onclick: move |_| { search_query.set(String::new()); },
                        "×"
                    }
                }
            }
        }
    }
}

// ─── Layout Type ────────────────────────────────────────────────────────────

pub fn render_layout_selector(
    mut layout_type: Signal<LayoutType>,
) -> Element {
    let current = layout_type();

    rsx! {
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
                ].into_iter().map(|(lt, label)| {
                    let lt_val = lt;
                    let btn_style = active_btn_style(current == lt);
                    rsx! {
                        button {
                            key: "{label}",
                            style: "flex: 1; padding: 4px 6px; border-radius: 4px; font-size: 11px; \
                                    cursor: pointer; transition: all 0.15s; border: 1px solid; {btn_style}",
                            onclick: move |_| { layout_type.set(lt_val); },
                            "{label}"
                        }
                    }
                })}
            }
        }
    }
}

// ─── Severity Filter ────────────────────────────────────────────────────────

pub fn render_severity_filter(
    mut filter_severity: Signal<Vec<NodeSeverity>>,
) -> Element {
    let active = filter_severity();

    rsx! {
        div {
            style: "margin-bottom: 10px;",
            div {
                style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600; \
                        display: flex; justify-content: space-between; align-items: center;",
                span { "Severity" }
                if !active.is_empty() {
                    button {
                        style: "background: none; border: none; color: var(--color-primary); \
                                cursor: pointer; font-size: 10px; padding: 0;",
                        onclick: move |_| { filter_severity.set(Vec::new()); },
                        "All"
                    }
                }
            }
            div {
                style: "display: flex; gap: 3px; flex-wrap: wrap;",
                {ALL_SEVERITIES.iter().map(|sev| {
                    let is_active = active.contains(sev);
                    let color = severity_color(sev);
                    let label = severity_label(sev);
                    let sev_val = sev.clone();
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
                                let mut current = filter_severity();
                                if let Some(pos) = current.iter().position(|s| s == &sev_val) {
                                    current.remove(pos);
                                } else {
                                    current.push(sev_val.clone());
                                }
                                filter_severity.set(current);
                            },
                            "{label}"
                        }
                    }
                })}
            }
        }
    }
}

// ─── OS Filter ──────────────────────────────────────────────────────────────

pub fn render_os_filter(
    mut filter_os: Signal<Vec<String>>,
    os_values: Vec<String>,
) -> Element {
    if os_values.is_empty() {
        return rsx! {};
    }

    let active = filter_os();

    rsx! {
        div {
            style: "margin-bottom: 10px;",
            div {
                style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600; \
                        display: flex; justify-content: space-between; align-items: center;",
                span { "ОС" }
                if !active.is_empty() {
                    button {
                        style: "background: none; border: none; color: var(--color-primary); \
                                cursor: pointer; font-size: 10px; padding: 0;",
                        onclick: move |_| { filter_os.set(Vec::new()); },
                        "All"
                    }
                }
            }
            div {
                style: "display: flex; gap: 3px; flex-wrap: wrap;",
                {os_values.into_iter().map(|os_name| {
                    let is_active = filter_os().contains(&os_name);
                    let chip_style = if is_active {
                        "background: var(--color-primary); color: white; border: 1px solid var(--color-primary);".to_string()
                    } else {
                        "background: transparent; color: var(--color-text-muted); border: 1px solid var(--color-border);".to_string()
                    };
                    rsx! {
                        button {
                            key: "{os_name}",
                            style: "padding: 2px 8px; border-radius: 4px; font-size: 10px; \
                                    cursor: pointer; transition: all 0.15s; {chip_style}",
                            onclick: move |_| {
                                let mut current = filter_os();
                                if let Some(pos) = current.iter().position(|s| s == &os_name) {
                                    current.remove(pos);
                                } else {
                                    current.push(os_name.clone());
                                }
                                filter_os.set(current);
                            },
                            "{os_name}"
                        }
                    }
                })}
            }
        }
    }
}

// ─── Port / Service Filter ──────────────────────────────────────────────────

pub fn render_port_filter(
    mut port_filter_enabled: Signal<bool>,
    mut filter_services: Signal<Vec<String>>,
    mut only_cve: Signal<bool>,
    display_services: Vec<String>,
    has_extra_services: bool,
) -> Element {
    let enabled = port_filter_enabled();

    rsx! {
        div {
            style: "margin-bottom: 10px;",
            div {
                style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600; \
                        display: flex; justify-content: space-between; align-items: center;",
                span { "Порты" }
                if !filter_services().is_empty() {
                    button {
                        style: "background: none; border: none; color: var(--color-primary); \
                                cursor: pointer; font-size: 10px; padding: 0;",
                        onclick: move |_| { filter_services.set(Vec::new()); },
                        "All"
                    }
                }
            }

            label {
                style: "display: flex; align-items: center; gap: 6px; cursor: pointer; \
                        color: var(--color-text-secondary); font-size: 11px; margin-bottom: 6px;",
                input {
                    r#type: "checkbox",
                    checked: "{enabled}",
                    onchange: move |_| { port_filter_enabled.set(!enabled); },
                    style: "accent-color: var(--color-primary);",
                }
                "Фильтр портов"
            }

            if enabled {
                div {
                    style: "display: flex; gap: 3px; flex-wrap: wrap;",
                    {display_services.into_iter().map(|svc_str| {
                        let is_active = filter_services().contains(&svc_str);
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
                                    let mut current = filter_services();
                                    if let Some(pos) = current.iter().position(|s| s == &svc_str) {
                                        current.remove(pos);
                                    } else {
                                        current.push(svc_str.clone());
                                    }
                                    filter_services.set(current);
                                },
                                "{svc_str}"
                            }
                        }
                    })}

                    {if has_extra_services {
                        rsx! {
                            button {
                                style: "padding: 2px 8px; border-radius: 4px; font-size: 10px; \
                                        cursor: pointer; transition: all 0.15s; \
                                        background: transparent; color: var(--color-text-muted); border: 1px solid var(--color-border);",
                                onclick: move |_| {
                                    let mut current = filter_services();
                                    if let Some(pos) = current.iter().position(|s| s == "__other__") {
                                        current.remove(pos);
                                    } else {
                                        current.push("__other__".to_string());
                                    }
                                    filter_services.set(current);
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
                    label {
                        style: "display: flex; align-items: center; gap: 6px; cursor: pointer; \
                                color: var(--color-text-secondary); font-size: 11px;",
                        input {
                            r#type: "checkbox",
                            checked: "{only_cve()}",
                            onchange: move |_| { only_cve.set(!only_cve()); },
                            style: "accent-color: var(--color-primary);",
                        }
                        "Only CVEs"
                    }
                }
            }
        }
    }
}

// ─── View Options ───────────────────────────────────────────────────────────

pub fn render_view_options(
    mut show_labels: Signal<bool>,
    mut cluster_mode: Signal<bool>,
    mut size_mode: Signal<SizeMode>,
) -> Element {
    let current_size = size_mode();

    rsx! {
        div {
            style: "margin-bottom: 10px;",
            div {
                style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600;",
                "Вид"
            }

            label {
                style: "display: flex; align-items: center; gap: 6px; cursor: pointer; \
                        color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px;",
                input {
                    r#type: "checkbox",
                    checked: "{show_labels()}",
                    onchange: move |_| { show_labels.set(!show_labels()); },
                    style: "accent-color: var(--color-primary);",
                }
                "Метки"
            }

            label {
                style: "display: flex; align-items: center; gap: 6px; cursor: pointer; \
                        color: var(--color-text-secondary); font-size: 11px;",
                input {
                    r#type: "checkbox",
                    checked: "{cluster_mode()}",
                    onchange: move |_| { cluster_mode.set(!cluster_mode()); },
                    style: "accent-color: var(--color-primary);",
                }
                "Подсети"
            }

            div {
                style: "display: flex; gap: 3px; margin-top: 6px;",
                {[
                    (SizeMode::Auto, "Auto"),
                    (SizeMode::Uniform, "Uniform"),
                ].into_iter().map(|(sm, label)| {
                    let is_active = current_size == sm;
                    let sm_val = sm;
                    let btn_style = active_btn_style(is_active);
                    rsx! {
                        button {
                            key: "{label}",
                            style: "flex: 1; padding: 4px 6px; border-radius: 4px; font-size: 11px; \
                                    cursor: pointer; transition: all 0.15s; border: 1px solid; {btn_style}",
                            onclick: move |_| { size_mode.set(sm_val); },
                            "{label}"
                        }
                    }
                })}
            }
        }
    }
}

// ─── Legend ─────────────────────────────────────────────────────────────────

pub fn render_legend(
    present_severities: Vec<NodeSeverity>,
) -> Element {
    rsx! {
        div {
            style: "margin-bottom: 10px;",
            div {
                style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px; font-weight: 600;",
                "Легенда"
            }
            div {
                style: "display: flex; flex-wrap: wrap; gap: 6px;",
                {present_severities.into_iter().map(|sev| {
                    let color = severity_color(&sev);
                    let label = severity_label(&sev);
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
    }
}

// ─── Reset Buttons ──────────────────────────────────────────────────────────

pub fn render_reset_buttons(
    on_reset_view: EventHandler<()>,
    mut filter_severity: Signal<Vec<NodeSeverity>>,
    mut filter_os: Signal<Vec<String>>,
    mut search_query: Signal<String>,
    mut filter_services: Signal<Vec<String>>,
    mut only_cve: Signal<bool>,
) -> Element {
    rsx! {
        div {
            style: "display: flex; gap: 4px;",
            button {
                style: "flex: 1; padding: 4px 8px; border-radius: 4px; font-size: 11px; \
                        background: var(--color-primary); color: white; border: none; \
                        cursor: pointer; transition: opacity 0.15s;",
                onclick: move |_| on_reset_view.call(()),
                "Сброс вид"
            }
            button {
                style: "flex: 1; padding: 4px 8px; border-radius: 4px; font-size: 11px; \
                        background: transparent; color: var(--color-text-muted); \
                        border: 1px solid var(--color-border); cursor: pointer;",
                onclick: move |_| {
                    filter_severity.set(Vec::new());
                    filter_os.set(Vec::new());
                    search_query.set(String::new());
                    filter_services.set(Vec::new());
                    only_cve.set(false);
                },
                "Сброс фильтры"
            }
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

pub fn compute_os_values(hosts: &[HostInfo]) -> Vec<String> {
    let mut set = std::collections::HashSet::new();
    for h in hosts.iter() {
        if let Some(ref os) = h.os_guess {
            set.insert(os.clone());
        }
    }
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    v
}

pub fn compute_present_severities(hosts: &[HostInfo]) -> Vec<NodeSeverity> {
    let mut set = std::collections::HashSet::new();
    for h in hosts.iter().filter(|h| h.alive) {
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
}

pub fn compute_service_counts(hosts: &[HostInfo]) -> Vec<(String, usize)> {
    let mut counts = std::collections::HashMap::new();
    for h in hosts.iter() {
        for p in &h.ports {
            *counts.entry(p.service_name.clone()).or_insert(0usize) += 1;
        }
    }
    let mut v: Vec<(String, usize)> = counts.into_iter().collect();
    v.sort_by_key(|b| std::cmp::Reverse(b.1));
    v
}
