use crate::models::HostInfo;
use dioxus::prelude::*;
use super::types::{count_cves, cve_badge_color, cve_badge_text};

#[derive(Props, Clone, PartialEq)]
pub struct TableRowProps {
    pub host: HostInfo,
    pub selected: bool,
    pub on_select: EventHandler<String>,
}

#[component]
pub fn TableRow(props: TableRowProps) -> Element {
    let host = &props.host;
    let ip = host.ip.to_string();
    let hostname = host.hostname.clone().unwrap_or_else(|| "—".to_string());
    let os = host.os_guess.clone().unwrap_or_else(|| "—".to_string());
    let ports_str = if host.ports.is_empty() {
        "—".to_string()
    } else {
        host.ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(", ")
    };
    let cve_stats = count_cves(host);
    let cve_str = cve_badge_text(&cve_stats);
    let cve_color = cve_badge_color(&cve_stats);
    let alive_cls = if host.alive { "" } else { "opacity-40" };
    let sel_bg = if props.selected { "var(--color-surface-hover)" } else { "transparent" };
    let ip_clone = ip.clone();

    rsx! {
        tr {
            key: "{ip}",
            class: "border-b cursor-pointer {alive_cls}",
            style: "border-color: var(--color-border); background: {sel_bg}",
            onclick: move |_| props.on_select.call(ip_clone.clone()),
            td {
                class: "py-2 px-3 font-mono",
                style: "color: var(--color-text-primary)",
                "{ip}"
            }
            td {
                class: "py-2 px-3",
                style: "color: var(--color-text-secondary)",
                "{hostname}"
            }
            td {
                class: "py-2 px-3",
                style: "color: var(--color-text-secondary)",
                "{os}"
            }
            td {
                class: "py-2 px-3 font-mono text-xs",
                style: "color: var(--color-text-secondary)",
                "{ports_str}"
            }
            td { class: "py-2 px-3 text-xs font-mono",
                span { style: "color: {cve_color}", "{cve_str}" }
            }
            td { class: "py-2 px-3",
                span {
                    class: "text-xs px-1.5 py-0.5 rounded cursor-pointer select-all",
                    style: "color: var(--color-text-muted)",
                    title: "IP для копирования",
                    onclick: move |e: Event<MouseData>| e.stop_propagation(),
                    "📋 {ip}"
                }
            }
        }
    }
}
