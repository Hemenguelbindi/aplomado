use super::types::{count_cves, cve_badge_color, cve_badge_text};
use crate::components::{Icon, IconName, IconSize};
use crate::models::HostInfo;
use dioxus::prelude::*;

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
        host.ports
            .iter()
            .map(|p| p.port.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let cve_stats = count_cves(host);
    let cve_str = cve_badge_text(&cve_stats);
    let cve_color = cve_badge_color(&cve_stats);
    let alive_cls = if host.alive { "" } else { "opacity-40" };
    let sel_bg = if props.selected {
        "bg-surface-muted"
    } else {
        ""
    };
    let ip_clone = ip.clone();

    rsx! {
        tr {
            key: "{ip}",
            class: "border-b border-border cursor-pointer {alive_cls} {sel_bg} hover:bg-surface-muted/30",
            onclick: move |_| props.on_select.call(ip_clone.clone()),
            td { class: "py-2 px-3 font-mono text-foreground", "{ip}" }
            td { class: "py-2 px-3 text-muted-foreground", "{hostname}" }
            td { class: "py-2 px-3 text-muted-foreground", "{os}" }
            td { class: "py-2 px-3 font-mono text-xs text-muted-foreground",
                style: "word-break: break-all; overflow-wrap: break-word; max-width: 200px",
                "{ports_str}"
            }
            td { class: "py-2 px-3 text-xs font-mono",
                span { style: "color: {cve_color}", "{cve_str}" }
            }
            td { class: "py-2 px-3",
                span {
                    class: "text-xs px-1.5 py-0.5 rounded cursor-pointer select-all text-muted-foreground",
                    title: "IP для копирования",
                    onclick: move |e: Event<MouseData>| e.stop_propagation(),
                    Icon { name: IconName::Copy, size: IconSize::Sm }
                    " {ip}"
                }
            }
        }
    }
}
