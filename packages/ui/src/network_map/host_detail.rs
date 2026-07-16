use dioxus::prelude::*;
use crate::components::{Tabs, TabDef, Badge, BadgeVariant, TextInput};
use super::types::{HostDetailPanelProps, HostDetailTab, count_cves, os_icon, risk_color};
use super::tab_overview::OverviewTab;
use super::tab_ports::PortsTab;
use super::tab_services::ServicesTab;
use super::tab_cve::CveTab;

#[component]
pub fn HostDetailPanel(props: HostDetailPanelProps) -> Element {
    let mut tab = use_signal(|| "Overview".to_string());
    let mut notes = use_signal(String::new);
    let host = &props.host;
    let ip = host.ip.to_string();
    let icon = os_icon(host.os_guess.as_deref().unwrap_or("—"));
    let cve_stats = count_cves(host);
    let risk_cls = risk_color(&cve_stats);
    let ports_count = host.ports.len();
    let cve_count: usize = host.ports.iter().map(|p| p.cves.len()).sum();

    let tabs = vec![
        TabDef { id: "Overview".into(), label: "Overview".into(), icon: None },
        TabDef { id: "Ports".into(), label: format!("Ports ({ports_count})"), icon: None },
        TabDef { id: "Services".into(), label: "Services".into(), icon: None },
        TabDef { id: "Cve".into(), label: format!("CVE ({cve_count})"), icon: None },
        TabDef { id: "Notes".into(), label: "Notes".into(), icon: None },
    ];

    let active_tab = match tab().as_str() {
        "Ports" => HostDetailTab::Ports,
        "Services" => HostDetailTab::Services,
        "Cve" => HostDetailTab::Cve,
        "Notes" => HostDetailTab::Notes,
        _ => HostDetailTab::Overview,
    };

    rsx! {
        div { class: "mt-4 border rounded-lg p-4 {risk_cls}",
            div { class: "flex items-center justify-between mb-3",
                div { class: "flex items-center gap-2",
                    span { class: "text-lg", "{icon}" }
                    h3 {
                        class: "text-lg font-semibold",
                        style: "color: var(--color-text-primary)",
                        "Детали хоста: {ip}"
                    }
                    if !host.alive {
                        Badge { variant: BadgeVariant::Error, "Down" }
                    }
                }
                button {
                    class: "text-sm cursor-pointer",
                    style: "color: var(--color-text-muted)",
                    onclick: move |_| props.on_close.call(()),
                    "✕ Закрыть"
                }
            }
            Tabs {
                tabs: tabs,
                active: tab(),
                on_select: move |id| tab.set(id),
            }
            div { class: "mt-4",
                match active_tab {
                    HostDetailTab::Overview => rsx! { OverviewTab { host: host.clone() } },
                    HostDetailTab::Ports => rsx! { PortsTab { ports: host.ports.clone() } },
                    HostDetailTab::Services => rsx! { ServicesTab { ports: host.ports.clone() } },
                    HostDetailTab::Cve => rsx! { CveTab { host: host.clone() } },
                    HostDetailTab::Notes => rsx! {
                        div { class: "space-y-3",
                            TextInput {
                                value: notes(),
                                placeholder: "Заметки об этом хосте...",
                                class: "h-32 resize-y",
                                oninput: move |e| notes.set(e),
                            }
                            div {
                                class: "text-xs",
                                style: "color: var(--color-text-muted)",
                                "Заметки сохраняются локально в сессии"
                            }
                        }
                    },
                }
            }
        }
    }
}
