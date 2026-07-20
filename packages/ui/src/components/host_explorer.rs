use crate::components::{
    Button, ButtonSize, ButtonVariant, EmptyState, HostDetailsDrawer, Icon, IconName, IconSize,
};
use crate::models::HostInfo;
use crate::{MapViewMode, NetworkMap, ScanStatusUi};
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HostExplorerProps {
    pub hosts: Vec<HostInfo>,
    #[props(optional)]
    pub scan_status: Option<ScanStatusUi>,
}

#[component]
pub fn HostExplorer(props: HostExplorerProps) -> Element {
    let mut view_mode = use_signal(|| MapViewMode::Table);
    let mut selected_host: Signal<Option<String>> = use_signal(|| None);
    let count = props.hosts.len();

    let alive_count = props.hosts.iter().filter(|h| h.alive).count();
    let dead_count = count - alive_count;

    let selected_host_info = selected_host().as_ref().and_then(|sel_ip| {
        props
            .hosts
            .iter()
            .find(|h| h.ip.to_string() == *sel_ip)
            .cloned()
    });

    rsx! {
        div { class: "space-y-4",
            if let Some(ref status) = props.scan_status {
                match status {
                    ScanStatusUi::Scanning { current, total } => {
                        let pct = if *total > 0 { (*current as f64 / *total as f64) * 100.0 } else { 0.0 };
                        rsx! {
                            div { class: "mb-4 p-4 border rounded-lg bg-surface border-border",
                                div { class: "flex items-center gap-2 mb-2",
                                    span { class: "w-2 h-2 rounded-full bg-warning animate-pulse" }
                                    span { class: "text-sm font-semibold text-warning", "Идёт сканирование..." }
                                    span { class: "text-sm text-muted-foreground", "({current}/{total} хостов)" }
                                }
                                crate::components::ProgressBar { value: pct, animated: true }
                            }
                        }
                    }
                    _ => rsx! {}
                }
            }

            div { class: "flex items-center justify-between flex-wrap gap-3",
                div { class: "flex items-center gap-3",
                    h2 { class: "text-lg font-semibold text-foreground", "Результаты ({count})" }
                    if alive_count > 0 {
                        span { class: "text-sm text-success", "{alive_count} alive" }
                    }
                    if dead_count > 0 {
                        span { class: "text-sm text-muted-foreground", "{dead_count} down" }
                    }
                }
                div { class: "flex items-center gap-2",
                    Button {
                        variant: if view_mode() == MapViewMode::Table { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        size: ButtonSize::Sm,
                        onclick: move |_| view_mode.set(MapViewMode::Table),
                        Icon { name: IconName::List, size: IconSize::Sm }
                        " Table"
                    }
                    Button {
                        variant: if view_mode() == MapViewMode::Topology { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        size: ButtonSize::Sm,
                        onclick: move |_| view_mode.set(MapViewMode::Topology),
                        Icon { name: IconName::Network, size: IconSize::Sm }
                        " Topology"
                    }
                }
            }

            if count == 0 {
                EmptyState { title: "Нет данных сканирования", description: "Перейдите в раздел \"Сканер\" чтобы запустить сканирование сети." }
            } else {
                NetworkMap {
                    key: "host-map-{count}",
                    hosts: props.hosts.clone(),
                    view_mode: view_mode(),
                    selected_host: selected_host(),
                    on_select_host: move |ip: String| {
                        let current = selected_host();
                        if current.as_deref() == Some(&ip) {
                            selected_host.set(None);
                        } else {
                            selected_host.set(Some(ip));
                        }
                    },
                    on_change_view: move |mode| view_mode.set(mode),
                }
            }
        }
        HostDetailsDrawer { host: selected_host_info, on_close: move |_| selected_host.set(None) }
    }
}
