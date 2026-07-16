use crate::{HostDetailPanel, MapViewMode, NetworkMap, ScanStatusUi};
use crate::components::{ProgressBar, EmptyState};
use crate::models::HostInfo;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HomeViewProps {
    pub results: Vec<HostInfo>,
    #[props(optional)]
    pub scan_status: Option<ScanStatusUi>,
}

#[component]
pub fn HomeView(props: HomeViewProps) -> Element {
    let has_data = !props.results.is_empty();
    let results_count = props.results.len();
    let mut view_mode = use_signal(|| MapViewMode::Table);
    let mut selected_host: Signal<Option<String>> = use_signal(|| None);

    rsx! {
        div { class: "p-8",
            h1 {
                class: "text-2xl font-bold mb-6",
                style: "color: var(--color-text-primary)",
                "Обзор"
            }

            if let Some(ref status) = props.scan_status {
                match status {
                    ScanStatusUi::Scanning { current, total } => {
                        let pct = if *total > 0 { (*current as f64 / *total as f64) * 100.0 } else { 0.0 };
                        rsx! {
                            div {
                                class: "mb-4 p-4 border rounded-lg",
                                style: "background: var(--color-surface); border-color: var(--color-border-light)",
                                div { class: "flex items-center gap-2 mb-2",
                                    span {
                                        class: "w-2 h-2 rounded-full",
                                        style: "background: var(--color-warning); animation: pulse 2s infinite"
                                    }
                                    span {
                                        class: "text-sm font-semibold",
                                        style: "color: var(--color-warning)",
                                        "Идёт сканирование..."
                                    }
                                    span {
                                        class: "text-sm",
                                        style: "color: var(--color-text-muted)",
                                        "({current}/{total} хостов)"
                                    }
                                }
                                ProgressBar {
                                    value: pct,
                                    animated: true,
                                }
                            }
                        }
                    }
                    _ => rsx! {}
                }
            }

            if !has_data {
                EmptyState {
                    icon: "📡",
                    title: "Нет данных сканирования",
                    description: "Перейдите в раздел \"Сканер\" чтобы запустить сканирование сети.",
                }
            }

            NetworkMap {
                key: "home-map-{results_count}",
                hosts: props.results.clone(),
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

            if let Some(ref sel_ip) = selected_host() {
                if let Some(host) = props.results.iter().find(|h| h.ip.to_string() == *sel_ip) {
                    HostDetailPanel {
                        host: host.clone(),
                        on_close: move |_| selected_host.set(None),
                    }
                }
            }
        }
    }
}
