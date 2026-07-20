mod host_detail;
mod tab_cve;
mod tab_notes;
mod tab_overview;
mod tab_ports;
mod tab_services;
mod table_row;
mod table_view;
mod types;

pub use host_detail::HostDetailPanel;
pub use table_view::TableView;
pub use types::{MapViewMode, NetworkMapProps};

use crate::components::{Button, ButtonVariant, EmptyState, Icon, IconName, IconSize};
use crate::topology::component::TopologyView as TopologyCanvas;
use dioxus::prelude::*;

#[component]
pub fn NetworkMap(props: NetworkMapProps) -> Element {
    let alive_hosts: Vec<crate::models::HostInfo> =
        props.hosts.iter().filter(|h| h.alive).cloned().collect();
    let dead_count = props.hosts.len().saturating_sub(alive_hosts.len());

    if alive_hosts.is_empty() {
        return rsx! {
            EmptyState {
                title: "Нет данных",
                description: "Запустите сканирование.",
            }
        };
    }

    let is_table = props.view_mode == MapViewMode::Table;
    let is_topo = props.view_mode == MapViewMode::Topology;

    rsx! {
        div { class: "space-y-2",
            div { class: "flex items-center justify-between",
                h2 { class: "text-lg font-semibold text-foreground",
                    "Карта сети: {alive_hosts.len()}"
                    if dead_count > 0 {
                        span { class: "text-sm ml-2 text-muted-foreground", "(+{dead_count} недоступны)" }
                    }
                }
                div { class: "flex gap-2",
                    Button {
                        variant: if is_table { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| props.on_change_view.call(MapViewMode::Table),
                        Icon { name: IconName::List, size: IconSize::Sm }
                        " Таблица"
                    }
                    Button {
                        variant: if is_topo { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                        onclick: move |_| props.on_change_view.call(MapViewMode::Topology),
                        Icon { name: IconName::Network, size: IconSize::Sm }
                        " Топология"
                    }
                }
            }
            match props.view_mode {
                MapViewMode::Table => rsx! {
                    TableView { hosts: alive_hosts.clone(), on_select_host: props.on_select_host, selected_host: props.selected_host.clone() }
                },
                MapViewMode::Topology => rsx! {
                    TopologyCanvas { hosts: alive_hosts.clone(), on_select_host: props.on_select_host }
                },
            }
        }
    }
}
