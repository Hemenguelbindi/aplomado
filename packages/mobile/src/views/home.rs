use dioxus::prelude::*;
use ui::{models::HostInfo, HostDetailPanel, MapViewMode, NetworkMap};

#[component]
pub fn Home() -> Element {
    let scan_results = use_context::<Signal<Vec<HostInfo>>>();
    let results = scan_results();
    let has_data = !results.is_empty();
    let mut view_mode = use_signal(|| MapViewMode::Table);
    let mut selected_host: Signal<Option<String>> = use_signal(|| None);

    let results_count = results.len();

    rsx! {
        div { class: "p-8",
            h1 { class: "text-2xl font-bold text-white mb-6", "Обзор" }

            if !has_data {
                div { class: "text-center text-gray-500 py-12",
                    p { class: "text-lg mb-2", "Нет данных сканирования" }
                    p { class: "text-sm", "Перейдите в раздел \"Сканер\" чтобы запустить сканирование сети." }
                }
            }

            NetworkMap {
                key: "home-map-{results_count}",
                hosts: results,
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
                if let Some(host) = scan_results().iter().find(|h| h.ip.to_string() == *sel_ip) {
                    HostDetailPanel {
                        host: host.clone(),
                        on_close: move |_| selected_host.set(None),
                    }
                }
            }
        }
    }
}
