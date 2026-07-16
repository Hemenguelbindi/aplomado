use crate::{HostDetailPanel, MapViewMode, NetworkMap, ScanForm, ScanConfigUi, ScanStatusUi};
use crate::components::{Button, ButtonVariant};
use crate::models::{HostInfo, Session};
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct ScanViewProps {
    pub session: Session,
    pub status: ScanStatusUi,
    pub results: Vec<HostInfo>,
    pub on_update_session: EventHandler<Session>,
    pub on_start_scan: EventHandler<ScanConfigUi>,
    pub on_stop_scan: EventHandler<()>,
    #[props(optional)]
    pub show_new_session: bool,
    #[props(optional)]
    pub on_new_session: Option<EventHandler<()>>,
}

#[component]
pub fn ScanView(props: ScanViewProps) -> Element {
    let targets_len = props.session.targets.len();
    let session_id = props.session.id.clone();
    let mut view_mode = use_signal(|| MapViewMode::Table);
    let mut selected_host: Signal<Option<String>> = use_signal(|| None);

    rsx! {
        div { class: "p-8 max-w-6xl mx-auto",

            ScanForm {
                session: props.session.clone(),
                status: props.status.clone(),
                on_update_session: move |s: Session| props.on_update_session.call(s),
                on_start_scan: move |cfg: ScanConfigUi| props.on_start_scan.call(cfg),
                on_stop_scan: move |_| props.on_stop_scan.call(()),
            }

            if props.show_new_session {
                div { class: "mt-2",
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: "text-sm",
                        onclick: move |_| {
                            if let Some(ref handler) = props.on_new_session {
                                handler.call(());
                            }
                        },
                        "Новая сессия"
                    }
                }
            }

            div { class: "mt-6",
                NetworkMap {
                    key: "scan-map-{session_id}-{targets_len}",
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
