use crate::components::{
    Button, ButtonSize, ButtonVariant, HostExplorer, Icon, IconName, IconSize,
};
use crate::models::{HostInfo, Session};
use crate::{ScanConfigUi, ScanForm, ScanStatusUi};
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct ScanWorkspaceProps {
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
pub fn ScanWorkspace(props: ScanWorkspaceProps) -> Element {
    let targets_len = props.session.targets.len();
    let session_id = props.session.id.clone();
    let status_for_explorer = match &props.status {
        ScanStatusUi::Scanning { .. } => Some(props.status.clone()),
        _ => None,
    };

    rsx! {
        div { class: "p-4 sm:p-6 lg:p-8",
            div { class: "flex flex-col lg:flex-row gap-6 max-w-7xl mx-auto",
                div { class: "w-full lg:w-[380px] shrink-0",
                    div { class: "border border-border rounded-lg bg-surface p-4",
                        h2 { class: "flex items-center gap-2 text-lg font-semibold text-foreground mb-4",
                            Icon { name: IconName::Scan, size: IconSize::Md }
                            "Новое сканирование"
                        }
                        ScanForm {
                            session: props.session.clone(),
                            status: props.status.clone(),
                            on_update_session: move |s: Session| props.on_update_session.call(s),
                            on_start_scan: move |cfg: ScanConfigUi| props.on_start_scan.call(cfg),
                            on_stop_scan: move |_| props.on_stop_scan.call(()),
                        }
                        if props.show_new_session {
                            div { class: "mt-3 pt-3 border-t border-border",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    size: ButtonSize::Sm,
                                    onclick: move |_| {
                                        if let Some(ref handler) = props.on_new_session {
                                            handler.call(());
                                        }
                                    },
                                    Icon { name: IconName::Plus, size: IconSize::Sm }
                                    " Новая сессия"
                                }
                            }
                        }
                    }
                }
                div { class: "flex-1 min-w-0",
                    HostExplorer {
                        key: "scan-explorer-{session_id}-{targets_len}",
                        hosts: props.results.clone(),
                        scan_status: status_for_explorer,
                    }
                }
            }
        }
    }
}
