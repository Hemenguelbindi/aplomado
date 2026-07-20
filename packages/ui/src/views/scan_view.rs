use crate::components::ScanWorkspace;
use crate::models::{HostInfo, Session};
use crate::{ScanConfigUi, ScanStatusUi};
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
    rsx! {
        ScanWorkspace {
            session: props.session.clone(),
            status: props.status.clone(),
            results: props.results.clone(),
            on_update_session: move |s: Session| props.on_update_session.call(s),
            on_start_scan: move |cfg: ScanConfigUi| props.on_start_scan.call(cfg),
            on_stop_scan: move |_| props.on_stop_scan.call(()),
            show_new_session: props.show_new_session,
            on_new_session: props.on_new_session,
        }
    }
}
