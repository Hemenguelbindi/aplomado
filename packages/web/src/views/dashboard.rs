use dioxus::prelude::*;
use ui::{DashboardView, models::HostInfo, ScanStatusUi};
use aplomado_core::history::ScanRecord;

#[component]
pub fn Dashboard() -> Element {
    let scan_results = use_context::<Signal<Vec<HostInfo>>>();
    let scan_status = use_context::<Signal<ScanStatusUi>>();
    let history = use_context::<Signal<Vec<ScanRecord>>>();
    let navigator = use_navigator();

    rsx! {
        DashboardView {
            hosts: scan_results(),
            history: history(),
            scan_status: scan_status(),
            on_navigate_to_scan: move |_| { navigator.push(crate::Route::Scan {}); },
            on_navigate_to_hosts: move |_| { navigator.push(crate::Route::Home {}); },
            on_navigate_to_history: move |_| { navigator.push(crate::Route::History {}); },
        }
    }
}
