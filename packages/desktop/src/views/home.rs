use dioxus::prelude::*;
use ui::{models::HostInfo, HomeView, ScanStatusUi};

#[component]
pub fn Home() -> Element {
    let scan_results = use_context::<Signal<Vec<HostInfo>>>();
    let scan_status = use_context::<Signal<ScanStatusUi>>();

    rsx! {
        HomeView {
            results: scan_results(),
            scan_status: scan_status(),
        }
    }
}
