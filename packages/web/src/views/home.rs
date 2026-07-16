use dioxus::prelude::*;
use ui::HomeView;
use ui::models::HostInfo;
use ui::ScanStatusUi;

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
