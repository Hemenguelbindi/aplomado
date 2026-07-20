use crate::components::HostExplorer;
use crate::models::HostInfo;
use crate::ScanStatusUi;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HomeViewProps {
    pub results: Vec<HostInfo>,
    #[props(optional)]
    pub scan_status: Option<ScanStatusUi>,
}

#[component]
pub fn HomeView(props: HomeViewProps) -> Element {
    rsx! {
        div { class: "p-8",
            h1 { class: "text-2xl font-bold mb-6 text-foreground", "Обзор" }
            HostExplorer {
                hosts: props.results.clone(),
                scan_status: props.scan_status.clone(),
            }
        }
    }
}
