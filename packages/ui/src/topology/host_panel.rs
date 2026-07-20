use crate::components::host_panel::{HostBadges, PanelHeader, PortList};
use crate::models::HostInfo;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HostPanelProps {
    pub host: Option<HostInfo>,
    pub on_close: EventHandler<()>,
}

#[component]
pub fn HostPanel(props: HostPanelProps) -> Element {
    rsx! {
        div {
            class: "fixed top-0 right-0 h-full w-80 z-40 bg-surface border-l border-border shadow-lg overflow-y-auto",
            style: "transform: translateX(0); transition: transform 0.2s ease;",
            if let Some(host) = &props.host {
                PanelHeader {
                    ip: host.ip.to_string(),
                    hostname: host.hostname.clone(),
                    on_close: move |_| props.on_close.call(()),
                }
                HostBadges {
                    os_guess: host.os_guess.clone(),
                    ttl: host.ttl,
                    alive: host.alive,
                }
                PortList { ports: host.ports.clone() }
            }
        }
    }
}
