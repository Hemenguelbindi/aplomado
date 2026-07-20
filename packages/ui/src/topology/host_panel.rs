use crate::components::host_panel::{HostBadges, PanelHeader, PortList};
use crate::models::HostInfo;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HostDetailPanelProps {
    pub host: Option<HostInfo>,
    pub on_close: EventHandler<()>,
}

#[component]
pub fn HostDetailPanel(props: HostDetailPanelProps) -> Element {
    let visible = props.host.is_some();

    let transform = if visible {
        "translateX(0)"
    } else {
        "translateX(100%)"
    };

    rsx! {
        div {
            style: "position: absolute; top: 0; right: 0; width: 380px; height: 100%; \
                    background: var(--color-surface); border-left: 1px solid var(--color-border); \
                    transform: {transform}; transition: transform 0.3s ease; z-index: 40; \
                    overflow-y: auto; box-shadow: -4px 0 16px rgba(0,0,0,0.2);",

            if let Some(ref host) = props.host {
                {rsx! {
                    PanelHeader {
                        ip: host.ip.clone(),
                        hostname: host.hostname.clone(),
                        on_close: move |_| props.on_close.call(()),
                    }
                    HostBadges {
                        os_guess: host.os_guess.clone(),
                        ttl: host.ttl,
                        alive: host.alive,
                    }
                    PortList { ports: host.ports.clone() }
                }}
            }
        }
    }
}
