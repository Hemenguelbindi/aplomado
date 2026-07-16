use crate::models::HostInfo;
use dioxus::prelude::*;
use super::types::os_icon;

#[derive(Props, Clone, PartialEq)]
pub struct OverviewTabProps {
    pub host: HostInfo,
}

#[component]
pub fn OverviewTab(props: OverviewTabProps) -> Element {
    let host = &props.host;
    let ip = host.ip.to_string();
    let hostname = host.hostname.as_deref().unwrap_or("—");
    let os = host.os_guess.as_deref().unwrap_or("—");
    let icon = os_icon(os);

    rsx! {
        div { class: "grid grid-cols-2 gap-4 text-sm",
            div {
                span { style: "color: var(--color-text-muted)", "IP: " }
                span { class: "font-mono", style: "color: var(--color-text-primary)", "{ip}" }
            }
            div {
                span { style: "color: var(--color-text-muted)", "Hostname: " }
                span { style: "color: var(--color-text-primary)", "{hostname}" }
            }
            div {
                span { style: "color: var(--color-text-muted)", "ОС: " }
                span { style: "color: var(--color-text-primary)", "{icon} {os}" }
            }
            div {
                span { style: "color: var(--color-text-muted)", "Статус: " }
                if host.alive {
                    span { style: "color: var(--color-success)", "● Alive" }
                } else {
                    span { style: "color: var(--color-error)", "● Down" }
                }
            }
        }
    }
}
