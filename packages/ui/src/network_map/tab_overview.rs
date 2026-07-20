use super::types::os_icon;
use crate::components::{Icon, IconSize};
use crate::models::HostInfo;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct OverviewTabProps {
    pub host: HostInfo,
}

#[component]
pub fn OverviewTab(props: OverviewTabProps) -> Element {
    let host = &props.host;
    let ip = host.ip.to_string();
    let hostname = host.hostname.as_deref().unwrap_or("\u{2014}");
    let os = host.os_guess.as_deref().unwrap_or("\u{2014}");
    let icon = os_icon(os);

    rsx! {
        div { class: "grid grid-cols-2 gap-4 text-sm",
            div {
                span { class: "text-muted-foreground", "IP: " }
                span { class: "font-mono text-foreground", "{ip}" }
            }
            div {
                span { class: "text-muted-foreground", "Hostname: " }
                span { class: "text-foreground", "{hostname}" }
            }
            div {
                span { class: "text-muted-foreground", "ОС: " }
                span { class: "inline-flex items-center gap-1 text-foreground", Icon { name: icon, size: IconSize::Sm } "{os}" }
            }
            div {
                span { class: "text-muted-foreground", "Статус: " }
                if host.alive {
                    span { class: "text-success", "\u{25CF} Alive" }
                } else {
                    span { class: "text-danger", "\u{25CF} Down" }
                }
            }
        }
    }
}
