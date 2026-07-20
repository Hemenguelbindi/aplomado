use dioxus::prelude::*;

use super::port_item::PortItem;
use crate::models::PortInfo;

#[component]
pub fn PortList(ports: Vec<PortInfo>) -> Element {
    rsx! {
        div {
            style: "padding: 0 16px 16px;",

            div {
                style: "font-size: 13px; font-weight: 600; color: var(--color-text-primary); \
                        margin-bottom: 8px; padding-bottom: 4px; \
                        border-bottom: 1px solid var(--color-border);",
                "Open Ports ({ports.len()})"
            }

            if ports.is_empty() {
                div {
                    style: "color: var(--color-text-muted); font-size: 12px; \
                            padding: 8px 0;",
                    "Нет открытых портов"
                }
            } else {
                {ports.iter().map(|port| {
                    rsx! { PortItem { port: port.clone() } }
                })}
            }
        }
    }
}
