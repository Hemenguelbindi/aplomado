use crate::models::PortInfo;
use crate::components::EmptyState;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct ServicesTabProps {
    pub ports: Vec<PortInfo>,
}

#[component]
pub fn ServicesTab(props: ServicesTabProps) -> Element {
    if props.ports.is_empty() {
        return rsx! {
            EmptyState {
                icon: "🌐",
                title: "Нет сервисов",
            }
        };
    }

    rsx! {
        div { class: "space-y-3",
            {props.ports.iter().map(|p| {
                let ver = p.service_version.as_deref().unwrap_or("");
                let banner = p.banner.as_deref().unwrap_or("");
                let short: String = if banner.len() > 80 {
                    banner.chars().take(80).collect()
                } else {
                    banner.to_string()
                };
                let has_banner = !banner.is_empty();
                rsx! {
                    div {
                        key: "{p.port}",
                        class: "border rounded p-3",
                        style: "background: var(--color-input-bg); border-color: var(--color-input-border)",
                        div { class: "flex items-center justify-between mb-1",
                            span {
                                class: "font-mono text-sm",
                                style: "color: var(--color-text-primary)",
                                "{p.service_name}"
                            }
                            span {
                                class: "text-xs",
                                style: "color: var(--color-text-muted)",
                                ":{p.port}"
                            }
                        }
                        if !ver.is_empty() {
                            div {
                                class: "text-xs mb-1",
                                style: "color: var(--color-text-muted)",
                                "Версия: {ver}"
                            }
                        }
                        if has_banner {
                            div {
                                class: "text-xs font-mono truncate",
                                style: "color: var(--color-text-muted)",
                                title: "{banner}", "Banner: {short}…"
                            }
                        }
                    }
                }
            })}
        }
    }
}
