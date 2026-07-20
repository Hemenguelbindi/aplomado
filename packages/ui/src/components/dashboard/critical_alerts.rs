use super::types::CriticalVulnItem;
use crate::components::{Badge, BadgeVariant, Card};
use dioxus::prelude::*;

#[component]
pub fn CriticalAlertsCard(vulns: Vec<CriticalVulnItem>) -> Element {
    rsx! {
        Card {
            title: "Критические уведомления",
            if vulns.is_empty() {
                div { class: "text-center py-4",
                    p { class: "text-sm text-muted-foreground", "Нет критических уязвимостей" }
                }
            } else {
                div { class: "space-y-3 max-h-64 overflow-y-auto",
                    for item in vulns.iter().take(10) {
                        div {
                            class: "flex items-center justify-between p-2 rounded bg-input-bg",
                            div { class: "flex items-center gap-2",
                                Badge {
                                    variant: if item.severity.to_lowercase() == "critical" { BadgeVariant::Error } else { BadgeVariant::Warning },
                                    "{item.severity}"
                                }
                                div {
                                    p { class: "text-sm font-mono font-medium text-foreground", "{item.cve_id}" }
                                    p { class: "text-xs text-muted-foreground",
                                        "{item.host_ip}:{item.port} \u{00B7} CVSS {item.cvss_score}"
                                    }
                                }
                            }
                        }
                    }
                    if vulns.len() > 10 {
                        p { class: "text-xs text-center mt-2 text-muted-foreground",
                            "и ещё {vulns.len() - 10} уязвимостей..."
                        }
                    }
                }
            }
        }
    }
}
