use crate::components::EmptyState;
use crate::models::PortInfo;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct PortsTabProps {
    pub ports: Vec<PortInfo>,
}

fn port_risk(port: &PortInfo) -> (&'static str, &'static str) {
    if port.cves.iter().any(|c| c.severity == "Critical") {
        ("text-severity-critical", "CRIT")
    } else if port.cves.iter().any(|c| c.severity == "High") {
        ("text-severity-high", "HIGH")
    } else if !port.cves.is_empty() {
        ("text-severity-medium", "MED")
    } else {
        ("text-severity-low", "LOW")
    }
}

#[component]
pub fn PortsTab(props: PortsTabProps) -> Element {
    if props.ports.is_empty() {
        return rsx! {
            EmptyState {
                title: "Нет открытых портов",
            }
        };
    }

    rsx! {
        table { class: "w-full text-xs text-left",
            thead {
                tr { class: "text-muted-foreground border-b border-border",
                    th { class: "py-1 px-2", "Порт" }
                    th { class: "py-1 px-2", "Протокол" }
                    th { class: "py-1 px-2", "Сервис" }
                    th { class: "py-1 px-2", "Версия" }
                    th { class: "py-1 px-2", "Риск" }
                }
            }
            tbody {
                {props.ports.iter().map(|p| {
                    let (risk_color, label) = port_risk(p);
                    let ver = p.service_version.as_deref().unwrap_or_default();
                    rsx! {
                        tr { key: "{p.port}", class: "border-b border-border",
                            td { class: "py-1 px-2 font-mono text-foreground", "{p.port}" }
                            td { class: "py-1 px-2 text-muted-foreground", "tcp" }
                            td { class: "py-1 px-2 text-muted-foreground", "{p.service_name}" }
                            td { class: "py-1 px-2 text-muted-foreground", "{ver}" }
                            td { class: "py-1 px-2 font-mono text-[10px] font-bold {risk_color}", "{label}" }
                        }
                    }
                })}
            }
        }
    }
}
