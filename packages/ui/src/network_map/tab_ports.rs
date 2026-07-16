use crate::models::PortInfo;
use crate::components::EmptyState;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct PortsTabProps {
    pub ports: Vec<PortInfo>,
}

fn port_risk(port: &PortInfo) -> (&'static str, &'static str) {
    if port.cves.iter().any(|c| c.severity == "Critical") {
        ("var(--color-severity-critical)", "CRIT")
    } else if port.cves.iter().any(|c| c.severity == "High") {
        ("var(--color-severity-high)", "HIGH")
    } else if !port.cves.is_empty() {
        ("var(--color-severity-medium)", "MED")
    } else {
        ("var(--color-severity-low)", "LOW")
    }
}

#[component]
pub fn PortsTab(props: PortsTabProps) -> Element {
    if props.ports.is_empty() {
        return rsx! {
            EmptyState {
                icon: "🔌",
                title: "Нет открытых портов",
            }
        };
    }

    rsx! {
        table { class: "w-full text-xs text-left",
            thead {
                tr {
                    style: "color: var(--color-text-muted); border-bottom: 1px solid var(--color-border-light)",
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
                        tr { key: "{p.port}", class: "border-b", style: "border-color: var(--color-border-light)",
                            td {
                                class: "py-1 px-2 font-mono",
                                style: "color: var(--color-text-primary)",
                                "{p.port}"
                            }
                            td {
                                class: "py-1 px-2",
                                style: "color: var(--color-text-muted)",
                                "tcp"
                            }
                            td {
                                class: "py-1 px-2",
                                style: "color: var(--color-text-secondary)",
                                "{p.service_name}"
                            }
                            td {
                                class: "py-1 px-2",
                                style: "color: var(--color-text-secondary)",
                                "{ver}"
                            }
                            td {
                                class: "py-1 px-2 font-mono text-[10px] font-bold",
                                style: "color: {risk_color}",
                                "{label}"
                            }
                        }
                    }
                })}
            }
        }
    }
}
