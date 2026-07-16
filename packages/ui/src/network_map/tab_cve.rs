use crate::models::HostInfo;
use crate::components::EmptyState;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct CveTabProps {
    pub host: HostInfo,
}

#[component]
pub fn CveTab(props: CveTabProps) -> Element {
    let all_cves: Vec<_> = props.host.ports.iter()
        .flat_map(|p| p.cves.iter().map(move |c| (&p.port, c)))
        .collect();

    if all_cves.is_empty() {
        return rsx! {
            EmptyState {
                icon: "🛡️",
                title: "Нет известных уязвимостей",
            }
        };
    }

    rsx! {
        table { class: "w-full text-xs text-left",
            thead {
                tr {
                    style: "color: var(--color-text-muted); border-bottom: 1px solid var(--color-border-light)",
                    th { class: "py-1 px-2", "Порт" }
                    th { class: "py-1 px-2", "CVE ID" }
                    th { class: "py-1 px-2", "Severity" }
                    th { class: "py-1 px-2", "CVSS" }
                }
            }
            tbody {
                {all_cves.iter().map(|(port, cve)| {
                    let cve_id = &cve.id;
                    let url = format!("https://nvd.nist.gov/vuln/detail/{}", cve_id);
                    let severity_color = match cve.severity.as_str() {
                        "Critical" => "var(--color-severity-critical)",
                        "High" => "var(--color-severity-high)",
                        "Medium" => "var(--color-severity-medium)",
                        _ => "var(--color-text-muted)",
                    };
                    let pv = **port;
                    rsx! {
                        tr { key: "{cve_id}-{pv}", class: "border-b", style: "border-color: var(--color-border-light)",
                            td {
                                class: "py-1 px-2 font-mono",
                                style: "color: var(--color-text-primary)",
                                "{pv}"
                            }
                            td { class: "py-1 px-2",
                                a {
                                    class: "hover:underline font-mono",
                                    style: "color: var(--color-primary)",
                                    href: "{url}", target: "_blank", "{cve_id}"
                                }
                            }
                            td { class: "py-1 px-2", style: "color: {severity_color}", "{cve.severity}" }
                            td {
                                class: "py-1 px-2",
                                style: "color: var(--color-text-secondary)",
                                "{cve.cvss_score}"
                            }
                        }
                    }
                })}
            }
        }
    }
}
