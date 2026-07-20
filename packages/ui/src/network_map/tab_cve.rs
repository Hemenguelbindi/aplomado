use crate::components::EmptyState;
use crate::models::HostInfo;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct CveTabProps {
    pub host: HostInfo,
}

#[component]
pub fn CveTab(props: CveTabProps) -> Element {
    let all_cves: Vec<_> = props
        .host
        .ports
        .iter()
        .flat_map(|p| p.cves.iter().map(move |c| (&p.port, c)))
        .collect();

    if all_cves.is_empty() {
        return rsx! {
            EmptyState {
                title: "Нет известных уязвимостей",
            }
        };
    }

    rsx! {
        table { class: "w-full text-xs text-left",
            thead {
                tr { class: "text-muted-foreground border-b border-border",
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
                        "Critical" => "text-severity-critical",
                        "High" => "text-severity-high",
                        "Medium" => "text-severity-medium",
                        _ => "text-muted-foreground",
                    };
                    let pv = **port;
                    rsx! {
                        tr { key: "{cve_id}-{pv}", class: "border-b border-border",
                            td { class: "py-1 px-2 font-mono text-foreground", "{pv}" }
                            td { class: "py-1 px-2",
                                a {
                                    class: "hover:underline font-mono text-primary",
                                    href: "{url}", target: "_blank", "{cve_id}"
                                }
                            }
                            td { class: "py-1 px-2 {severity_color}", "{cve.severity}" }
                            td { class: "py-1 px-2 text-muted-foreground", "{cve.cvss_score}" }
                        }
                    }
                })}
            }
        }
    }
}
