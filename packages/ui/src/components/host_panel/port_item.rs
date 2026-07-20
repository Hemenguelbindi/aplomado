use dioxus::prelude::*;

use crate::models::PortInfo;

#[component]
pub fn PortItem(port: PortInfo) -> Element {
    let cve_count = port.cves.len();

    rsx! {
        div {
            key: "{port.port}",
            style: "padding: 6px 0; border-bottom: 1px solid var(--color-border);",

            div {
                style: "display: flex; justify-content: space-between; align-items: center;",

                div {
                    style: "font-family: monospace; font-size: 13px; \
                            color: var(--color-text-primary);",
                    span {
                        style: "font-weight: 600;",
                        "{port.port}"
                    }
                    span {
                        style: "color: var(--color-text-muted); margin-left: 6px; \
                                font-size: 12px;",
                        "{port.service_name}"
                    }
                }

                if cve_count > 0 {
                    span {
                        style: "color: var(--color-severity-critical); font-size: 11px; \
                                font-weight: 600;",
                        "⚠ {cve_count}"
                    }
                }
            }

            if let Some(ref version) = port.service_version {
                if !version.is_empty() {
                    div {
                        style: "font-size: 11px; color: var(--color-text-muted); \
                                margin-top: 2px; font-family: monospace;",
                        "{version}"
                    }
                }
            }

            if let Some(ref banner) = port.banner {
                if !banner.is_empty() {
                    div {
                        style: "font-size: 10px; color: var(--color-text-muted); \
                                margin-top: 2px; font-family: monospace; \
                                max-height: 32px; overflow: hidden; \
                                text-overflow: ellipsis;",
                        "{banner}"
                    }
                }
            }

            // CVEs
            if cve_count > 0 {
                div {
                    style: "margin-top: 4px; display: flex; gap: 4px; flex-wrap: wrap;",
                    {port.cves.iter().take(5).map(|cve| {
                        let bg = match cve.severity.to_lowercase().as_str() {
                            "critical" => "var(--color-severity-critical)",
                            "high" => "var(--color-severity-high)",
                            "medium" => "var(--color-severity-medium)",
                            _ => "var(--color-severity-low)",
                        };
                        rsx! {
                            span {
                                key: "{cve.id}",
                                style: "display: inline-block; padding: 1px 6px; \
                                        border-radius: 3px; font-size: 10px; \
                                        background: {bg}; color: white; \
                                        font-family: monospace;",
                                "{cve.id}"
                            }
                        }
                    })}
                    if cve_count > 5 {
                        span {
                            key: "{cve_count}-more",
                            style: "font-size: 10px; color: var(--color-text-muted); \
                                    align-self: center;",
                            "+{cve_count - 5} more"
                        }
                    }
                }
            }
        }
    }
}
