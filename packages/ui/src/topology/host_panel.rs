use dioxus::prelude::*;
use crate::models::HostInfo;

#[derive(Props, Clone, PartialEq)]
pub struct HostDetailPanelProps {
    pub host: Option<HostInfo>,
    pub on_close: EventHandler<()>,
}

#[component]
pub fn HostDetailPanel(props: HostDetailPanelProps) -> Element {
    let visible = props.host.is_some();

    let transform = if visible {
        "translateX(0)"
    } else {
        "translateX(100%)"
    };

    let alive_bg = match props.host.as_ref() {
        Some(h) if h.alive => "var(--color-severity-low)",
        _ => "var(--color-severity-unknown)",
    };

    rsx! {
        div {
            style: "position: absolute; top: 0; right: 0; width: 380px; height: 100%; \
                    background: var(--color-surface); border-left: 1px solid var(--color-border); \
                    transform: {transform}; transition: transform 0.3s ease; z-index: 40; \
                    overflow-y: auto; box-shadow: -4px 0 16px rgba(0,0,0,0.2);",

            if let Some(ref host) = props.host {
                {rsx! {
                    // Close button
                    div {
                        style: "position: sticky; top: 0; display: flex; justify-content: flex-end; \
                                padding: 8px 12px; background: var(--color-surface); z-index: 1; \
                                border-bottom: 1px solid var(--color-border);",
                        button {
                            style: "background: none; border: none; color: var(--color-text-muted); \
                                    font-size: 18px; cursor: pointer; padding: 4px 8px; \
                                    border-radius: 4px; line-height: 1;",
                            onclick: move |_| props.on_close.call(()),
                            "×"
                        }
                    }

                    div {
                        style: "padding: 16px;",

                        // IP + Hostname header
                        div {
                            style: "margin-bottom: 12px;",
                            div {
                                style: "font-family: monospace; font-size: 18px; font-weight: bold; \
                                        color: var(--color-text-primary);",
                                "{host.ip}"
                            }
                            if let Some(ref hostname) = host.hostname {
                                div {
                                    style: "font-size: 13px; color: var(--color-text-muted); margin-top: 2px;",
                                    "{hostname}"
                                }
                            }
                        }

                        // Badges row
                        div {
                            style: "display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 16px;",

                            if let Some(ref os) = host.os_guess {
                                span {
                                    style: "display: inline-block; padding: 2px 8px; border-radius: 4px; \
                                            font-size: 11px; background: var(--color-primary); color: white;",
                                    "🖥 {os}"
                                }
                            }

                            if let Some(ttl) = host.ttl {
                                span {
                                    style: "display: inline-block; padding: 2px 8px; border-radius: 4px; \
                                            font-size: 11px; background: var(--color-border); \
                                            color: var(--color-text-secondary);",
                                    "TTL: {ttl}"
                                }
                            }

                            span {
                                style: "display: inline-block; padding: 2px 8px; border-radius: 4px; \
                                        font-size: 11px; font-weight: 600; \
                                        background: {alive_bg}; \
                                        color: white;",
                                if host.alive { "Alive" } else { "Down" }
                            }
                        }

                        // Open Ports section
                        div {
                            style: "margin-bottom: 16px;",
                            div {
                                style: "font-size: 13px; font-weight: 600; color: var(--color-text-primary); \
                                        margin-bottom: 8px; padding-bottom: 4px; \
                                        border-bottom: 1px solid var(--color-border);",
                                "Open Ports ({host.ports.len()})"
                            }

                            if host.ports.is_empty() {
                                div {
                                    style: "color: var(--color-text-muted); font-size: 12px; font-style: italic; \
                                            padding: 8px 0;",
                                    "No open ports detected"
                                }
                            } else {
                                {host.ports.iter().map(|port| {
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
                                                            style: "font-size: 10px; color: var(--color-text-muted); \
                                                                    align-self: center;",
                                                            "+{cve_count - 5} more"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                })}
                            }
                        }
                    }
                }}
            }
        }
    }
}
