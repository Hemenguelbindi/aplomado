use dioxus::prelude::*;
use crate::models::HostInfo;

#[derive(Props, Clone, PartialEq)]
pub struct TopologyTooltipProps {
    pub host: Option<HostInfo>,
    pub pos: (f64, f64),
    pub visible: bool,
}

#[component]
pub fn TopologyTooltip(props: TopologyTooltipProps) -> Element {
    if !props.visible || props.host.is_none() {
        return rsx! {};
    }

    let host = props.host.as_ref().unwrap();
    let ip = host.ip.to_string();
    let hostname = host.hostname.as_deref().unwrap_or("");
    let os_guess = host.os_guess.as_deref().unwrap_or("");
    let port_count = host.ports.len();
    let cve_count: usize = host.ports.iter().map(|p| p.cves.len()).sum();

    // Determine severity from ports
    let critical_ports = [22, 23, 135, 139, 445, 3389, 3306, 5432, 6379, 27017];
    let has_critical = host.ports.iter().any(|p| critical_ports.contains(&p.port));
    let (severity_label, severity_color) = if !host.alive {
        ("Unknown", "var(--color-severity-unknown)")
    } else if has_critical {
        ("High", "var(--color-severity-high)")
    } else if host.ports.is_empty() {
        ("Low", "var(--color-severity-low)")
    } else {
        ("Medium", "var(--color-severity-medium)")
    };

    // Position with offset, clamp to viewport
    let x = props.pos.0 + 12.0;
    let y = props.pos.1 + 12.0;

    rsx! {
        div {
            style: "position: absolute; left: {x}px; top: {y}px; z-index: 50; pointer-events: none; \
                    background: var(--color-surface); border: 1px solid var(--color-border); \
                    border-radius: 8px; padding: 8px 12px; font-size: 12px; \
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3); max-width: 250px;",

            // IP address
            div {
                style: "font-family: monospace; font-weight: bold; color: var(--color-text-primary); margin-bottom: 2px;",
                "{ip}"
            }

            // Hostname
            if !hostname.is_empty() {
                div {
                    style: "color: var(--color-text-muted); font-size: 11px; margin-bottom: 4px;",
                    "{hostname}"
                }
            }

            // OS guess
            if !os_guess.is_empty() {
                div {
                    style: "color: var(--color-text-secondary); font-size: 11px; margin-bottom: 4px;",
                    "🖥 {os_guess}"
                }
            }

            // Stats row
            div {
                style: "display: flex; gap: 6px; align-items: center; flex-wrap: wrap;",

                // Severity badge
                span {
                    style: "display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 10px; \
                            font-weight: 600; background: {severity_color}; color: white;",
                    "{severity_label}"
                }

                // Port count
                span {
                    style: "color: var(--color-text-secondary); font-size: 11px;",
                    "Ports: {port_count}"
                }

                // CVE count
                if cve_count > 0 {
                    span {
                        style: "color: var(--color-severity-critical); font-size: 11px; font-weight: 600;",
                        "⚠ {cve_count} CVE"
                    }
                }
            }
        }
    }
}
