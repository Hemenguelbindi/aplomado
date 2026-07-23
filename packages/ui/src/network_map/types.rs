use crate::components::IconName;
use crate::models::HostInfo;
use dioxus::prelude::*;

#[derive(Clone, PartialEq, Debug)]
pub enum MapViewMode {
    Table,
    Topology,
}

#[derive(Props, Clone, PartialEq)]
pub struct NetworkMapProps {
    pub hosts: Vec<HostInfo>,
    pub view_mode: MapViewMode,
    pub on_change_view: EventHandler<MapViewMode>,
    pub on_select_host: EventHandler<String>,
    #[props(optional)]
    pub selected_host: Option<String>,
}

#[derive(Props, Clone, PartialEq)]
pub struct HostDetailPanelProps {
    pub host: HostInfo,
    pub on_close: EventHandler<()>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum HostDetailTab {
    Overview,
    Ports,
    Services,
    Cve,
    Notes,
}

pub struct CveStats {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

pub fn count_cves(host: &HostInfo) -> CveStats {
    let mut s = CveStats {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };
    for p in &host.ports {
        for c in &p.cves {
            match c.severity.as_str() {
                "Critical" => s.critical += 1,
                "High" => s.high += 1,
                "Medium" => s.medium += 1,
                _ => s.low += 1,
            }
        }
    }
    s
}

pub fn cve_badge_color(s: &CveStats) -> &'static str {
    if s.critical > 0 {
        "var(--color-severity-critical)"
    } else if s.high > 0 {
        "var(--color-severity-high)"
    } else if s.medium > 0 {
        "var(--color-severity-medium)"
    } else {
        "var(--color-text-muted)"
    }
}

pub fn cve_badge_text(s: &CveStats) -> String {
    let total = s.critical + s.high + s.medium + s.low;
    if total == 0 {
        return "\u{2014}".into();
    }
    let mut parts = Vec::new();
    if s.critical > 0 {
        parts.push(format!("C:{}", s.critical));
    }
    if s.high > 0 {
        parts.push(format!("H:{}", s.high));
    }
    if s.medium > 0 {
        parts.push(format!("M:{}", s.medium));
    }
    if s.low > 0 {
        parts.push(format!("L:{}", s.low));
    }
    parts.join(" ")
}

pub fn os_icon(os: &str) -> IconName {
    let l = os.to_lowercase();
    if l.contains("linux") || l.contains("ubuntu") || l.contains("debian") {
        IconName::Terminal
    } else if l.contains("windows")
        || l.contains("macos")
        || l.contains("darwin")
        || l.contains("mac")
    {
        IconName::Monitor
    } else if l.contains("cisco") || l.contains("router") || l.contains("switch") {
        IconName::Globe
    } else if l.contains("camera") || l.contains("dahua") || l.contains("hikvision") {
        IconName::Camera
    } else if l.contains("android") || l.contains("ios") {
        IconName::Smartphone
    } else {
        IconName::Server
    }
}

pub fn risk_color(s: &CveStats) -> &'static str {
    if s.critical > 0 {
        "border-severity-critical/50 bg-severity-critical/5"
    } else if s.high > 0 {
        "border-severity-high/50 bg-severity-high/5"
    } else if s.medium > 0 {
        "border-severity-medium/50 bg-severity-medium/5"
    } else {
        "border-border bg-surface"
    }
}
