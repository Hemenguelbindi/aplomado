use crate::helpers::pluralize;
use crate::scan_form::ScanStatusUi;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct StatusPillProps {
    /// Current scan status.
    pub scan_status: ScanStatusUi,
}

/// An inline indicator showing the current scan status: dot + label.
#[component]
pub fn StatusPill(props: StatusPillProps) -> Element {
    let (dot_style, status_text, pulse_class) = match &props.scan_status {
        ScanStatusUi::Scanning { current, total } => (
            "background: var(--color-warning)",
            format!("{current}/{total}"),
            "animate-pulse",
        ),
        ScanStatusUi::Done(count) => (
            "background: var(--color-success)",
            pluralize(*count as usize, "хост", "хоста", "хостов"),
            "",
        ),
        ScanStatusUi::Error(msg) => ("background: var(--color-error)", msg.clone(), ""),
        ScanStatusUi::Idle => ("background: var(--color-success)", "Ready".into(), ""),
    };

    rsx! {
        div {
            class: "flex items-center gap-2 px-2.5 py-1 rounded-full",
            style: "background: var(--color-border);",
            span {
                class: "w-2 h-2 rounded-full {pulse_class}",
                style: "{dot_style};",
            }
            span {
                class: "text-xs",
                style: "color: var(--color-text-muted);",
                "{status_text}"
            }
        }
    }
}
