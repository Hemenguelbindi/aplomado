use dioxus::prelude::*;
use crate::models::{ScanTargetItem, TargetStatus};
use crate::components::{Badge, BadgeVariant, Button, ButtonVariant};

#[derive(Props, Clone, PartialEq)]
pub struct TargetListProps {
    pub targets: Vec<ScanTargetItem>,
    pub is_scanning: bool,
    pub on_run: EventHandler<String>,
    pub on_remove: EventHandler<String>,
}

#[component]
pub fn TargetList(props: TargetListProps) -> Element {
    if props.targets.is_empty() { return rsx! {}; }

    let total = props.targets.len();

    rsx! {
        div { class: "space-y-1",
            label {
                class: "text-sm",
                style: "color: var(--color-text-muted)",
                "Цели ({total})"
            }
            div { class: "max-h-60 overflow-y-auto space-y-1",
                {props.targets.iter().map(|item| {
                    let idx = item.id.clone();
                    let target = item.target.clone();
                    let preset_label = item.preset.label().to_string();
                    let (status_text, badge_variant) = match &item.status {
                        TargetStatus::Queued => ("⏳", BadgeVariant::Default),
                        TargetStatus::Scanning => ("🔄", BadgeVariant::Info),
                        TargetStatus::Done(n) => {
                            // Store count in a local
                            let _ = n;
                            ("✅", BadgeVariant::Success)
                        },
                        TargetStatus::Error(_) => ("❌", BadgeVariant::Error),
                    };
                    let idx_run = idx.clone();
                    let idx_remove = idx.clone();

                    rsx! {
                        div {
                            key: "{idx}",
                            class: "flex items-center gap-2 border rounded px-3 py-2",
                            style: "background: var(--color-input-bg); border-color: var(--color-input-border)",
                            span {
                                class: "text-sm font-mono flex-1",
                                style: "color: var(--color-text-primary)",
                                "{target}"
                            }
                            Badge { variant: BadgeVariant::Primary, "{preset_label}" }
                            Badge { variant: badge_variant, "{status_text}" }
                            Button {
                                variant: ButtonVariant::Icon,
                                disabled: props.is_scanning,
                                onclick: move |_| props.on_run.call(idx_run.clone()),
                                "▶"
                            }
                            Button {
                                variant: ButtonVariant::Icon,
                                disabled: props.is_scanning,
                                onclick: move |_| props.on_remove.call(idx_remove.clone()),
                                "✕"
                            }
                        }
                    }
                })}
            }
        }
    }
}
