use crate::components::{Badge, BadgeVariant, Button, ButtonVariant, Icon, IconName, IconSize};
use crate::models::{ScanTargetItem, TargetStatus};
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct TargetListProps {
    pub targets: Vec<ScanTargetItem>,
    pub is_scanning: bool,
    pub on_run: EventHandler<String>,
    pub on_remove: EventHandler<String>,
}

fn status_indicator(status: &TargetStatus) -> &'static str {
    match status {
        TargetStatus::Queued => "text-muted-foreground",
        TargetStatus::Scanning => "text-primary animate-pulse",
        TargetStatus::Done(_) => "text-success",
        TargetStatus::Error(_) => "text-danger",
    }
}

fn status_dot(status: &TargetStatus) -> &'static str {
    match status {
        TargetStatus::Queued => "○",
        TargetStatus::Scanning => "◌",
        TargetStatus::Done(_) => "●",
        TargetStatus::Error(_) => "●",
    }
}

#[component]
pub fn TargetList(props: TargetListProps) -> Element {
    if props.targets.is_empty() {
        return rsx! {};
    }

    let total = props.targets.len();

    rsx! {
        div { class: "space-y-1",
            label { class: "text-sm text-muted-foreground", "Цели ({total})" }
            div { class: "max-h-60 overflow-y-auto space-y-1",
                {props.targets.iter().map(|item| {
                    let idx = item.id.clone();
                    let target = item.target.clone();
                    let preset_label = item.preset.label().to_string();
                    let indicator_cls = status_indicator(&item.status);
                    let dot = status_dot(&item.status);
                    let label = match &item.status {
                        TargetStatus::Queued => "Queued",
                        TargetStatus::Scanning => "Scanning",
                        TargetStatus::Done(_) => "Done",
                        TargetStatus::Error(_) => "Error",
                    };
                    let idx_run = idx.clone();
                    let idx_remove = idx.clone();

                    rsx! {
                        div {
                            key: "{idx}",
                            class: "flex items-center gap-2 border border-input-border rounded px-3 py-2 bg-input-bg",
                            span { class: "text-sm font-mono flex-1 text-foreground", "{target}" }
                            Badge { variant: BadgeVariant::Primary, "{preset_label}" }
                            span { class: "text-xs font-mono {indicator_cls}", "{dot} {label}" }
                            Button {
                                variant: ButtonVariant::Icon,
                                disabled: props.is_scanning,
                                onclick: move |_| props.on_run.call(idx_run.clone()),
                                Icon { name: IconName::Play, size: IconSize::Sm }
                            }
                            Button {
                                variant: ButtonVariant::Icon,
                                disabled: props.is_scanning,
                                onclick: move |_| props.on_remove.call(idx_remove.clone()),
                                Icon { name: IconName::Close, size: IconSize::Sm }
                            }
                        }
                    }
                })}
            }
        }
    }
}
