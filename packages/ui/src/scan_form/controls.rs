use dioxus::prelude::*;
use crate::models::ScanTargetItem;
use crate::components::{Button, ButtonVariant};
use super::{ScanConfigUi, build_scan_config};

#[derive(Props, Clone, PartialEq)]
pub struct ScanControlsProps {
    pub is_scanning: bool,
    pub targets_empty: bool,
    pub targets: Vec<ScanTargetItem>,
    pub on_start_scan: EventHandler<ScanConfigUi>,
    pub on_stop_scan: EventHandler<()>,
}

#[component]
pub fn ScanControls(props: ScanControlsProps) -> Element {
    rsx! {
        div { class: "flex gap-3",
            if props.is_scanning {
                Button {
                    variant: ButtonVariant::Danger,
                    class: "flex-1",
                    onclick: move |_| props.on_stop_scan.call(()),
                    "⏹ Остановить"
                }
            } else {
                Button {
                    variant: ButtonVariant::Primary,
                    class: "flex-1",
                    disabled: props.targets_empty,
                    onclick: move |_| {
                        if let Some(cfg) = build_scan_config(&props.targets) {
                            props.on_start_scan.call(cfg);
                        }
                    },
                    "▶ Запустить все цели"
                }
            }
        }
    }
}
