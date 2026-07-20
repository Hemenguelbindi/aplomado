use dioxus::prelude::*;
use crate::components::{Button, ButtonVariant};
use crate::models::ScanPreset;

pub const ALL_PRESETS: &[ScanPreset] = &[
    ScanPreset::Quick, ScanPreset::Standard, ScanPreset::Full,
    ScanPreset::Vulnerability, ScanPreset::Cameras, ScanPreset::Custom,
];

#[derive(Props, Clone, PartialEq)]
pub struct PresetSelectorProps {
    pub active: ScanPreset,
    pub disabled: bool,
    pub on_select: EventHandler<ScanPreset>,
}

#[component]
pub fn PresetSelector(props: PresetSelectorProps) -> Element {
    rsx! {
        div { class: "flex items-center gap-2 flex-wrap",
            span {
                key: "preset-label",
                class: "text-sm",
                style: "color: var(--color-text-muted)",
                "Пресет:"
            }
            {ALL_PRESETS.iter().map(|p| {
                let p_clone = p.clone();
                let active = *p == props.active;
                let label = p.label();
                let variant = if active { ButtonVariant::Primary } else { ButtonVariant::Secondary };
                rsx! {
                    Button {
                        key: "{label}",
                        variant: variant,
                        disabled: props.disabled,
                        onclick: move |_| props.on_select.call(p_clone.clone()),
                        "{label}"
                    }
                }
            })}
        }
    }
}
