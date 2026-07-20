use crate::components::{Card, Icon, IconName, IconSize, Tone};
use dioxus::prelude::*;

#[component]
pub fn StatCard(
    label: String,
    value: String,
    tone: Tone,
    icon: IconName,
    subtext: Option<String>,
    #[props(default = false)] danger: bool,
    #[props(default = true)] large_value: bool,
) -> Element {
    let value_class = if large_value {
        "text-3xl font-bold mt-1"
    } else {
        "text-lg font-bold mt-1"
    };
    let val_cls = if danger {
        "text-danger"
    } else {
        "text-foreground"
    };
    rsx! {
        Card {
            div { class: "flex items-center justify-between",
                div {
                    p { class: "text-sm font-medium text-muted-foreground", "{label}" }
                    p { class: "{value_class} {val_cls}", "{value}" }
                    if let Some(sub) = subtext {
                        p { class: "text-xs mt-1 text-muted-foreground", "{sub}" }
                    }
                }
                div { class: "w-12 h-12 rounded-lg flex items-center justify-center {tone.bg_class()}",
                    Icon { name: icon, size: IconSize::Lg }
                }
            }
        }
    }
}
