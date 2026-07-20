use crate::components::Card;
use dioxus::prelude::*;

#[component]
pub fn StatCard(
    label: String,
    value: String,
    subtext: Option<String>,
    icon: &'static str,
    icon_bg: String,
    #[props(default = false)]
    danger: bool,
    #[props(default = true)]
    large_value: bool,
) -> Element {
    let value_class = if large_value {
        "text-3xl font-bold mt-1"
    } else {
        "text-lg font-bold mt-1"
    };
    let value_style = if danger {
        "color: var(--color-danger)"
    } else {
        "color: var(--color-text-primary)"
    };
    rsx! {
        Card {
            div { class: "flex items-center justify-between",
                div {
                    p { class: "text-sm font-medium", style: "color: var(--color-text-muted)", "{label}" }
                    p { class: "{value_class}", style: "{value_style}", "{value}" }
                    if let Some(sub) = subtext {
                        p { class: "text-xs mt-1", style: "color: var(--color-text-muted)", "{sub}" }
                    }
                }
                div {
                    class: "w-12 h-12 rounded-lg flex items-center justify-center text-2xl",
                    style: "background: {icon_bg}",
                    "{icon}"
                }
            }
        }
    }
}
