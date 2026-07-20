use crate::components::{Icon, IconName, IconSize};
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct ThemeToggleProps {
    pub on_theme_toggle: EventHandler<()>,
}

#[component]
pub fn ThemeToggle(props: ThemeToggleProps) -> Element {
    let theme_name = crate::theme::use_theme_name();
    let icon = if theme_name() == "dark" {
        IconName::Sun
    } else {
        IconName::Moon
    };

    rsx! {
        button {
            class: "flex items-center justify-center w-8 h-8 rounded-full bg-border text-muted-foreground border-none cursor-pointer transition-colors duration-200 hover:text-foreground",
            onclick: move |_| props.on_theme_toggle.call(()),
            Icon { name: icon, size: IconSize::Sm }
        }
    }
}
