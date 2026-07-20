use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct ThemeToggleProps {
    /// Callback fired when the user clicks the theme toggle button.
    pub on_theme_toggle: EventHandler<()>,
}

/// A round button that toggles between dark (☀) and light (☾) theme icons.
#[component]
pub fn ThemeToggle(props: ThemeToggleProps) -> Element {
    let theme_name = crate::theme::use_theme_name();
    let theme_icon = if theme_name() == "dark" {
        "\u{2600}" // ☀
    } else {
        "\u{263E}" // ☾
    };

    rsx! {
        button {
            class: "flex items-center justify-center w-8 h-8 rounded-full cursor-pointer transition-colors duration-200",
            style: "background: var(--color-border); color: var(--color-text-secondary); border: none;",
            onclick: move |_| props.on_theme_toggle.call(()),
            "{theme_icon}"
        }
    }
}
