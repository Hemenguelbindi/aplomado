use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HamburgerMenuProps {
    /// Whether the mobile menu is currently open.
    pub menu_open: Signal<bool>,
}

/// Animated hamburger button (visible on mobile only via `md:hidden`).
///
/// Three bars animate into a close (X) icon when `menu_open` is true.
#[component]
pub fn HamburgerMenu(props: HamburgerMenuProps) -> Element {
    let mut menu_open = props.menu_open;

    let bar1_transform = if menu_open() {
        "rotate(45deg) translate(2px, 2px)"
    } else {
        "none"
    };
    let bar1_opacity = if menu_open() { "0" } else { "1" };
    let bar2_transform = if menu_open() {
        "rotate(-45deg) translate(2px, -2px)"
    } else {
        "none"
    };

    rsx! {
        button {
            class: "md:hidden flex flex-col justify-center items-center w-8 h-8 gap-1 cursor-pointer",
            style: "background: transparent; border: none;",
            onclick: move |_| menu_open.with_mut(|v| *v = !*v),
            // Bar 1
            span {
                class: "block w-5 h-0.5 rounded-sm transition-all duration-200",
                style: "background: var(--color-text-primary); transform: {bar1_transform}; opacity: {bar1_opacity};",
            }
            // Bar 2
            span {
                class: "block w-5 h-0.5 rounded-sm transition-all duration-200",
                style: "background: var(--color-text-primary); opacity: if menu_open() { \"0\" } else { \"1\" };",
            }
            // Bar 3
            span {
                class: "block w-5 h-0.5 rounded-sm transition-all duration-200",
                style: "background: var(--color-text-primary); transform: {bar2_transform};",
            }
        }
    }
}
