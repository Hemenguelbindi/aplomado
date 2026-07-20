use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct NavLinksProps {
    /// Child nav links (platform-specific `Link` components).
    pub children: Element,
    /// Whether the mobile menu is currently open.
    pub menu_open: Signal<bool>,
}

/// Desktop navigation container. When `menu_open` is true on mobile, shows as a dropdown.
#[component]
pub fn NavLinks(props: NavLinksProps) -> Element {
    let menu_open = props.menu_open;

    let nav_class = if menu_open() {
        "flex flex-col md:flex-row md:items-center gap-2 p-3 md:p-0 border md:border-0 absolute md:static top-full left-0 right-0 z-50"
    } else {
        "hidden md:flex md:items-center gap-1"
    };

    rsx! {
        nav {
            class: "{nav_class}",
            style: if menu_open() { "background: var(--color-surface); border-color: var(--color-border);" } else { "" },
            {props.children}
        }
    }
}
