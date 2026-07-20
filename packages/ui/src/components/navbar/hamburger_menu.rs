use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HamburgerMenuProps {
    pub menu_open: Signal<bool>,
}

#[component]
pub fn HamburgerMenu(props: HamburgerMenuProps) -> Element {
    let mut menu_open = props.menu_open;

    let bar1_transform = if menu_open() {
        "rotate(45deg) translate(2px, 2px)"
    } else {
        "none"
    };
    let bar1_opacity = if menu_open() { "0" } else { "1" };
    let bar2_opacity = if menu_open() { "0" } else { "1" };
    let bar2_transform = if menu_open() {
        "rotate(-45deg) translate(2px, -2px)"
    } else {
        "none"
    };

    rsx! {
        button {
            class: "md:hidden flex flex-col justify-center items-center w-8 h-8 gap-1 bg-transparent border-none cursor-pointer",
            onclick: move |_| menu_open.with_mut(|v| *v = !*v),
            span {
                class: "block w-5 h-0.5 rounded-sm bg-foreground transition-all duration-200",
                style: "transform: {bar1_transform}; opacity: {bar1_opacity};",
            }
            span {
                class: "block w-5 h-0.5 rounded-sm bg-foreground transition-all duration-200",
                style: "opacity: {bar2_opacity};",
            }
            span {
                class: "block w-5 h-0.5 rounded-sm bg-foreground transition-all duration-200",
                style: "transform: {bar2_transform};",
            }
        }
    }
}
