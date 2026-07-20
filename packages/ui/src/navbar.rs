use crate::components::{navbar::*, Icon, IconName, IconSize};
use crate::scan_form::ScanStatusUi;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct NavbarProps {
    pub children: Element,
    #[props(default)]
    pub current_route: Option<String>,
    #[props(default)]
    pub scan_status: ScanStatusUi,
    #[props(default)]
    pub vuln_count: usize,
    #[props(default)]
    pub on_theme_toggle: EventHandler<()>,
}

#[component]
pub fn Navbar(props: NavbarProps) -> Element {
    let menu_open = use_signal(|| false);
    rsx! {
        div {
            class: "relative flex items-center justify-between px-4 py-3 border-b bg-surface border-border",
            Logo { }
            div { class: "relative",
                NavLinks { menu_open, children: props.children }
                HamburgerMenu { menu_open }
            }
            div { class: "hidden sm:flex items-center gap-3",
                StatusPill { scan_status: props.scan_status }
                if props.vuln_count > 0 {
                    div {
                        class: "flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-danger/15 text-danger",
                        Icon { name: IconName::AlertTriangle, size: IconSize::Sm }
                        span { "{props.vuln_count}" }
                    }
                }
                ThemeToggle { on_theme_toggle: props.on_theme_toggle }
            }
        }
    }
}
