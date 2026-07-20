use dioxus::prelude::*;
use crate::components::navbar::*;
use crate::scan_form::ScanStatusUi;

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
            class: "relative flex items-center justify-between px-4 py-3 border-b",
            style: "background: var(--color-surface); border-color: var(--color-border);",
            Logo { }
            div { class: "relative",
                NavLinks { menu_open, children: props.children }
                HamburgerMenu { menu_open }
            }
            div { class: "hidden sm:flex items-center gap-3",
                StatusPill { scan_status: props.scan_status }
                if props.vuln_count > 0 {
                    div {
                        class: "flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium",
                        style: "background: rgba(248,81,73,0.15); color: var(--color-severity-critical);",
                        span { "\u{26A0}" }
                        span { "{props.vuln_count}" }
                    }
                }
                ThemeToggle { on_theme_toggle: props.on_theme_toggle }
            }
        }
    }
}
