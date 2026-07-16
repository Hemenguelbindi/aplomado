use dioxus::prelude::*;
use crate::scan_form::ScanStatusUi;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Props, Clone, PartialEq)]
pub struct NavbarProps {
    /// Child nav links (platform-specific `Link` components).
    pub children: Element,
    /// Current route path for active-link highlighting (e.g. `"/"`, `"/scan"`).
    #[props(default)]
    pub current_route: Option<String>,
    /// Current scan status.
    #[props(default)]
    pub scan_status: ScanStatusUi,
    /// Number of found vulnerabilities across all hosts.
    #[props(default)]
    pub vuln_count: usize,
    /// Callback fired when the user clicks the theme toggle button.
    #[props(default)]
    pub on_theme_toggle: EventHandler<()>,
}

/// Top navigation bar with logo, status indicator, counters, and theme toggle.
///
/// Pass platform-specific `Link` components as children for the navigation links.
#[component]
pub fn Navbar(props: NavbarProps) -> Element {
    let mut menu_open = use_signal(|| false);
    let theme_name = crate::theme::use_theme_name();

    // ── status dot + label ──────────────────────────────────────
    let (dot_style, status_text, pulse_class) = match &props.scan_status {
        ScanStatusUi::Scanning { current, total } => (
            "background: var(--color-warning)",
            format!("{current}/{total}"),
            "animate-pulse",
        ),
        ScanStatusUi::Done(count) => (
            "background: var(--color-success)",
            format!("{count} hosts"),
            "",
        ),
        ScanStatusUi::Error(msg) => (
            "background: var(--color-error)",
            msg.clone(),
            "",
        ),
        ScanStatusUi::Idle => (
            "background: var(--color-success)",
            "Ready".into(),
            "",
        ),
    };


    let theme_icon = if theme_name() == "dark" {
        "\u{2600}" // ☀
    } else {
        "\u{263E}" // ☾
    };

    // ── hamburger icon transform helpers ────────────────────────
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

    let nav_class = if menu_open() {
        "flex flex-col md:flex-row md:items-center gap-2 p-3 md:p-0 border md:border-0 absolute md:static top-full left-0 right-0 z-50"
    } else {
        "hidden md:flex md:items-center gap-1"
    };

    rsx! {
        div {
            class: "relative flex items-center justify-between px-4 py-3 border-b",
            style: "background: var(--color-surface); border-color: var(--color-border);",

            // ── Logo ──────────────────────────────────────────
            div {
                class: "flex items-center gap-2.5",
                // Icon badge
                div {
                    class: "flex items-center justify-center w-8 h-8 rounded-lg font-bold text-sm",
                    style: "background: var(--color-primary); color: var(--color-bg-primary);",
                    "K"
                }
                // Name
                span {
                    class: "font-bold text-lg tracking-wide",
                    style: "color: var(--color-text-primary);",
                    "KESTREL"
                }
                // Version pill
                span {
                    class: "hidden sm:inline text-xs px-1.5 py-0.5 rounded",
                    style: "background: var(--color-border); color: var(--color-text-muted);",
                    "v{APP_VERSION}"
                }
            }

            // ── Nav + hamburger toggle ─────────────────────────
            div { class: "relative",
                // Desktop nav / mobile dropdown
                nav { class: "{nav_class}",
                    style: if menu_open() { "background: var(--color-surface); border-color: var(--color-border);" } else { "" },
                    {props.children}
                }

                // Hamburger button (mobile only)
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

            // ── Right section: status, vuln badge, theme toggle ──
            div { class: "hidden sm:flex items-center gap-3",
                // Status pill
                div {
                    class: "flex items-center gap-2 px-2.5 py-1 rounded-full",
                    style: "background: var(--color-border);",
                    span {
                        class: "w-2 h-2 rounded-full {pulse_class}",
                        style: "{dot_style};",
                    }
                    span {
                        class: "text-xs",
                        style: "color: var(--color-text-muted);",
                        "{status_text}"
                    }
                }

                // Vulnerability count badge (shown only when > 0)
                if props.vuln_count > 0 {
                    div {
                        class: "flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium",
                        style: "background: rgba(248,81,73,0.15); color: var(--color-severity-critical);",
                        span { "\u{26A0}" }
                        span { "{props.vuln_count}" }
                    }
                }

                // Theme toggle
                button {
                    class: "flex items-center justify-center w-8 h-8 rounded-full cursor-pointer transition-colors duration-200",
                    style: "background: var(--color-border); color: var(--color-text-secondary); border: none;",
                    onclick: move |_| props.on_theme_toggle.call(()),
                    "{theme_icon}"
                }
            }

            // Mobile-only: status + theme in a compact row beneath the main bar
            // (visible only when menu is open, inside the dropdown above)
        }
    }
}
