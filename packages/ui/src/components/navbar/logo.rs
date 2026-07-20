use dioxus::prelude::*;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Aplomado branding block: "A" badge, "APLOMADO" text, and version pill.
#[component]
pub fn Logo() -> Element {
    rsx! {
        div {
            class: "flex items-center gap-2.5",
            // Icon badge
            div {
                class: "flex items-center justify-center w-8 h-8 rounded-lg font-bold text-sm",
                style: "background: var(--color-primary); color: var(--color-bg-primary);",
                "A"
            }
            // Name
            span {
                class: "font-bold text-lg tracking-wide",
                style: "color: var(--color-text-primary);",
                "APLOMADO"
            }
            // Version pill
            span {
                class: "hidden sm:inline text-xs px-1.5 py-0.5 rounded",
                style: "background: var(--color-border); color: var(--color-text-muted);",
                "v{APP_VERSION}"
            }
        }
    }
}
