use dioxus::prelude::*;

#[component]
pub fn HostBadges(os_guess: Option<String>, ttl: Option<u8>, alive: bool) -> Element {
    let alive_bg = if alive {
        "var(--color-severity-low)"
    } else {
        "var(--color-severity-unknown)"
    };

    rsx! {
        div {
            style: "padding: 0 16px 16px;",

            div {
                style: "display: flex; gap: 6px; flex-wrap: wrap;",

                if let Some(ref os) = os_guess {
                    span {
                        style: "display: inline-block; padding: 2px 8px; border-radius: 4px; \
                                font-size: 11px; background: var(--color-primary); color: white;",
                        "🖥 {os}"
                    }
                }

                if let Some(ttl) = ttl {
                    span {
                        style: "display: inline-block; padding: 2px 8px; border-radius: 4px; \
                                font-size: 11px; background: var(--color-border); \
                                color: var(--color-text-secondary);",
                        "TTL: {ttl}"
                    }
                }

                span {
                    style: "display: inline-block; padding: 2px 8px; border-radius: 4px; \
                            font-size: 11px; font-weight: 600; \
                            background: {alive_bg}; \
                            color: white;",
                    if alive { "Alive" } else { "Down" }
                }
            }
        }
    }
}
