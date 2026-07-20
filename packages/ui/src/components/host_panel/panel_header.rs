use dioxus::prelude::*;

#[component]
pub fn PanelHeader(ip: String, hostname: Option<String>, on_close: EventHandler<()>) -> Element {
    rsx! {
        // Close button
        div {
            style: "position: sticky; top: 0; display: flex; justify-content: flex-end; \
                    padding: 8px 12px; background: var(--color-surface); z-index: 1; \
                    border-bottom: 1px solid var(--color-border);",
            button {
                style: "background: none; border: none; color: var(--color-text-muted); \
                        font-size: 18px; cursor: pointer; padding: 4px 8px; \
                        border-radius: 4px; line-height: 1;",
                onclick: move |_| on_close.call(()),
                "×"
            }
        }

        div {
            style: "padding: 16px;",

            // IP + Hostname header
            div {
                style: "margin-bottom: 12px;",
                div {
                    style: "font-family: monospace; font-size: 18px; font-weight: bold; \
                            color: var(--color-text-primary);",
                    "{ip}"
                }
                if let Some(ref hostname) = hostname {
                    div {
                        style: "font-size: 13px; color: var(--color-text-muted); margin-top: 2px;",
                        "{hostname}"
                    }
                }
            }
        }
    }
}
