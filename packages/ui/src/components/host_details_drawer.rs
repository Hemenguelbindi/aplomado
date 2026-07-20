use crate::models::HostInfo;
use crate::HostDetailPanel;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct HostDetailsDrawerProps {
    pub host: Option<HostInfo>,
    pub on_close: EventHandler<()>,
}

#[component]
pub fn HostDetailsDrawer(props: HostDetailsDrawerProps) -> Element {
    let close = props.on_close.clone();

    rsx! {
        if let Some(host) = &props.host {
            div {
                class: "fixed inset-0 z-50",
                aria_hidden: "true",
                onclick: move |_| close.call(()),
                div { class: "absolute inset-0 bg-overlay/80" }
            }
            div {
                class: "fixed z-50 inset-x-0 bottom-0 md:inset-y-0 md:right-0 md:left-auto md:w-[480px] flex flex-col bg-surface border-t md:border-l border-border shadow-xl outline-none",
                onclick: move |e: Event<MouseData>| e.stop_propagation(),
                div { class: "flex items-center justify-between px-4 py-3 border-b border-border bg-surface shrink-0",
                    h3 { class: "text-base font-semibold text-foreground", "Детали хоста" }
                    button {
                        class: "flex items-center justify-center w-8 h-8 rounded-md text-muted-foreground hover:text-foreground bg-transparent border-none cursor-pointer",
                        "aria-label": "Закрыть",
                        onclick: move |_| close.call(()),
                        span { class: "text-lg leading-none", "\u{2716}" }
                    }
                }
                div { class: "flex-1 overflow-y-auto px-4 py-3",
                    HostDetailPanel { host: host.clone(), on_close: close.clone() }
                }
                div {
                    class: "md:hidden flex items-center justify-center px-4 py-2 border-t border-border bg-surface shrink-0",
                    button {
                        class: "w-full py-2 rounded-md text-sm font-medium text-muted-foreground hover:text-foreground bg-transparent border border-border cursor-pointer",
                        onclick: move |_| close.call(()),
                        "Закрыть"
                    }
                }
            }
        }
    }
}
