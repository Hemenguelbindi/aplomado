use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct ModalProps {
    #[props(default)]
    pub title: Option<String>,
    #[props(default)]
    pub class: Option<String>,
    #[props(optional)]
    pub on_close: EventHandler<()>,
    pub children: Element,
}

#[component]
pub fn Modal(props: ModalProps) -> Element {
    let extra_class = props.class.as_deref().unwrap_or("");

    rsx! {
        div {
            class: "fixed inset-0 z-50 flex items-center justify-center {extra_class}",
            role: "dialog",
            "aria-modal": "true",
            "aria-label": props.title.as_deref().unwrap_or("Модальное окно"),
            onkeydown: move |e: Event<KeyboardData>| {
                if e.key() == Key::Escape {
                    props.on_close.call(());
                }
            },
            div {
                class: "absolute inset-0 bg-overlay",
                onclick: move |_| props.on_close.call(()),
            }
            div {
                class: "relative bg-surface border border-border rounded-lg shadow-xl max-w-lg w-full mx-4 p-6 z-10",
                if let Some(ref title) = props.title {
                    div { class: "flex items-center justify-between mb-4",
                        h2 { class: "text-lg font-semibold text-foreground", "{title}" }
                        button {
                            class: "flex items-center justify-center w-7 h-7 rounded text-sm text-muted-foreground hover:text-foreground bg-transparent border-none cursor-pointer",
                            "aria-label": "Закрыть",
                            onclick: move |_| props.on_close.call(()),
                            "\u{2715}"
                        }
                    }
                } else {
                    div { class: "flex justify-end -mt-2 mb-2",
                        button {
                            class: "flex items-center justify-center w-7 h-7 rounded text-sm text-muted-foreground hover:text-foreground bg-transparent border-none cursor-pointer",
                            "aria-label": "Закрыть",
                            onclick: move |_| props.on_close.call(()),
                            "\u{2715}"
                        }
                    }
                }
                {props.children}
            }
        }
    }
}
