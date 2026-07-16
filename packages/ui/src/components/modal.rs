use dioxus::prelude::*;

/// Модальное окно с оверлеем и закрытием по клику на backdrop.
///
/// # Пример
/// ```ignore
/// let mut show_modal = use_signal(|| false);
/// if show_modal() {
///     Modal {
///         title: "Подтверждение",
///         on_close: move |_| show_modal.set(false),
///         rsx! {
///             p { "Вы уверены?" }
///         }
///     }
/// }
/// ```
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
            // Backdrop
            div {
                class: "absolute inset-0",
                style: "background: var(--color-overlay)",
                onclick: move |_| props.on_close.call(()),
            }
            // Modal content
            div {
                class: "relative bg-[var(--color-surface)] border rounded-lg shadow-xl max-w-lg w-full mx-4 p-6 z-10",
                style: "border-color: var(--color-border-light)",
                if let Some(ref title) = props.title {
                    div { class: "flex items-center justify-between mb-4",
                        h2 {
                            class: "text-lg font-semibold",
                            style: "color: var(--color-text-primary)",
                            "{title}"
                        }
                        button {
                            class: "text-sm cursor-pointer",
                            style: "color: var(--color-text-muted)",
                            onclick: move |_| props.on_close.call(()),
                            "✕"
                        }
                    }
                } else {
                    div { class: "flex justify-end -mt-2 mb-2",
                        button {
                            class: "text-sm cursor-pointer",
                            style: "color: var(--color-text-muted)",
                            onclick: move |_| props.on_close.call(()),
                            "✕"
                        }
                    }
                }
                {props.children}
            }
        }
    }
}
