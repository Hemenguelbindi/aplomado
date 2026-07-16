use dioxus::prelude::*;

/// Поле ввода текста с опциональным label, сообщением об ошибке и подсказкой.
///
/// # Пример
/// ```ignore
/// TextInput {
///     value: "{input_value}",
///     placeholder: "Введите IP...",
///     label: "Цель сканирования",
///     oninput: move |e| input_value.set(e.value()),
/// }
/// ```
#[derive(Props, Clone, PartialEq)]
pub struct TextInputProps {
    #[props(default)]
    pub value: Option<String>,
    #[props(default)]
    pub placeholder: Option<String>,
    #[props(default)]
    pub label: Option<String>,
    #[props(default)]
    pub error: Option<String>,
    #[props(default)]
    pub helper: Option<String>,
    #[props(default)]
    pub disabled: bool,
    #[props(default)]
    pub input_type: Option<String>,
    #[props(default)]
    pub class: Option<String>,
    #[props(optional)]
    pub oninput: EventHandler<String>,
    #[props(optional)]
    pub onkeydown: EventHandler<Event<KeyboardData>>,
}

#[component]
pub fn TextInput(props: TextInputProps) -> Element {
    let input_type = props.input_type.as_deref().unwrap_or("text");
    let border_color = if props.error.is_some() {
        "var(--color-error)"
    } else {
        "var(--color-input-border)"
    };
    let extra_class = props.class.as_deref().unwrap_or("");

    rsx! {
        div { class: "flex flex-col gap-1",
            if let Some(ref label) = props.label {
                label {
                    class: "text-xs font-medium",
                    style: "color: var(--color-text-muted)",
                    "{label}"
                }
            }
            input {
                class: "w-full rounded p-2 text-sm outline-none {extra_class}",
                style: "background: var(--color-input-bg); border: 1px solid {border_color}; color: var(--color-text-primary)",
                r#type: "{input_type}",
                placeholder: props.placeholder.as_deref().unwrap_or(""),
                value: props.value.as_deref().unwrap_or(""),
                disabled: props.disabled,
                oninput: move |e| props.oninput.call(e.value()),
                onkeydown: move |e| props.onkeydown.call(e),
            }
            if let Some(ref error) = props.error {
                span {
                    class: "text-xs",
                    style: "color: var(--color-error)",
                    "{error}"
                }
            } else if let Some(ref helper) = props.helper {
                span {
                    class: "text-xs",
                    style: "color: var(--color-text-muted)",
                    "{helper}"
                }
            }
        }
    }
}

/// Текстовое поле ввода (textarea) с поддержкой label и ошибок.
///
/// # Пример
/// ```ignore
/// Textarea {
///     value: "{notes}",
///     placeholder: "Заметки...",
///     label: "Примечания",
///     oninput: move |e| notes.set(e.value()),
/// }
/// ```
#[derive(Props, Clone, PartialEq)]
pub struct TextareaProps {
    #[props(default)]
    pub value: Option<String>,
    #[props(default)]
    pub placeholder: Option<String>,
    #[props(default)]
    pub label: Option<String>,
    #[props(default)]
    pub error: Option<String>,
    #[props(default)]
    pub helper: Option<String>,
    #[props(default)]
    pub disabled: bool,
    #[props(default)]
    pub rows: Option<u32>,
    #[props(default)]
    pub class: Option<String>,
    #[props(optional)]
    pub oninput: EventHandler<String>,
}

#[component]
pub fn Textarea(props: TextareaProps) -> Element {
    let border_color = if props.error.is_some() {
        "var(--color-error)"
    } else {
        "var(--color-input-border)"
    };
    let extra_class = props.class.as_deref().unwrap_or("");

    rsx! {
        div { class: "flex flex-col gap-1",
            if let Some(ref label) = props.label {
                label {
                    class: "text-xs font-medium",
                    style: "color: var(--color-text-muted)",
                    "{label}"
                }
            }
            textarea {
                class: "w-full rounded p-3 text-sm resize-y outline-none {extra_class}",
                style: "background: var(--color-input-bg); border: 1px solid {border_color}; color: var(--color-text-primary)",
                rows: props.rows.unwrap_or(4),
                placeholder: props.placeholder.as_deref().unwrap_or(""),
                value: props.value.as_deref().unwrap_or(""),
                disabled: props.disabled,
                oninput: move |e| props.oninput.call(e.value()),
            }
            if let Some(ref error) = props.error {
                span { class: "text-xs", style: "color: var(--color-error)", "{error}" }
            } else if let Some(ref helper) = props.helper {
                span { class: "text-xs", style: "color: var(--color-text-muted)", "{helper}" }
            }
        }
    }
}
