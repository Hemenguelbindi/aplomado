use dioxus::prelude::*;

/// Опция для выпадающего списка
#[derive(Clone, PartialEq, Debug)]
pub struct SelectOption {
    pub value: String,
    pub label: String,
    pub disabled: bool,
}

impl SelectOption {
    pub fn new(value: &str, label: &str) -> Self {
        Self {
            value: value.to_string(),
            label: label.to_string(),
            disabled: false,
        }
    }
}

/// Группа опций для выпадающего списка
#[derive(Clone, PartialEq, Debug)]
pub struct SelectGroup {
    pub label: String,
    pub options: Vec<SelectOption>,
}

/// Выпадающий список с поддержкой групп опций.
///
/// # Пример
/// ```ignore
/// Select {
///     value: "{selected}",
///     options: vec![SelectOption::new("std", "Standard")],
///     label: "Пресет",
///     on_change: move |v| selected.set(v),
/// }
/// ```
#[derive(Props, Clone, PartialEq)]
pub struct SelectProps {
    #[props(default)]
    pub value: Option<String>,
    #[props(default)]
    pub options: Vec<SelectOption>,
    #[props(default)]
    pub groups: Vec<SelectGroup>,
    #[props(default)]
    pub label: Option<String>,
    #[props(default)]
    pub placeholder: Option<String>,
    #[props(default)]
    pub disabled: bool,
    #[props(default)]
    pub error: Option<String>,
    #[props(default)]
    pub class: Option<String>,
    #[props(optional)]
    pub on_change: EventHandler<String>,
}

#[component]
pub fn Select(props: SelectProps) -> Element {
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
            select {
                class: "w-full rounded p-2 text-sm outline-none appearance-none cursor-pointer {extra_class}",
                style: "background: var(--color-input-bg); border: 1px solid {border_color}; color: var(--color-text-primary)",
                disabled: props.disabled,
                onchange: move |e| props.on_change.call(e.value()),
                if let Some(ref ph) = props.placeholder {
                    option { value: "", disabled: true, selected: props.value.is_none(), "{ph}" }
                }
                if !props.groups.is_empty() {
                    {props.groups.iter().map(|group| {
                        rsx! {
                            optgroup { label: "{group.label}",
                                {group.options.iter().map(|opt| {
                                    let selected = props.value.as_deref() == Some(&opt.value);
                                    rsx! {
                                        option {
                                            key: "{opt.value}",
                                            value: "{opt.value}",
                                            disabled: opt.disabled,
                                            selected: selected,
                                            "{opt.label}"
                                        }
                                    }
                                })}
                            }
                        }
                    })}
                } else {
                    {props.options.iter().map(|opt| {
                        let selected = props.value.as_deref() == Some(&opt.value);
                        rsx! {
                            option {
                                key: "{opt.value}",
                                value: "{opt.value}",
                                disabled: opt.disabled,
                                selected: selected,
                                "{opt.label}"
                            }
                        }
                    })}
                }
            }
            if let Some(ref error) = props.error {
                span { class: "text-xs", style: "color: var(--color-error)", "{error}" }
            }
        }
    }
}
