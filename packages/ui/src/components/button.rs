use dioxus::prelude::*;

/// Визуальные варианты кнопки
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum ButtonVariant {
    #[default]
    Primary,
    Secondary,
    Danger,
    Ghost,
    Icon,
}

/// Размеры кнопки
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum ButtonSize {
    Sm,
    #[default]
    Md,
    Lg,
}

/// Переиспользуемая кнопка с поддержкой вариантов и размеров.
///
/// # Пример
/// ```ignore
/// Button {
///     variant: ButtonVariant::Primary,
///     onclick: move |_| handle_click(),
///     "Запустить"
/// }
/// ```
#[derive(Props, Clone, PartialEq)]
pub struct ButtonProps {
    pub variant: ButtonVariant,
    #[props(default)]
    pub size: ButtonSize,
    #[props(default)]
    pub disabled: bool,
    #[props(default)]
    pub class: Option<String>,
    #[props(optional)]
    pub onclick: EventHandler<()>,
    pub children: Element,
}

#[component]
pub fn Button(props: ButtonProps) -> Element {
    let base = "inline-flex items-center justify-center rounded font-medium cursor-pointer transition-colors duration-150 hover:opacity-80 disabled:opacity-50 disabled:cursor-not-allowed";

    let size_class = match props.size {
        ButtonSize::Sm => "px-2 py-1 text-xs",
        ButtonSize::Md => "px-3 py-2 text-sm",
        ButtonSize::Lg => "px-6 py-3 text-base font-semibold",
    };

    let variant_style = match props.variant {
        ButtonVariant::Primary => {
            "background: var(--color-primary); color: var(--color-text-primary)"
        }
        ButtonVariant::Secondary => {
            "background: var(--color-border); color: var(--color-text-secondary)"
        }
        ButtonVariant::Danger => {
            "background: var(--color-danger); color: var(--color-text-primary)"
        }
        ButtonVariant::Ghost => "background: transparent; color: var(--color-text-muted)",
        ButtonVariant::Icon => {
            "background: transparent; color: var(--color-text-muted); padding: 0.25rem"
        }
    };

    let extra_class = props.class.as_deref().unwrap_or("");

    rsx! {
        button {
            class: "{base} {size_class} {extra_class}",
            style: "{variant_style}",
            disabled: props.disabled,
            onclick: move |_| props.onclick.call(()),
            {props.children}
        }
    }
}
