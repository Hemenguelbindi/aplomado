use dioxus::prelude::*;

/// Индикатор прогресса с опциональным label и анимацией.
///
/// # Пример
/// ```ignore
/// ProgressBar {
///     value: 65.0,
///     label: "Сканирование",
///     animated: true,
/// }
/// ```
#[derive(Props, Clone, PartialEq)]
pub struct ProgressBarProps {
    /// Значение от 0.0 до 100.0
    pub value: f64,
    #[props(default)]
    pub label: Option<String>,
    #[props(default)]
    pub animated: bool,
    #[props(default)]
    pub show_percentage: bool,
    #[props(default)]
    pub class: Option<String>,
}

#[component]
pub fn ProgressBar(props: ProgressBarProps) -> Element {
    let clamped = props.value.clamp(0.0, 100.0);
    let anim_class = if props.animated && clamped > 0.0 && clamped < 100.0 {
        "animate-pulse"
    } else {
        ""
    };
    let extra_class = props.class.as_deref().unwrap_or("");

    rsx! {
        div { class: "w-full {extra_class}",
            if props.label.is_some() || props.show_percentage {
                div { class: "flex items-center justify-between mb-1",
                    if let Some(ref label) = props.label {
                        span {
                            class: "text-sm",
                            style: "color: var(--color-text-muted)",
                            "{label}"
                        }
                    }
                    if props.show_percentage {
                        span {
                            class: "text-xs font-mono",
                            style: "color: var(--color-text-secondary)",
                            "{clamped:.0}%"
                        }
                    }
                }
            }
            div {
                class: "w-full h-2 rounded-full overflow-hidden",
                style: "background: var(--color-input-bg)",
                div {
                    class: "h-full rounded-full transition-all duration-300 {anim_class}",
                    style: "background: var(--color-primary); width: {clamped}%",
                }
            }
        }
    }
}
