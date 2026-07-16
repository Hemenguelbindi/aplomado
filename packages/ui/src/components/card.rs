use dioxus::prelude::*;

/// Варианты карточки
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CardVariant {
    /// Обычная карточка с surface фоном
    Default,
    /// Карточка с input-bg фоном (для форм, полей ввода)
    Input,
    /// Карточка с border-light фоном (для выделенных секций)
    Highlight,
}

impl Default for CardVariant {
    fn default() -> Self { CardVariant::Default }
}

/// Переиспользуемая карточка-контейнер с опциональным заголовком и действиями.
///
/// # Пример
/// ```ignore
/// Card {
///     title: "Настройки",
///     variant: CardVariant::Default,
///     actions: rsx! { Button { variant: ButtonVariant::Ghost, "Сохранить" } },
///     rsx! { p { "Содержимое карточки" } }
/// }
/// ```
#[derive(Props, Clone, PartialEq)]
pub struct CardProps {
    #[props(default)]
    pub title: Option<String>,
    #[props(default)]
    pub variant: CardVariant,
    #[props(optional)]
    pub actions: Option<Element>,
    pub children: Element,
}

#[component]
pub fn Card(props: CardProps) -> Element {
    let (bg, border) = match props.variant {
        CardVariant::Default => ("var(--color-surface)", "var(--color-border)"),
        CardVariant::Input => ("var(--color-input-bg)", "var(--color-input-border)"),
        CardVariant::Highlight => ("var(--color-surface)", "var(--color-border-light)"),
    };

    let has_header = props.title.is_some() || props.actions.is_some();

    rsx! {
        div {
            class: "border rounded-lg p-4",
            style: "background: {bg}; border-color: {border}",
            if has_header {
                div {
                    class: "flex items-center justify-between mb-3",
                    div { class: "flex items-center gap-2",
                        if let Some(ref title) = props.title {
                            h3 {
                                class: "text-lg font-semibold",
                                style: "color: var(--color-text-primary)",
                                "{title}"
                            }
                        }
                    }
                    if let Some(ref actions) = props.actions {
                        div { class: "flex items-center gap-2", {actions} }
                    }
                }
            }
            {props.children}
        }
    }
}
