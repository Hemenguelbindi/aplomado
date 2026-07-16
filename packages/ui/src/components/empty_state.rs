use dioxus::prelude::*;

/// Пустое состояние с иконкой, заголовком, описанием и опциональным действием.
///
/// # Пример
/// ```ignore
/// EmptyState {
///     icon: "🔍",
///     title: "Нет данных",
///     description: "Запустите сканирование для получения результатов",
///     action: rsx! {
///         Button { variant: ButtonVariant::Primary, onclick: move |_| start_scan(), "Сканировать" }
///     },
/// }
/// ```
#[derive(Props, Clone, PartialEq)]
pub struct EmptyStateProps {
    #[props(default)]
    pub icon: Option<String>,
    #[props(default)]
    pub title: Option<String>,
    #[props(default)]
    pub description: Option<String>,
    #[props(optional)]
    pub action: Option<Element>,
    #[props(default)]
    pub class: Option<String>,
}

#[component]
pub fn EmptyState(props: EmptyStateProps) -> Element {
    let extra_class = props.class.as_deref().unwrap_or("");

    rsx! {
        div {
            class: "text-center py-12 {extra_class}",
            if let Some(ref icon) = props.icon {
                div {
                    class: "text-4xl mb-4",
                    "{icon}"
                }
            }
            if let Some(ref title) = props.title {
                h3 {
                    class: "text-lg font-semibold mb-2",
                    style: "color: var(--color-text-primary)",
                    "{title}"
                }
            }
            if let Some(ref description) = props.description {
                p {
                    class: "text-sm mb-4",
                    style: "color: var(--color-text-muted)",
                    "{description}"
                }
            }
            if let Some(ref action) = props.action {
                div { class: "flex justify-center", {action} }
            }
        }
    }
}
