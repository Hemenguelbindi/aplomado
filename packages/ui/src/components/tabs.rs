use dioxus::prelude::*;

/// Определение одной вкладки
#[derive(Clone, PartialEq, Debug)]
pub struct TabDef {
    pub id: String,
    pub label: String,
    pub icon: Option<String>,
}

/// Горизонтальные вкладки с поддержкой иконок.
///
/// # Пример
/// ```ignore
/// let mut active = use_signal(|| "overview".to_string());
/// Tabs {
///     tabs: vec![
///         TabDef { id: "overview".into(), label: "Overview".into(), icon: None },
///         TabDef { id: "ports".into(), label: "Ports".into(), icon: None },
///     ],
///     active: active(),
///     on_select: move |id| active.set(id),
/// }
/// ```
#[derive(Props, Clone, PartialEq)]
pub struct TabsProps {
    pub tabs: Vec<TabDef>,
    pub active: String,
    #[props(optional)]
    pub on_select: EventHandler<String>,
    #[props(default)]
    pub class: Option<String>,
}

#[component]
pub fn Tabs(props: TabsProps) -> Element {
    let extra_class = props.class.as_deref().unwrap_or("");

    rsx! {
        div {
            class: "flex gap-1 border-b {extra_class}",
            style: "border-color: var(--color-border-light)",
            {props.tabs.iter().map(|tab| {
                let is_active = props.active == tab.id;
                let tab_id = tab.id.clone();
                let (tab_style, border_bottom) = if is_active {
                    ("var(--color-primary)", "2px solid var(--color-primary)")
                } else {
                    ("var(--color-text-muted)", "2px solid transparent")
                };
                rsx! {
                    button {
                        key: "{tab.id}",
                        class: "px-3 py-1.5 text-sm font-medium cursor-pointer flex items-center gap-1.5",
                        style: "color: {tab_style}; border-bottom: {border_bottom}",
                        onclick: move |_| props.on_select.call(tab_id.clone()),
                        if let Some(ref icon) = tab.icon {
                            span { class: "text-base", "{icon}" }
                        }
                        "{tab.label}"
                    }
                }
            })}
        }
    }
}
