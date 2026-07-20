use dioxus::prelude::*;

#[derive(Clone, PartialEq, Debug)]
pub struct TabDef {
    pub id: String,
    pub label: String,
    pub icon: Option<String>,
}

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
            class: "flex gap-1 border-b border-border {extra_class}",
            role: "tablist",
            {props.tabs.iter().map(|tab| {
                let is_active = props.active == tab.id;
                let tab_id = tab.id.clone();
                let tab_style = if is_active { "text-primary border-b-2 border-primary" } else { "text-muted-foreground border-b-2 border-transparent" };
                rsx! {
                    button {
                        key: "{tab.id}",
                        class: "px-3 py-1.5 text-sm font-medium cursor-pointer flex items-center gap-1.5 bg-transparent {tab_style}",
                        role: "tab",
                        "aria-selected": if is_active { "true" } else { "false" },
                        "aria-controls": "tabpanel-{tab.id}",
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
