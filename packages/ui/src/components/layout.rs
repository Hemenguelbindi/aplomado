use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct AppShellProps {
    pub children: Element,
}

#[component]
pub fn AppShell(props: AppShellProps) -> Element {
    rsx! {
        div { class: "min-h-screen flex flex-col bg-background",
            {props.children}
        }
    }
}

#[derive(Props, Clone, PartialEq)]
pub struct PageContainerProps {
    #[props(default)]
    pub class: Option<String>,
    #[props(default)]
    pub wide: bool,
    pub children: Element,
}

#[component]
pub fn PageContainer(props: PageContainerProps) -> Element {
    let width_class = if props.wide { "" } else { "max-w-6xl" };
    let extra = props.class.as_deref().unwrap_or("");
    rsx! {
        div { class: "px-4 sm:px-6 lg:px-8 py-5 sm:py-6 lg:py-8 mx-auto w-full {width_class} {extra}",
            {props.children}
        }
    }
}

#[derive(Props, Clone, PartialEq)]
pub struct PageHeaderProps {
    pub title: String,
    #[props(default)]
    pub description: Option<String>,
    #[props(optional)]
    pub actions: Option<Element>,
    #[props(optional)]
    pub breadcrumbs: Option<Element>,
}

#[component]
pub fn PageHeader(props: PageHeaderProps) -> Element {
    rsx! {
        div { class: "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 mb-6 sm:mb-8",
            div { class: "min-w-0",
                if let Some(ref bread) = props.breadcrumbs {
                    div { class: "flex items-center gap-1 text-xs text-muted-foreground mb-1",
                        {bread}
                    }
                }
                h1 { class: "text-2xl font-bold text-foreground",
                    "{props.title}"
                }
                if let Some(ref desc) = props.description {
                    p { class: "text-sm text-muted-foreground mt-1",
                        "{desc}"
                    }
                }
            }
            if let Some(ref actions) = props.actions {
                div { class: "flex items-center gap-2 flex-shrink-0",
                    {actions}
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
pub struct PageSectionProps {
    pub title: String,
    #[props(default)]
    pub description: Option<String>,
    #[props(optional)]
    pub actions: Option<Element>,
    pub children: Element,
}

#[component]
pub fn PageSection(props: PageSectionProps) -> Element {
    rsx! {
        div { class: "mb-6",
            div { class: "flex items-center justify-between mb-3",
                div {
                    h2 { class: "text-lg font-semibold text-foreground", "{props.title}" }
                    if let Some(ref desc) = props.description {
                        p { class: "text-sm text-muted-foreground mt-0.5", "{desc}" }
                    }
                }
                if let Some(ref actions) = props.actions {
                    div { class: "flex items-center gap-2", {actions} }
                }
            }
            {props.children}
        }
    }
}
