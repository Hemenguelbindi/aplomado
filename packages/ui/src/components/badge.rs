use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum BadgeVariant {
    #[default]
    Default,
    Primary,
    Success,
    Warning,
    Error,
    Info,
}

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum BadgeSize {
    #[default]
    Sm,
    Md,
}

#[derive(Props, Clone, PartialEq)]
pub struct BadgeProps {
    #[props(default)]
    pub variant: BadgeVariant,
    #[props(default)]
    pub size: BadgeSize,
    #[props(default)]
    pub pulse: bool,
    #[props(default)]
    pub class: Option<String>,
    pub children: Element,
}

#[component]
pub fn Badge(props: BadgeProps) -> Element {
    let size_class = match props.size {
        BadgeSize::Sm => "px-2 py-0.5 text-xs",
        BadgeSize::Md => "px-3 py-1 text-sm",
    };

    let variant_class = match props.variant {
        BadgeVariant::Default => "bg-border text-muted-foreground",
        BadgeVariant::Primary => "bg-primary/10 text-primary",
        BadgeVariant::Success => "bg-success/10 text-success",
        BadgeVariant::Warning => "bg-warning/10 text-warning",
        BadgeVariant::Error => "bg-danger/15 text-danger",
        BadgeVariant::Info => "bg-info/10 text-info",
    };

    let pulse_class = if props.pulse { "animate-pulse" } else { "" };
    let extra_class = props.class.as_deref().unwrap_or("");

    rsx! {
        span {
            class: "inline-flex items-center rounded-full font-medium {size_class} {variant_class} {pulse_class} {extra_class}",
            {props.children}
        }
    }
}
