use dioxus::prelude::*;

/// Варианты бейджа по цвету
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum BadgeVariant {
    Default,
    Primary,
    Success,
    Warning,
    Error,
    Info,
}

impl Default for BadgeVariant {
    fn default() -> Self { BadgeVariant::Default }
}

/// Размеры бейджа
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum BadgeSize {
    Sm,
    Md,
}

impl Default for BadgeSize {
    fn default() -> Self { BadgeSize::Sm }
}

/// Переиспользуемый бейдж для отображения статусов и меток.
///
/// # Пример
/// ```ignore
/// Badge { variant: BadgeVariant::Error, "Critical" }
/// Badge { variant: BadgeVariant::Success, size: BadgeSize::Md, "Alive" }
/// ```
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

    let variant_style = match props.variant {
        BadgeVariant::Default => "background: var(--color-border); color: var(--color-text-secondary)",
        BadgeVariant::Primary => "background: var(--color-surface); color: var(--color-primary)",
        BadgeVariant::Success => "background: var(--color-surface); color: var(--color-success)",
        BadgeVariant::Warning => "background: var(--color-surface); color: var(--color-warning)",
        BadgeVariant::Error => "background: rgba(248,81,73,0.15); color: var(--color-severity-critical)",
        BadgeVariant::Info => "background: var(--color-surface); color: var(--color-severity-medium)",
    };

    let pulse_class = if props.pulse { "animate-pulse" } else { "" };
    let extra_class = props.class.as_deref().unwrap_or("");

    rsx! {
        span {
            class: "inline-flex items-center rounded-full font-medium {size_class} {pulse_class} {extra_class}",
            style: "{variant_style}",
            {props.children}
        }
    }
}
