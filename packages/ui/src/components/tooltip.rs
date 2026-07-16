use dioxus::prelude::*;

/// Позиция тултипа относительно триггера
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TooltipPosition {
    Top,
    Bottom,
    Left,
    Right,
}

impl Default for TooltipPosition {
    fn default() -> Self { TooltipPosition::Top }
}

/// Тултип, появляющийся при наведении на триггер.
/// Использует CSS-only подход через Tailwind `group` / `group-hover`.
///
/// # Пример
/// ```ignore
/// Tooltip {
///     text: "Скопировать IP",
///     position: TooltipPosition::Top,
///     rsx! { span { class: "cursor-pointer", "📋" } }
/// }
/// ```
#[derive(Props, Clone, PartialEq)]
pub struct TooltipProps {
    pub text: String,
    #[props(default)]
    pub position: TooltipPosition,
    pub children: Element,
}

#[component]
pub fn Tooltip(props: TooltipProps) -> Element {
    let position_style = match props.position {
        TooltipPosition::Top => "bottom: 100%; left: 50%; transform: translateX(-50%); margin-bottom: 4px",
        TooltipPosition::Bottom => "top: 100%; left: 50%; transform: translateX(-50%); margin-top: 4px",
        TooltipPosition::Left => "right: 100%; top: 50%; transform: translateY(-50%); margin-right: 4px",
        TooltipPosition::Right => "left: 100%; top: 50%; transform: translateY(-50%); margin-left: 4px",
    };

    rsx! {
        div { class: "group relative inline-flex",
            {props.children}
            div {
                class: "absolute z-50 hidden group-hover:block px-2 py-1 text-xs rounded whitespace-nowrap pointer-events-none",
                style: "background: var(--color-overlay); color: var(--color-text-primary); {position_style}",
                "{props.text}"
            }
        }
    }
}
