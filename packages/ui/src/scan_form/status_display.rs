use crate::components::ProgressBar;
use crate::helpers::pluralize;
use crate::scan_form::ScanStatusUi;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct StatusDisplayProps {
    pub status: ScanStatusUi,
    pub targets_empty: bool,
}

#[component]
pub fn StatusDisplay(props: StatusDisplayProps) -> Element {
    rsx! {
        match &props.status {
            ScanStatusUi::Idle => rsx! {
                div {
                    class: "text-center text-sm",
                    style: "color: var(--color-text-muted)",
                    if props.targets_empty {
                        "Добавьте цели для сканирования"
                    } else {
                        "Готов к сканированию"
                    }
                }
            },
            ScanStatusUi::Scanning { current, total } => {
                let pct = if *total > 0 {
                    (*current as f64 / *total as f64) * 100.0
                } else { 0.0 };
                let label = if *total > 0 {
                    format!("Сканирование... {}/{}", current, pluralize(*total as usize, "хост", "хоста", "хостов"))
                } else {
                    "Сканирование...".to_string()
                };
                rsx! {
                    ProgressBar {
                        value: pct,
                        label: "{label}",
                        animated: *current == 0,
                    }
                }
            },
            ScanStatusUi::Done(count) => {
                let found = pluralize(*count as usize, "хост", "хоста", "хостов");
                rsx! {
                    div {
                        class: "text-center text-sm",
                        style: "color: var(--color-success)",
                        "Сканирование завершено. Найдено: {found}"
                    }
                }
            },
            ScanStatusUi::Error(e) => rsx! {
                div {
                    class: "text-center text-sm",
                    style: "color: var(--color-error)",
                    "Ошибка: {e}"
                }
            },
        }
    }
}
