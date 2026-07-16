use dioxus::prelude::*;
use crate::components::ProgressBar;
use crate::scan_form::ScanStatusUi;

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
                    format!("Сканирование... {}/{} хостов", current, total)
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
            ScanStatusUi::Done(count) => rsx! {
                div {
                    class: "text-center text-sm",
                    style: "color: var(--color-success)",
                    "Сканирование завершено. Найдено хостов: {count}"
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
