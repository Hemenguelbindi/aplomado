use dioxus::prelude::*;
use crate::components::EmptyState;
use kestrel_core::history::ScanRecord;

#[derive(Props, Clone, PartialEq)]
pub struct HistoryViewProps {
    pub records: Vec<ScanRecord>,
    pub on_select: EventHandler<String>,
    pub on_delete: EventHandler<String>,
}

#[component]
pub fn HistoryView(props: HistoryViewProps) -> Element {
    if props.records.is_empty() {
        return rsx! {
            EmptyState {
                icon: "📋",
                title: "Нет сохранённых сканов",
                description: "Запустите сканирование, чтобы увидеть результаты здесь.",
            }
        };
    }

    rsx! {
        div { class: "overflow-x-auto",
            table { class: "w-full text-sm text-left",
                thead {
                    tr {
                        style: "color: var(--color-text-muted); border-bottom: 1px solid var(--color-border)",
                        th { class: "py-2 px-3", "Дата" }
                        th { class: "py-2 px-3", "Цели" }
                        th { class: "py-2 px-3", "Хостов" }
                        th { class: "py-2 px-3", "Живых" }
                        th { class: "py-2 px-3", "Портов" }
                        th { class: "py-2 px-3", "Время" }
                        th { class: "py-2 px-3", "" }
                    }
                }
                tbody {
                    {props.records.iter().map(|record| {
                        let id = record.id.clone();
                        let first_target = record.targets.first()
                            .cloned()
                            .unwrap_or_else(|| "—".to_string());
                        let extra = if record.targets.len() > 1 {
                            format!(" (+{})", record.targets.len() - 1)
                        } else {
                            String::new()
                        };
                        let del_id = record.id.clone();

                        rsx! {
                            tr {
                                key: "{id}",
                                class: "border-b cursor-pointer",
                                style: "border-color: var(--color-border)",
                                td {
                                    class: "py-2 px-3",
                                    style: "color: var(--color-text-secondary)",
                                    "{&record.timestamp[..19.min(record.timestamp.len())].replace(\"T\", \" \")}"
                                }
                                td {
                                    class: "py-2 px-3 font-mono text-xs",
                                    style: "color: var(--color-text-primary)",
                                    "{first_target}{extra}"
                                }
                                td {
                                    class: "py-2 px-3",
                                    style: "color: var(--color-text-secondary)",
                                    "{record.hosts_total}"
                                }
                                td {
                                    class: "py-2 px-3",
                                    style: "color: var(--color-success)",
                                    "{record.hosts_alive}"
                                }
                                td {
                                    class: "py-2 px-3",
                                    style: "color: var(--color-text-secondary)",
                                    "{record.ports_total}"
                                }
                                td {
                                    class: "py-2 px-3",
                                    style: "color: var(--color-text-secondary)",
                                    "{record.duration_secs}s"
                                }
                                td { class: "py-2 px-3",
                                    button {
                                        class: "text-xs cursor-pointer",
                                        style: "color: var(--color-severity-critical); background: transparent; border: none; padding: 0.25rem",
                                        onclick: move |e: Event<MouseData>| {
                                            e.stop_propagation();
                                            props.on_delete.call(del_id.clone());
                                        },
                                        "✕"
                                    }
                                }
                            }
                        }
                    })}
                }
            }
        }
    }
}
