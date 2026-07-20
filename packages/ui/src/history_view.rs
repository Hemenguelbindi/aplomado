use crate::components::{EmptyState, Icon, IconName, IconSize};
use crate::helpers::format_datetime;
use aplomado_core::history::ScanRecord;
use dioxus::prelude::*;

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
                title: "Нет сохранённых сканов",
                description: "Запустите сканирование, чтобы увидеть результаты здесь.",
            }
        };
    }

    rsx! {
        div { class: "overflow-x-auto",
            table { class: "w-full text-sm text-left",
                thead {
                    tr { class: "text-muted-foreground border-b border-border",
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
                                class: "border-b border-border cursor-pointer hover:bg-surface-muted/30",
                                td { class: "py-2 px-3 text-muted-foreground", "{format_datetime(&record.timestamp)}" }
                                td { class: "py-2 px-3 font-mono text-xs text-foreground", "{first_target}{extra}" }
                                td { class: "py-2 px-3 text-muted-foreground", "{record.hosts_total}" }
                                td { class: "py-2 px-3 text-success", "{record.hosts_alive}" }
                                td { class: "py-2 px-3 text-muted-foreground", "{record.ports_total}" }
                                td { class: "py-2 px-3 text-muted-foreground", "{record.duration_secs}s" }
                                td { class: "py-2 px-3",
                                    button {
                                        class: "flex items-center justify-center w-6 h-6 rounded cursor-pointer text-muted-foreground hover:text-danger bg-transparent border-none",
                                        onclick: move |e: Event<MouseData>| {
                                            e.stop_propagation();
                                            props.on_delete.call(del_id.clone());
                                        },
                                        Icon { name: IconName::Trash2, size: IconSize::Sm }
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
