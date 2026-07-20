use crate::components::Card;
use crate::helpers::format_datetime;
use aplomado_core::history::ScanRecord;
use dioxus::prelude::*;

#[component]
pub fn RecentScansTable(scans: Vec<ScanRecord>) -> Element {
    rsx! {
        Card {
            title: "Последние сканирования",
            div { class: "overflow-x-auto",
                table { class: "w-full text-sm",
                    thead {
                        tr { class: "border-b", style: "border-color: var(--color-border)",
                            th { class: "text-left py-2 px-3 font-medium", style: "color: var(--color-text-muted)", "Метка" }
                            th { class: "text-left py-2 px-3 font-medium", style: "color: var(--color-text-muted)", "Цели" }
                            th { class: "text-left py-2 px-3 font-medium", style: "color: var(--color-text-muted)", "Хосты" }
                            th { class: "text-left py-2 px-3 font-medium", style: "color: var(--color-text-muted)", "Порты" }
                            th { class: "text-left py-2 px-3 font-medium", style: "color: var(--color-text-muted)", "Дата" }
                            th { class: "text-left py-2 px-3 font-medium", style: "color: var(--color-text-muted)", "Время" }
                        }
                    }
                    tbody {
                        for record in scans {
                            tr {
                                class: "border-b hover:opacity-80",
                                style: "border-color: var(--color-border-light); cursor: pointer",
                                td { class: "py-2 px-3 font-medium", style: "color: var(--color-text-primary)", "{record.label}" }
                                td { class: "py-2 px-3", style: "color: var(--color-text-secondary)", "{record.targets.join(\", \")}" }
                                td { class: "py-2 px-3",
                                    span { style: "color: var(--color-success)", "{record.hosts_alive}" }
                                    span { style: "color: var(--color-text-muted)", " / {record.hosts_total}" }
                                }
                                td { class: "py-2 px-3", style: "color: var(--color-text-secondary)", "{record.ports_total}" }
                                td { class: "py-2 px-3", style: "color: var(--color-text-muted)", "{format_datetime(&record.timestamp)}" }
                                td { class: "py-2 px-3", style: "color: var(--color-text-muted)", "{record.duration_secs}с" }
                            }
                        }
                    }
                }
            }
        }
    }
}
