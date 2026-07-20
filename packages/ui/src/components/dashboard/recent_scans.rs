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
                        tr { class: "border-b border-border",
                            th { class: "text-left py-2 px-3 font-medium text-muted-foreground", "Метка" }
                            th { class: "text-left py-2 px-3 font-medium text-muted-foreground", "Цели" }
                            th { class: "text-left py-2 px-3 font-medium text-muted-foreground", "Хосты" }
                            th { class: "text-left py-2 px-3 font-medium text-muted-foreground", "Порты" }
                            th { class: "text-left py-2 px-3 font-medium text-muted-foreground", "Дата" }
                            th { class: "text-left py-2 px-3 font-medium text-muted-foreground", "Время" }
                        }
                    }
                    tbody {
                        for record in scans {
                            tr { class: "border-b border-border cursor-pointer hover:bg-surface-muted/30",
                                td { class: "py-2 px-3 font-medium text-foreground", "{record.label}" }
                                td { class: "py-2 px-3 text-muted-foreground", "{record.targets.join(\", \")}" }
                                td { class: "py-2 px-3",
                                    span { class: "text-success", "{record.hosts_alive}" }
                                    span { class: "text-muted-foreground", " / {record.hosts_total}" }
                                }
                                td { class: "py-2 px-3 text-muted-foreground", "{record.ports_total}" }
                                td { class: "py-2 px-3 text-muted-foreground", "{format_datetime(&record.timestamp)}" }
                                td { class: "py-2 px-3 text-muted-foreground", "{record.duration_secs}с" }
                            }
                        }
                    }
                }
            }
        }
    }
}
