use crate::components::dashboard::{
    calculate_stats, CriticalAlertsCard, RecentScansTable, StatCard, TopServicesChart,
};
use crate::components::{
    Badge, BadgeVariant, Button, ButtonVariant, Card, EmptyState, Icon, IconName, IconSize, Tone,
};
use crate::helpers::pluralize;
use crate::models::HostInfo;
use crate::ScanStatusUi;
use aplomado_core::history::ScanRecord;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct DashboardViewProps {
    pub hosts: Vec<HostInfo>,
    pub history: Vec<ScanRecord>,
    pub scan_status: ScanStatusUi,
    pub on_navigate_to_scan: EventHandler<()>,
    pub on_navigate_to_hosts: EventHandler<()>,
    pub on_navigate_to_history: EventHandler<()>,
}

#[component]
pub fn DashboardView(props: DashboardViewProps) -> Element {
    let stats = calculate_stats(&props.hosts, &props.history);

    rsx! {
        div { class: "p-8 max-w-7xl mx-auto",
            div { class: "flex items-center justify-between mb-8",
                div {
                    h1 { class: "text-2xl font-bold text-foreground", "Панель управления" }
                    p { class: "text-sm mt-1 text-muted-foreground",
                        if let Some(ref time) = stats.last_scan_time {
                            "Последнее сканирование: {time}"
                        } else {
                            "Сканирования ещё не проводились"
                        }
                    }
                }
                Button {
                    variant: ButtonVariant::Primary,
                    onclick: move |_| props.on_navigate_to_hosts.call(()),
                    Icon { name: IconName::Hosts, size: IconSize::Sm }
                    " Обзор сети"
                }
            }

            div { class: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8",
                StatCard {
                    label: "Хосты".to_string(),
                    value: stats.alive_hosts.to_string(),
                    subtext: Some(format!("из {} обнаружено", stats.total_hosts)),
                    tone: Tone::Success,
                    icon: IconName::Server,
                }
                StatCard {
                    label: "Открытые порты".to_string(),
                    value: stats.open_ports.to_string(),
                    tone: Tone::Info,
                    icon: IconName::Activity,
                }
                StatCard {
                    label: "Уязвимости".to_string(),
                    value: stats.vuln_count.to_string(),
                    tone: if stats.vuln_count > 0 { Tone::Danger } else { Tone::Success },
                    icon: IconName::Shield,
                    danger: stats.vuln_count > 0,
                }
                StatCard {
                    label: "Последнее сканирование".to_string(),
                    value: stats.alive_summary.clone().unwrap_or_else(|| "\u{2014}".to_string()),
                    subtext: stats.ports_summary.clone(),
                    tone: Tone::Neutral,
                    icon: IconName::Clock,
                    large_value: false,
                }
            }

            div { class: "grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8",
                Card {
                    title: "Быстрые действия",
                    div { class: "flex flex-col gap-3",
                        Button {
                            variant: ButtonVariant::Primary,
                            onclick: move |_| props.on_navigate_to_scan.call(()),
                            Icon { name: IconName::Scan, size: IconSize::Sm }
                            " Новое сканирование"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            onclick: move |_| props.on_navigate_to_history.call(()),
                            Icon { name: IconName::History, size: IconSize::Sm }
                            " История сканов"
                        }
                    }
                }
                Card {
                    title: "Обзор сети",
                    div { class: "space-y-4",
                        div {
                            p { class: "text-sm mb-2 text-muted-foreground", "Хосты в сети" }
                            div { class: "flex items-center gap-3",
                                div { class: "flex-1 h-2 rounded-full overflow-hidden bg-border",
                                    div {
                                        class: "h-full rounded-full bg-success",
                                        style: "width: {stats.alive_pct}%",
                                    }
                                }
                                span { class: "text-xs font-medium text-muted-foreground",
                                    "{stats.alive_hosts}/{stats.total_hosts}"
                                }
                            }
                        }
                        if !props.hosts.is_empty() {
                            div {
                                p { class: "text-sm mb-2 text-muted-foreground", "Популярные сервисы" }
                                TopServicesChart { services: stats.top_services }
                            }
                        }
                        div { class: "flex items-center gap-2 mt-2",
                            match &props.scan_status {
                                ScanStatusUi::Idle => rsx! {
                                    Badge { variant: BadgeVariant::Default, "Готов к сканированию" }
                                },
                                ScanStatusUi::Scanning { current, total } => rsx! {
                                    Badge { variant: BadgeVariant::Warning, pulse: true, "Сканирование {current}/{total}" }
                                },
                                ScanStatusUi::Done(count) => {
                                    let done_text = format!("Завершено: {}", pluralize(*count as usize, "хост", "хоста", "хостов"));
                                    rsx! { Badge { variant: BadgeVariant::Success, "{done_text}" } }
                                },
                                ScanStatusUi::Error(msg) => rsx! {
                                    Badge { variant: BadgeVariant::Error, "Ошибка: {msg}" }
                                },
                            }
                        }
                    }
                }
                CriticalAlertsCard { vulns: stats.critical_vulns }
            }

            if !stats.recent_scans.is_empty() {
                RecentScansTable { scans: stats.recent_scans }
            }

            if props.hosts.is_empty() && props.history.is_empty() {
                EmptyState {
                    title: "APLOMADO \u{2014} Панель управления",
                    description: "Запустите первое сканирование сети, чтобы увидеть статистику и уведомления здесь.",
                }
            }
        }
    }
}
