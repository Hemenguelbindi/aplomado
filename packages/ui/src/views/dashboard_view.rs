use crate::components::dashboard::{
    calculate_stats, CriticalAlertsCard, RecentScansTable, StatCard, TopServicesChart,
};
use crate::components::{Badge, BadgeVariant, Button, ButtonVariant, Card, EmptyState};
use crate::helpers::pluralize;
use crate::models::HostInfo;
use crate::ScanStatusUi;
use dioxus::prelude::*;
use aplomado_core::history::ScanRecord;

// ---------------------------------------------------------------------------
// Props — unchanged
// ---------------------------------------------------------------------------

#[derive(Props, Clone, PartialEq)]
pub struct DashboardViewProps {
    pub hosts: Vec<HostInfo>,
    pub history: Vec<ScanRecord>,
    pub scan_status: ScanStatusUi,
    pub on_navigate_to_scan: EventHandler<()>,
    pub on_navigate_to_hosts: EventHandler<()>,
    pub on_navigate_to_history: EventHandler<()>,
}

// ---------------------------------------------------------------------------
// Main component — orchestrator
// ---------------------------------------------------------------------------

#[component]
pub fn DashboardView(props: DashboardViewProps) -> Element {
    let stats = calculate_stats(&props.hosts, &props.history);

    rsx! {
        div { class: "p-8 max-w-7xl mx-auto",
            // Header
            div { class: "flex items-center justify-between mb-8",
                div {
                    h1 { class: "text-2xl font-bold", style: "color: var(--color-text-primary)", "Панель управления" }
                    p { class: "text-sm mt-1", style: "color: var(--color-text-muted)",
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
                    "Обзор сети"
                }
            }

            // Stats Cards
            div { class: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8",
                StatCard {
                    label: "Хосты".to_string(),
                    value: stats.alive_hosts.to_string(),
                    subtext: Some(format!("из {} обнаружено", stats.total_hosts)),
                    icon: "🖥",
                    icon_bg: "rgba(63,185,80,0.15)".to_string(),
                }
                StatCard {
                    label: "Открытые порты".to_string(),
                    value: stats.open_ports.to_string(),
                    icon: "🔌",
                    icon_bg: "rgba(88,166,255,0.15)".to_string(),
                }
                StatCard {
                    label: "Уязвимости".to_string(),
                    value: stats.vuln_count.to_string(),
                    icon: "🛡",
                    icon_bg: if stats.vuln_count > 0 {
                        "rgba(248,81,73,0.15)".to_string()
                    } else {
                        "rgba(63,185,80,0.15)".to_string()
                    },
                    danger: stats.vuln_count > 0,
                }
                StatCard {
                    label: "Последнее сканирование".to_string(),
                    value: stats.alive_summary.clone().unwrap_or_else(|| "—".to_string()),
                    subtext: stats.ports_summary.clone(),
                    icon: "📊",
                    icon_bg: "rgba(139,148,158,0.15)".to_string(),
                    large_value: false,
                }
            }

            // Quick Actions + Network Overview + Critical Alerts
            div { class: "grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8",
                Card {
                    title: "Быстрые действия",
                    div { class: "flex flex-col gap-3",
                        Button {
                            variant: ButtonVariant::Primary,
                            onclick: move |_| props.on_navigate_to_scan.call(()),
                            "🔍  Новое сканирование"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            onclick: move |_| props.on_navigate_to_history.call(()),
                            "📋  История сканов"
                        }
                    }
                }
                Card {
                    title: "Обзор сети",
                    div { class: "space-y-4",
                        div {
                            p { class: "text-sm mb-2", style: "color: var(--color-text-secondary)", "Хосты в сети" }
                            div { class: "flex items-center gap-3",
                                div { class: "flex-1 h-2 rounded-full overflow-hidden", style: "background: var(--color-border)",
                                    div {
                                        class: "h-full rounded-full",
                                        style: "width: {stats.alive_pct}%; background: var(--color-success)"
                                    }
                                }
                                span { class: "text-xs font-medium", style: "color: var(--color-text-muted)",
                                    "{stats.alive_hosts}/{stats.total_hosts}"
                                }
                            }
                        }
                        if !props.hosts.is_empty() {
                            div {
                                p { class: "text-sm mb-2", style: "color: var(--color-text-secondary)", "Популярные сервисы" }
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

            // Recent Scans
            if !stats.recent_scans.is_empty() {
                RecentScansTable { scans: stats.recent_scans }
            }

            // Empty State
            if props.hosts.is_empty() && props.history.is_empty() {
                EmptyState {
                    icon: "🦅",
                    title: "APLOMADO — Панель управления",
                    description: "Запустите первое сканирование сети, чтобы увидеть статистику и уведомления здесь.",
                }
            }
        }
    }
}
