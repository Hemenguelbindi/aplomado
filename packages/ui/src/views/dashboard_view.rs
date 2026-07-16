use crate::components::{Badge, BadgeVariant, Button, ButtonVariant, Card, EmptyState};
use crate::models::HostInfo;
use crate::ScanStatusUi;
use dioxus::prelude::*;
use kestrel_core::history::ScanRecord;

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
    let alive_hosts = props.hosts.iter().filter(|h| h.alive).count();
    let total_hosts = props.hosts.len();
    let open_ports: usize = props.hosts.iter().map(|h| h.ports.len()).sum();
    let vuln_count: usize = props
        .hosts
        .iter()
        .flat_map(|h| h.ports.iter())
        .filter(|p| !p.cves.is_empty())
        .count();

    let critical_vulns: Vec<(&HostInfo, &crate::models::PortInfo, &crate::models::CveSummary)> =
        props
            .hosts
            .iter()
            .flat_map(|h| {
                h.ports
                    .iter()
                    .flat_map(move |p| p.cves.iter().map(move |c| (h, p, c)))
            })
            .filter(|(_, _, cve)| {
                cve.severity.to_lowercase() == "critical" || cve.severity.to_lowercase() == "high"
            })
            .collect();

    let recent_scans: Vec<&ScanRecord> = props.history.iter().take(5).collect();

    let last_scan_time = props.history.first().map(|r| r.timestamp.as_str());

    let alive_pct = if total_hosts > 0 { alive_hosts * 100 / total_hosts } else { 0 };

    rsx! {
        div { class: "p-8 max-w-7xl mx-auto",
            // Header
            div { class: "flex items-center justify-between mb-8",
                div {
                    h1 {
                        class: "text-2xl font-bold",
                        style: "color: var(--color-text-primary)",
                        "Dashboard"
                    }
                    p {
                        class: "text-sm mt-1",
                        style: "color: var(--color-text-muted)",
                        if let Some(time) = last_scan_time {
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

            // ── Stats Cards ──────────────────────────────────
            div { class: "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8",
                // Hosts
                Card {
                    div { class: "flex items-center justify-between",
                        div {
                            p { class: "text-sm font-medium", style: "color: var(--color-text-muted)", "Хосты" }
                            p { class: "text-3xl font-bold mt-1", style: "color: var(--color-text-primary)", "{alive_hosts}" }
                            p { class: "text-xs mt-1", style: "color: var(--color-text-muted)", "из {total_hosts} обнаружено" }
                        }
                        div {
                            class: "w-12 h-12 rounded-lg flex items-center justify-center text-2xl",
                            style: "background: rgba(63,185,80,0.15)",
                            "🖥"
                        }
                    }
                }

                // Open Ports
                Card {
                    div { class: "flex items-center justify-between",
                        div {
                            p { class: "text-sm font-medium", style: "color: var(--color-text-muted)", "Открытые порты" }
                            p { class: "text-3xl font-bold mt-1", style: "color: var(--color-text-primary)", "{open_ports}" }
                        }
                        div {
                            class: "w-12 h-12 rounded-lg flex items-center justify-center text-2xl",
                            style: "background: rgba(88,166,255,0.15)",
                            "🔌"
                        }
                    }
                }

                // Vulnerabilities
                Card {
                    div { class: "flex items-center justify-between",
                        div {
                            p { class: "text-sm font-medium", style: "color: var(--color-text-muted)", "Уязвимости" }
                            p { class: "text-3xl font-bold mt-1",
                                style: if vuln_count > 0 { "color: var(--color-danger)" } else { "color: var(--color-text-primary)" },
                                "{vuln_count}"
                            }
                        }
                        div {
                            class: "w-12 h-12 rounded-lg flex items-center justify-center text-2xl",
                            style: if vuln_count > 0 { "background: rgba(248,81,73,0.15)" } else { "background: rgba(63,185,80,0.15)" },
                            "🛡"
                        }
                    }
                }

                // Last Scan
                Card {
                    div { class: "flex items-center justify-between",
                        div {
                            p { class: "text-sm font-medium", style: "color: var(--color-text-muted)", "Последнее сканирование" }
                            p { class: "text-lg font-bold mt-1", style: "color: var(--color-text-primary)",
                                if let Some(record) = props.history.first() {
                                    "{record.hosts_alive}/{record.hosts_total} хостов"
                                } else {
                                    "—"
                                }
                            }
                            p { class: "text-xs mt-1", style: "color: var(--color-text-muted)",
                                if let Some(record) = props.history.first() {
                                    "{record.ports_total} портов · {record.duration_secs}с"
                                } else {
                                    "Нет данных"
                                }
                            }
                        }
                        div {
                            class: "w-12 h-12 rounded-lg flex items-center justify-center text-2xl",
                            style: "background: rgba(139,148,158,0.15)",
                            "📊"
                        }
                    }
                }
            }

            // ── Quick Actions + Network Overview ─────────────
            div { class: "grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8",
                // Quick Actions
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

                // Network Overview
                Card {
                    title: "Обзор сети",
                    div { class: "space-y-4",
                        // Alive vs Down
                        div {
                            p { class: "text-sm mb-2", style: "color: var(--color-text-secondary)", "Хосты в сети" }
                            div { class: "flex items-center gap-3",
                                div { class: "flex-1 h-2 rounded-full overflow-hidden", style: "background: var(--color-border)",
                                    div {
                                        class: "h-full rounded-full",
                                        style: "width: {alive_pct}%; background: var(--color-success)"
                                    }
                                }
                                span { class: "text-xs font-medium", style: "color: var(--color-text-muted)",
                                    "{alive_hosts}/{total_hosts}"
                                }
                            }
                        }

                        // Top services
                        if !props.hosts.is_empty() {
                            div {
                                p { class: "text-sm mb-2", style: "color: var(--color-text-secondary)", "Популярные сервисы" }
                                {render_top_services(&props.hosts)}
                            }
                        }

                        // Status
                        div { class: "flex items-center gap-2 mt-2",
                            match &props.scan_status {
                                ScanStatusUi::Idle => rsx! {
                                    Badge { variant: BadgeVariant::Default, "Готов к сканированию" }
                                },
                                ScanStatusUi::Scanning { current, total } => rsx! {
                                    Badge { variant: BadgeVariant::Warning, pulse: true, "Сканирование {current}/{total}" }
                                },
                                ScanStatusUi::Done(count) => rsx! {
                                    Badge { variant: BadgeVariant::Success, "Завершено: {count} хостов" }
                                },
                                ScanStatusUi::Error(msg) => rsx! {
                                    Badge { variant: BadgeVariant::Error, "Ошибка: {msg}" }
                                },
                            }
                        }
                    }
                }

                // Critical Alerts
                Card {
                    title: "Критические уведомления",
                    if critical_vulns.is_empty() {
                        div { class: "text-center py-4",
                            p { class: "text-sm", style: "color: var(--color-text-muted)", "Нет критических уязвимостей" }
                        }
                    } else {
                        div { class: "space-y-3 max-h-64 overflow-y-auto",
                            for (host, port, cve) in critical_vulns.iter().take(10) {
                                div {
                                    class: "flex items-center justify-between p-2 rounded",
                                    style: "background: var(--color-input-bg)",
                                    div { class: "flex items-center gap-2",
                                        Badge {
                                            variant: if cve.severity.to_lowercase() == "critical" { BadgeVariant::Error } else { BadgeVariant::Warning },
                                            "{cve.severity}"
                                        }
                                        div {
                                            p { class: "text-sm font-mono font-medium", style: "color: var(--color-text-primary)", "{cve.id}" }
                                            p { class: "text-xs", style: "color: var(--color-text-muted)",
                                                "{host.ip}:{port.port} · CVSS {cve.cvss_score}"
                                            }
                                        }
                                    }
                                }
                            }
                            if critical_vulns.len() > 10 {
                                p { class: "text-xs text-center mt-2", style: "color: var(--color-text-muted)",
                                    "и ещё {critical_vulns.len() - 10} уязвимостей..."
                                }
                            }
                        }
                    }
                }
            }

            // ── Recent Scans ──────────────────────────────────
            if !recent_scans.is_empty() {
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
                                for record in recent_scans {
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
                                        td { class: "py-2 px-3", style: "color: var(--color-text-muted)", "{record.timestamp}" }
                                        td { class: "py-2 px-3", style: "color: var(--color-text-muted)", "{record.duration_secs}с" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── Empty State ───────────────────────────────────
            if props.hosts.is_empty() && props.history.is_empty() {
                EmptyState {
                    icon: "🦅",
                    title: "KESTREL Dashboard",
                    description: "Запустите первое сканирование сети, чтобы увидеть статистику и уведомления здесь.",
                }
            }
        }
    }
}

/// Render top 5 services as a mini bar chart
fn render_top_services(hosts: &[HostInfo]) -> Element {
    let mut service_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for host in hosts {
        for port in &host.ports {
            *service_counts
                .entry(port.service_name.clone())
                .or_insert(0) += 1;
        }
    }

    let mut services: Vec<(String, usize)> = service_counts.into_iter().collect();
    services.sort_by(|a, b| b.1.cmp(&a.1));
    let max_count = services.first().map(|s| s.1).unwrap_or(1).max(1);

    rsx! {
        div { class: "space-y-2",
            for (service, count) in services.iter().take(5) {
                div { class: "flex items-center gap-2",
                    span { class: "text-xs w-16 truncate", style: "color: var(--color-text-secondary)", "{service}" }
                    div { class: "flex-1 h-1.5 rounded-full overflow-hidden", style: "background: var(--color-border)",
                        div {
                            class: "h-full rounded-full",
                            style: "width: {count * 100 / max_count}%; background: var(--color-primary)"
                        }
                    }
                    span { class: "text-xs font-mono", style: "color: var(--color-text-muted)", "{count}" }
                }
            }
        }
    }
}
