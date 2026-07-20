use dioxus::prelude::*;
use peregrine_core::history::{ScanDiff, ScanRecord, diff_scans};
use ui::components::EmptyState;
use ui::helpers::format_datetime;

/// Страница сравнения двух сканов (ScanDiff).
#[component]
pub fn Diff() -> Element {
    let history = use_context::<Signal<Vec<ScanRecord>>>();
    let records = history.read().clone();

    let mut scan_a_id = use_signal(String::new);
    let mut scan_b_id = use_signal(String::new);
    let mut diff_result = use_signal(|| None::<ScanDiff>);

    let a_sel = scan_a_id();
    let b_sel = scan_b_id();

    let can_compare = !a_sel.is_empty() && !b_sel.is_empty() && a_sel != b_sel;
    let recs_for_btn = records.clone();

    rsx! {
        div { class: "p-8 max-w-6xl mx-auto",
            // --- Заголовок ---
            h1 {
                class: "text-2xl font-bold mb-6",
                style: "color: var(--color-text-primary)",
                "Сравнение сканов"
            }

            if records.is_empty() {
                EmptyState {
                    icon: "🔍",
                    title: "Нет сканов для сравнения",
                    description: "Запустите хотя бы два сканирования, чтобы увидеть различия.",
                }
            } else {
                // --- Селекторы ---
                div {
                    class: "grid grid-cols-1 md:grid-cols-2 gap-6 mb-8",
                    style: "color: var(--color-text-primary)",

                    // Scan A - колонка кнопок
                    div {
                        label { class: "block text-sm font-medium mb-2", "Скан A (базовый)" }
                        div { class: "flex flex-col gap-2",
                            {records.iter().map(|r| {
                                let id = r.id.clone();
                                let label = format!("{} | {} targets | {} hosts",
                                    &r.timestamp[..19.min(r.timestamp.len())].replace("T", " "),
                                    r.targets.join(", "),
                                    r.hosts_alive
                                );
                                let is_selected = a_sel == id;
                                rsx! {
                                    button {
                                        key: "a-{id}",
                                        class: "w-full text-left px-3 py-2 rounded text-sm font-mono transition-colors",
                                        style: if is_selected {
                                            "background: var(--color-primary); color: #fff; border: 2px solid var(--color-primary);"
                                        } else {
                                            "background: var(--color-surface); color: var(--color-text-primary); border: 1px solid var(--color-border);"
                                        },
                                        onclick: move |_| {
                                            scan_a_id.set(id.clone());
                                            diff_result.set(None);
                                        },
                                        "{label}"
                                    }
                                }
                            })}
                        }
                    }

                    // Scan B - колонка кнопок
                    div {
                        label { class: "block text-sm font-medium mb-2", "Скан B (новый)" }
                        div { class: "flex flex-col gap-2",
                            {records.iter().map(|r| {
                                let id = r.id.clone();
                                let label = format!("{} | {} targets | {} hosts",
                                    format_datetime(&r.timestamp),
                                    r.targets.join(", "),
                                    r.hosts_alive
                                );
                                let is_selected = b_sel == id;
                                rsx! {
                                    button {
                                        key: "b-{id}",
                                        class: "w-full text-left px-3 py-2 rounded text-sm font-mono transition-colors",
                                        style: if is_selected {
                                            "background: var(--color-primary); color: #fff; border: 2px solid var(--color-primary);"
                                        } else {
                                            "background: var(--color-surface); color: var(--color-text-primary); border: 1px solid var(--color-border);"
                                        },
                                        onclick: move |_| {
                                            scan_b_id.set(id.clone());
                                            diff_result.set(None);
                                        },
                                        "{label}"
                                    }
                                }
                            })}
                        }
                    }
                }

                // --- Кнопка Compare ---
                div { class: "mb-8",
                    button {
                        class: "px-6 py-2 rounded font-medium cursor-pointer transition-colors duration-200",
                        style: if can_compare {
                            "background: var(--color-primary); color: #fff; border: none;"
                        } else {
                            "background: var(--color-surface); color: var(--color-text-muted); border: 1px solid var(--color-border); cursor: not-allowed;"
                        },
                        disabled: !can_compare,
                        onclick: move |_| {
                            let a_id = scan_a_id();
                            let b_id = scan_b_id();
                            let rec_a = recs_for_btn.iter().find(|r| r.id == *a_id);
                            let rec_b = recs_for_btn.iter().find(|r| r.id == *b_id);
                            if let (Some(a), Some(b)) = (rec_a, rec_b) {
                                diff_result.set(Some(diff_scans(a, b)));
                            }
                        },
                        if can_compare { "Сравнить" } else { "Выберите два разных скана" }
                    }
                }

                // --- Результаты ---
                if let Some(ref diff) = diff_result() {
                    DiffResults { diff: diff.clone() }
                }
            }
        }
    }
}

/// Компонент отображения результатов сравнения.
#[component]
fn DiffResults(diff: ScanDiff) -> Element {
    let has_port_changes = !diff.port_changes.is_empty();
    let has_cve_changes = !diff.cve_changes.is_empty();
    let has_host_changes = !diff.hosts_added.is_empty() || !diff.hosts_removed.is_empty();
    let has_any = has_host_changes || has_port_changes || has_cve_changes;

    rsx! {
        div {
            // --- Summary Cards ---
            div { class: "grid grid-cols-2 md:grid-cols-4 gap-4 mb-8",
                SummaryCard {
                    label: "Хосты добавлено",
                    value: diff.hosts_added.len().to_string(),
                    color: "var(--color-severity-high)",
                }
                SummaryCard {
                    label: "Хосты удалено",
                    value: diff.hosts_removed.len().to_string(),
                    color: "var(--color-severity-critical)",
                }
                SummaryCard {
                    label: "Хосты без изменений",
                    value: diff.hosts_unchanged.to_string(),
                    color: "var(--color-success)",
                }
                SummaryCard {
                    label: "Изменение живых",
                    value: format!("{:+}", diff.alive_change),
                    color: if diff.alive_change >= 0 { "var(--color-success)" } else { "var(--color-severity-critical)" },
                }
            }

            div { class: "grid grid-cols-2 gap-4 mb-8",
                SummaryCard {
                    label: "Изменение портов",
                    value: format!("{:+}", diff.ports_total_change),
                    color: "var(--color-text-primary)",
                }
                SummaryCard {
                    label: "CVE добавлено",
                    value: diff.cve_changes.iter().filter(|c| matches!(c.change_type, peregrine_core::history::ChangeType::Added)).count().to_string(),
                    color: "var(--color-severity-critical)",
                }
                SummaryCard {
                    label: "CVE исправлено",
                    value: diff.cve_changes.iter().filter(|c| matches!(c.change_type, peregrine_core::history::ChangeType::Removed)).count().to_string(),
                    color: "var(--color-success)",
                }
                SummaryCard {
                    label: "Изменений портов",
                    value: diff.port_changes.len().to_string(),
                    color: "var(--color-severity-medium)",
                }
            }

            if !has_any {
                div {
                    class: "p-6 rounded text-center",
                    style: "background: var(--color-surface); color: var(--color-text-primary); border: 1px solid var(--color-border);",
                    "✅ Сканы идентичны — изменений не обнаружено"
                }
            } else {
                // --- Hosts Added ---
                if !diff.hosts_added.is_empty() {
                    Section { title: "🟢 Появились хосты", color: "var(--color-severity-high)",
                        for ip in &diff.hosts_added {
                            HostBadge { ip: ip.clone(), variant: "added" }
                        }
                    }
                }

                // --- Hosts Removed ---
                if !diff.hosts_removed.is_empty() {
                    Section { title: "🔴 Исчезли хосты", color: "var(--color-severity-critical)",
                        for ip in &diff.hosts_removed {
                            HostBadge { ip: ip.clone(), variant: "removed" }
                        }
                    }
                }

                // --- Port Changes ---
                if has_port_changes {
                    Section { title: "📡 Изменения портов", color: "var(--color-severity-medium)",
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm text-left",
                                thead {
                                    tr {
                                        style: "color: var(--color-text-muted); border-bottom: 1px solid var(--color-border)",
                                        th { class: "py-2 px-3", "Хост" }
                                        th { class: "py-2 px-3", "Порт" }
                                        th { class: "py-2 px-3", "Тип изменения" }
                                        th { class: "py-2 px-3", "Детали" }
                                    }
                                }
                                tbody {
                                    {diff.port_changes.iter().map(|pc| {
                                        let (change_label, change_color, details) = match &pc.change_type {
                                            peregrine_core::history::ChangeType::Added =>
                                                ("Добавлен", "var(--color-severity-high)", String::new()),
                                            peregrine_core::history::ChangeType::Removed =>
                                                ("Удалён", "var(--color-severity-critical)", String::new()),
                                            peregrine_core::history::ChangeType::ServiceChanged(old, new) =>
                                                ("Сервис изменён", "var(--color-severity-medium)",
                                                 format!("{old} → {new}")),
                                            peregrine_core::history::ChangeType::VersionChanged(old, new) =>
                                                ("Версия изменена", "var(--color-primary)",
                                                 format!("{:?} → {:?}", old, new)),
                                        };

                                        rsx! {
                                            tr {
                                                key: "{pc.host_ip}:{pc.port}",
                                                class: "border-b",
                                                style: "border-color: var(--color-border)",
                                                td { class: "py-2 px-3 font-mono text-xs",
                                                    style: "color: var(--color-text-primary)",
                                                    "{pc.host_ip}"
                                                }
                                                td { class: "py-2 px-3 font-mono",
                                                    style: "color: var(--color-text-secondary)",
                                                    "{pc.port}"
                                                }
                                                td { class: "py-2 px-3",
                                                    span {
                                                        class: "text-xs font-medium px-2 py-0.5 rounded",
                                                        style: "background: {change_color}; color: #fff;",
                                                        "{change_label}"
                                                    }
                                                }
                                                td { class: "py-2 px-3",
                                                    style: "color: var(--color-text-secondary)",
                                                    "{details}"
                                                }
                                            }
                                        }
                                    })}
                                }
                            }
                        }
                    }
                }

                // --- CVE Changes ---
                if has_cve_changes {
                    Section { title: "⚠️ Изменения CVE", color: "var(--color-severity-critical)",
                        div { class: "overflow-x-auto",
                            table { class: "w-full text-sm text-left",
                                thead {
                                    tr {
                                        style: "color: var(--color-text-muted); border-bottom: 1px solid var(--color-border)",
                                        th { class: "py-2 px-3", "Хост" }
                                        th { class: "py-2 px-3", "CVE" }
                                        th { class: "py-2 px-3", "Статус" }
                                    }
                                }
                                tbody {
                                    {diff.cve_changes.iter().map(|cc| {
                                        let (label, color) = match cc.change_type {
                                            peregrine_core::history::ChangeType::Added =>
                                                ("🆕 Появилась", "var(--color-severity-critical)"),
                                            peregrine_core::history::ChangeType::Removed =>
                                                ("✅ Исправлена", "var(--color-success)"),
                                            _ => ("Изменена", "var(--color-severity-medium)"),
                                        };

                                        rsx! {
                                            tr {
                                                key: "{cc.host_ip}:{cc.cve_id}",
                                                class: "border-b",
                                                style: "border-color: var(--color-border)",
                                                td { class: "py-2 px-3 font-mono text-xs",
                                                    style: "color: var(--color-text-primary)",
                                                    "{cc.host_ip}"
                                                }
                                                td { class: "py-2 px-3 font-mono text-xs",
                                                    style: "color: var(--color-severity-critical)",
                                                    "{cc.cve_id}"
                                                }
                                                td { class: "py-2 px-3",
                                                    span {
                                                        class: "text-xs font-medium px-2 py-0.5 rounded",
                                                        style: "background: {color}; color: #fff;",
                                                        "{label}"
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

                // --- Footer: какие сканы сравнивались ---
                div {
                    class: "mt-8 text-xs",
                    style: "color: var(--color-text-muted)",
                    "Сравнение: {diff.scan_a_id} ↔ {diff.scan_b_id}"
                }
            }
        }
    }
}

/// Карточка-сводка одного показателя.
#[component]
fn SummaryCard(label: String, value: String, color: String) -> Element {
    rsx! {
        div {
            class: "p-4 rounded",
            style: "background: var(--color-surface); border: 1px solid var(--color-border);",
            div { class: "text-2xl font-bold", style: "color: {color}", "{value}" }
            div { class: "text-xs mt-1", style: "color: var(--color-text-muted)", "{label}" }
        }
    }
}

/// Бейдж хоста (добавлен/удалён).
#[component]
fn HostBadge(ip: String, variant: String) -> Element {
    let (bg, dot) = match variant.as_str() {
        "added" => ("background: rgba(63,185,80,0.15); border: 1px solid rgba(63,185,80,0.3);",
                    "🟢"),
        "removed" => ("background: rgba(248,81,73,0.15); border: 1px solid rgba(248,81,73,0.3);",
                      "🔴"),
        _ => ("background: var(--color-surface); border: 1px solid var(--color-border);", "⚪"),
    };

    rsx! {
        div {
            class: "inline-block px-3 py-1.5 rounded font-mono text-sm mr-2 mb-2",
            style: "{bg} color: var(--color-text-primary);",
            "{dot} {ip}"
        }
    }
}

/// Секция с заголовком и содержимым.
#[component]
fn Section(title: String, color: String, children: Element) -> Element {
    rsx! {
        div { class: "mb-6",
            h2 {
                class: "text-lg font-semibold mb-3",
                style: "color: {color}",
                "{title}"
            }
            {children}
        }
    }
}
