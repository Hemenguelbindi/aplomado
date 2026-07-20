use super::table_row::TableRow;
use super::types::count_cves;
use crate::helpers::pluralize;
use crate::models::HostInfo;
use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq)]
enum SortColumn {
    Ip,
    Hostname,
    Os,
    Ports,
    Cve,
}

#[derive(Clone, Copy, PartialEq)]
enum SortDir {
    Asc,
    Desc,
}

fn toggle_sort(col: SortColumn, mut sc: Signal<SortColumn>, mut sd: Signal<SortDir>) {
    if sc() == col {
        sd.set(match sd() {
            SortDir::Asc => SortDir::Desc,
            _ => SortDir::Asc,
        });
    } else {
        sc.set(col);
        sd.set(SortDir::Asc);
    }
}

fn arrow(col: SortColumn, cur: SortColumn, dir: SortDir) -> &'static str {
    if cur != col {
        return "";
    }
    match dir {
        SortDir::Asc => " ^",
        SortDir::Desc => " v",
    }
}

fn sort_val(h: &HostInfo, col: SortColumn) -> String {
    match col {
        SortColumn::Ip => h.ip.to_string(),
        SortColumn::Hostname => h.hostname.clone().unwrap_or_else(|| "zzz".into()),
        SortColumn::Os => h.os_guess.clone().unwrap_or_else(|| "zzz".into()),
        SortColumn::Ports => h.ports.len().to_string(),
        SortColumn::Cve => {
            let s = count_cves(h);
            format!("{:04}{:03}{:02}{:01}", s.critical, s.high, s.medium, s.low)
        }
    }
}

fn matches_q(h: &HostInfo, q: &str) -> bool {
    h.ip.to_string().to_lowercase().contains(q)
        || h.hostname
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains(q)
        || h.os_guess
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains(q)
}

#[derive(Props, Clone, PartialEq)]
pub struct TableViewProps {
    pub hosts: Vec<HostInfo>,
    pub on_select_host: EventHandler<String>,
    #[props(optional)]
    pub selected_host: Option<String>,
}

#[component]
pub fn TableView(props: TableViewProps) -> Element {
    let mut search = use_signal(String::new);
    let sort_col = use_signal(|| SortColumn::Ip);
    let sort_dir = use_signal(|| SortDir::Asc);
    let q = search().to_lowercase();
    let filtered: Vec<HostInfo> = if q.is_empty() {
        props.hosts.clone()
    } else {
        props
            .hosts
            .iter()
            .filter(|h| matches_q(h, &q))
            .cloned()
            .collect()
    };

    let sc = sort_col();
    let sd = sort_dir();
    let mut sorted = filtered;
    sorted.sort_by(|a, b| {
        let cmp = sort_val(a, sc).cmp(&sort_val(b, sc));
        match sd {
            SortDir::Asc => cmp,
            SortDir::Desc => cmp.reverse(),
        }
    });

    let count_label = pluralize(sorted.len(), "хост", "хоста", "хостов");

    rsx! {
        div { class: "space-y-2",
            div { class: "flex items-center gap-2",
                input {
                    class: "flex-1 rounded p-2 text-sm outline-none",
                    style: "background: var(--color-input-bg); border: 1px solid var(--color-input-border); color: var(--color-text-primary)",
                    placeholder: "Поиск по IP, hostname, ОС...",
                    value: "{search}",
                    oninput: move |e| search.set(e.value()),
                }
                span {
                    class: "text-xs",
                    style: "color: var(--color-text-muted)",
                    "{count_label}"
                }
            }
            div { class: "overflow-x-auto",
                table { class: "w-full text-sm text-left",
                    thead {
                        tr {
                            style: "color: var(--color-text-muted); border-bottom: 1px solid var(--color-border)",
                            th {
                                class: "py-2 px-3 cursor-pointer select-none",
                                style: "color: var(--color-text-muted)",
                                onclick: move |_| toggle_sort(SortColumn::Ip, sort_col, sort_dir),
                                "IP{arrow(SortColumn::Ip, sc, sd)}"
                            }
                            th {
                                class: "py-2 px-3 cursor-pointer select-none",
                                style: "color: var(--color-text-muted)",
                                onclick: move |_| toggle_sort(SortColumn::Hostname, sort_col, sort_dir),
                                "Hostname{arrow(SortColumn::Hostname, sc, sd)}"
                            }
                            th {
                                class: "py-2 px-3 cursor-pointer select-none",
                                style: "color: var(--color-text-muted)",
                                onclick: move |_| toggle_sort(SortColumn::Os, sort_col, sort_dir),
                                "OS{arrow(SortColumn::Os, sc, sd)}"
                            }
                            th {
                                class: "py-2 px-3 cursor-pointer select-none",
                                style: "color: var(--color-text-muted)",
                                onclick: move |_| toggle_sort(SortColumn::Ports, sort_col, sort_dir),
                                "Порты{arrow(SortColumn::Ports, sc, sd)}"
                            }
                            th {
                                class: "py-2 px-3 cursor-pointer select-none",
                                style: "color: var(--color-text-muted)",
                                onclick: move |_| toggle_sort(SortColumn::Cve, sort_col, sort_dir),
                                "CVE{arrow(SortColumn::Cve, sc, sd)}"
                            }
                            th {
                                class: "py-2 px-3",
                                style: "color: var(--color-text-muted)",
                                "Действия"
                            }
                        }
                    }
                    tbody {
                        {sorted.iter().map(|host| {
                            let is_sel = props.selected_host.as_deref() == Some(&host.ip.to_string());
                            rsx! { TableRow { key: "{host.ip}", host: host.clone(), selected: is_sel, on_select: props.on_select_host } }
                        })}
                    }
                }
            }
        }
    }
}
