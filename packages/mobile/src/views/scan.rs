use dioxus::core::Task;
use dioxus::prelude::*;
use ui::{
    models::HostInfo,
    models::{Session, SessionStatus},
    HostDetailPanel, MapViewMode, NetworkMap, ScanConfigUi, ScanForm, ScanStatusUi,
};

#[component]
pub fn Scan() -> Element {
    let mut current_session = use_context::<Signal<Option<Session>>>();
    let mut status = use_context::<Signal<ScanStatusUi>>();
    let mut scan_results = use_context::<Signal<Vec<HostInfo>>>();
    let _history = use_context::<Signal<Vec<aplomado_core::history::ScanRecord>>>();
    let mut view_mode = use_signal(|| MapViewMode::Table);
    let mut scan_task: Signal<Option<Task>> = use_signal(|| None);
    let mut selected_host: Signal<Option<String>> = use_signal(|| None);

    let session = current_session().unwrap_or(Session {
        id: format!("ses_{}", chrono::Local::now().timestamp_millis()),
        name: String::new(),
        targets: vec![],
        status: SessionStatus::Idle,
        created_at: chrono::Local::now().to_rfc3339(),
        updated_at: chrono::Local::now().to_rfc3339(),
        hosts: vec![],
        duration_secs: 0,
    });
    let targets_count = session.targets.len();

    rsx! {
        div { class: "p-8 max-w-6xl mx-auto",
            h1 { class: "text-2xl font-bold text-white mb-6", "Сканирование" }

            ScanForm {
                session: session.clone(),
                status: status(),
                on_update_session: move |s: Session| {
                    current_session.set(Some(s));
                },
                on_start_scan: move |cfg: ScanConfigUi| {
                    let total = cfg.targets.len() as u32;
                    status.set(ScanStatusUi::Scanning { current: 0, total });

                    let handle = spawn(async move {
                        scan_results.set(Vec::new());
                        status.set(ScanStatusUi::Scanning { current: 0, total });
                        let mut found = Vec::new();

                        let policy = aplomado_core::scanner::policy::ScanPolicy::default();
                        for (i, target) in cfg.targets.iter().enumerate() {
                            let ips = aplomado_core::scanner::resolve_targets(target)
                                .unwrap_or_default()
                                .into_iter()
                                .filter(|&ip| policy.is_allowed(ip))
                                .collect::<Vec<_>>();
                            for ip in ips {
                                status.set(ScanStatusUi::Scanning {
                                    current: (i + 1) as u32,
                                    total,
                                });
                                let host = aplomado_core::scanner::engine::scan_single_target(ip, &cfg.ports, None).await;
                                found.push(host);
                                scan_results.set(found.clone());
                                tokio::task::yield_now().await;
                            }
                            tokio::task::yield_now().await;
                        }

                        scan_results.set(found.clone());
                        if matches!(*status.read(), ScanStatusUi::Scanning { .. }) {
                            status.set(ScanStatusUi::Done(found.len() as u32));
                        }
                    });
                    scan_task.set(Some(handle));
                },
                on_stop_scan: move |_| {
                    if let Some(task) = scan_task() {
                        task.cancel();
                    }
                    status.set(ScanStatusUi::Idle);
                    scan_task.set(None);
                },
            }

            div { class: "mt-6",
                NetworkMap {
                    key: "scan-map-{targets_count}",
                    hosts: scan_results(),
                    view_mode: view_mode(),
                    selected_host: selected_host(),
                        on_select_host: move |ip: String| {
                            let current = selected_host();
                            if current.as_deref() == Some(&ip) {
                                selected_host.set(None);
                            } else {
                                selected_host.set(Some(ip));
                            }
                        },
                    on_change_view: move |mode| view_mode.set(mode),
                }
            }

            if let Some(ref sel_ip) = selected_host() {
                if let Some(host) = scan_results().iter().find(|h| h.ip.to_string() == *sel_ip) {
                    HostDetailPanel {
                        host: host.clone(),
                        on_close: move |_| selected_host.set(None),
                    }
                }
            }
        }
    }
}
