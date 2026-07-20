use dioxus::prelude::*;
use ui::{
    helpers::{create_default_session, handle_scan_failure, handle_scan_success, mark_targets_scanning, targets_to_strings},
    models::{HostInfo, Session},
    ScanConfigUi, ScanStatusUi, ScanView,
};
use peregrine_core::history::ScanRecord;

fn count_target_hosts(targets: &[ui::models::ScanTarget]) -> u32 {
    targets.iter().map(|t| match t {
        ui::models::ScanTarget::Cidr(c) => peregrine_core::scanner::expand_cidr(c).len() as u32,
        ui::models::ScanTarget::Ip(_) | ui::models::ScanTarget::Hostname(_) => 1,
        ui::models::ScanTarget::Range(s, e) => {
            peregrine_core::scanner::expand_range(&s.to_string(), &e.to_string()).len() as u32
        }
    }).sum()
}

#[component]
pub fn Scan() -> Element {
let mut current_session = use_context::<Signal<Option<Session>>>();
    let mut status = use_context::<Signal<ScanStatusUi>>();
    let mut scan_results = use_context::<Signal<Vec<HostInfo>>>();
    let history = use_context::<Signal<Vec<ScanRecord>>>();
    let mut scan_task: Signal<Option<dioxus::core::Task>> = use_signal(|| None);

    let session = current_session().and_then(|s| if s.id.is_empty() { None } else { Some(s) }).unwrap_or_else(|| {
        let s = create_default_session();
        current_session.set(Some(s.clone()));
        s
    });

    let session_for_view = session.clone();

    rsx! {
        ScanView {
            session: session_for_view,
            status: scan_status(),
            results: scan_results(),
            show_new_session: true,
            on_update_session: move |s: Session| {
                current_session.set(Some(s.clone()));
                let json = serde_json::to_string(&s).unwrap_or_default();
                spawn(async move { api::save_session(json).await.ok(); });
            },
            on_start_scan: move |cfg: ScanConfigUi| {
                let total_hosts = count_target_hosts(&cfg.targets);
                scan_status.set(ScanStatusUi::Scanning { current: 0, total: total_hosts });
                mark_targets_scanning(current_session);
                let start_millis = chrono::Utc::now().timestamp_millis();
                let targets_str = targets_to_strings(&cfg.targets);
                let ports = cfg.ports.clone();

                let handle = spawn(async move {
                    match api::run_scan(api::ScanRequest { targets: targets_str.clone(), ports }).await {
                        Ok(hosts) => {
                            let duration = ((chrono::Utc::now().timestamp_millis() - start_millis) / 1000) as u64;
                            handle_scan_success(scan_results, scan_status, history, current_session, hosts, targets_str, duration).await;
                        }
                        Err(e) => handle_scan_failure(scan_status, current_session, e.to_string()).await,
                    }
                });
                scan_task.set(Some(handle));
            },
            on_stop_scan: move |_| {
                if let Some(task) = scan_task() { task.cancel(); }
                scan_status.set(ScanStatusUi::Idle);
                scan_task.set(None);
            },
            on_new_session: move |_| {
                current_session.set(Some(create_default_session()));
                scan_results.set(Vec::new());
                scan_status.set(ScanStatusUi::Idle);
            },
        }
    }
}
