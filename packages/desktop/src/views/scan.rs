use dioxus::prelude::*;
use ui::{
    helpers::{create_default_session, handle_scan_success, targets_to_strings},
    models::{HostInfo, Session},
    ScanConfigUi, ScanStatusUi, ScanView,
};
use peregrine_core::history::ScanRecord;

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
            status: status(),
            results: scan_results(),
            on_update_session: move |s: Session| current_session.set(Some(s)),
            on_start_scan: move |cfg: ScanConfigUi| {
                let total = cfg.targets.len() as u32;
                let targets_str = targets_to_strings(&cfg.targets);
                let ports = cfg.ports.clone();
                let targets = cfg.targets.clone();

                let handle = spawn(async move {
                    scan_results.set(Vec::new());
                    status.set(ScanStatusUi::Scanning { current: 0, total });
                    let mut found = Vec::new();
                    let start_time = std::time::Instant::now();

                    for (i, target) in targets.iter().enumerate() {
                        let ips = peregrine_core::scanner::resolve_targets(target);
                        for ip in ips {
                            let current = (i + 1) as u32;
                            status.set(ScanStatusUi::Scanning { current, total });
                            let host = peregrine_core::scanner::engine::scan_single_target(ip, &ports, None).await;
                            found.push(host);
                            scan_results.set(found.clone());
                            tokio::task::yield_now().await;
                        }
                        tokio::task::yield_now().await;
                    }

                    scan_results.set(found.clone());
                    let duration = start_time.elapsed().as_secs();
                    handle_scan_success(
                        scan_results, status, history,
                        current_session, found, targets_str, duration,
                    ).await;
                });
                scan_task.set(Some(handle));
            },
            on_stop_scan: move |_| {
                if let Some(task) = scan_task() { task.cancel(); }
                status.set(ScanStatusUi::Idle);
                scan_task.set(None);
            },
        }
    }
}
