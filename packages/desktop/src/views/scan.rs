use dioxus::prelude::*;
use ui::{
    models::{HostInfo, Session},
    helpers::{create_default_session, build_scan_record, targets_to_strings},
    ScanView, ScanConfigUi, ScanStatusUi,
};
use kestrel_core::history::ScanRecord;

#[component]
pub fn Scan() -> Element {
    let mut current_session = use_context::<Signal<Option<Session>>>();
    let mut status = use_context::<Signal<ScanStatusUi>>();
    let scan_results = use_context::<Signal<Vec<HostInfo>>>();
    let history = use_context::<Signal<Vec<ScanRecord>>>();
    let mut scan_task: Signal<Option<dioxus::core::Task>> = use_signal(|| None);

    if current_session().is_none() || current_session().unwrap().id.is_empty() {
        current_session.set(Some(create_default_session()));
    }

    let session_for_view = current_session().unwrap_or_else(create_default_session);

    rsx! {
        ScanView {
            session: session_for_view,
            status: status(),
            results: scan_results(),
            on_update_session: move |s: Session| current_session.set(Some(s)),
            on_start_scan: move |cfg: ScanConfigUi| {
                let total = cfg.targets.len() as u32;
                let mut st = status;
                let mut sr = scan_results;
                let mut hist = history;
                let targets_str = targets_to_strings(&cfg.targets);

                let handle = spawn(async move {
                    sr.set(Vec::new());
                    st.set(ScanStatusUi::Scanning { current: 0, total });
                    let mut found = Vec::new();
                    let start_time = std::time::Instant::now();

                    for (i, target) in cfg.targets.iter().enumerate() {
                        let ips = ui::scan_engine::resolve_targets(target);
                        for ip in ips {
                            st.set(ScanStatusUi::Scanning { current: (i + 1) as u32, total });
                            let host = ui::scan_engine::scan_single_target(ip, &cfg.ports, None).await;
                            found.push(host);
                            sr.set(found.clone());
                            tokio::task::yield_now().await;
                        }
                        tokio::task::yield_now().await;
                    }

                    sr.set(found.clone());
                    let duration = start_time.elapsed().as_secs();
                    let record = build_scan_record(&found, &targets_str, duration);
                    kestrel_core::history::save_scan(&record).ok();
                    let mut h = hist();
                    h.insert(0, record);
                    hist.set(h);

                    if matches!(*st.read(), ScanStatusUi::Scanning { .. }) {
                        st.set(ScanStatusUi::Done(found.len() as u32));
                    }
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
