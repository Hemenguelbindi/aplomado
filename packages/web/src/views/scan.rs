use dioxus::prelude::*;
use ui::{
    models::{HostInfo, Session, SessionStatus, TargetStatus},
    helpers::{create_default_session, build_scan_record, targets_to_strings},
    ScanView, ScanConfigUi, ScanStatusUi,
};
use kestrel_core::history::ScanRecord;

#[component]
pub fn Scan() -> Element {
    let mut current_session = use_context::<Signal<Option<Session>>>();
    let mut scan_status = use_context::<Signal<ScanStatusUi>>();
    let mut scan_results = use_context::<Signal<Vec<HostInfo>>>();
    let history = use_context::<Signal<Vec<ScanRecord>>>();
    let mut scan_task: Signal<Option<dioxus::core::Task>> = use_signal(|| None);

    if current_session().is_none() || current_session().unwrap().id.is_empty() {
        current_session.set(Some(create_default_session()));
    }

    let session_for_view = current_session().unwrap_or_else(create_default_session);

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
                let mut st = scan_status;
                let mut sr = scan_results;
                let mut hist = history;
                let mut sess = current_session;
                let targets = cfg.targets.clone();
                let ports = cfg.ports.clone();

                let total_hosts: u32 = targets.iter().map(|t| {
                    match t {
                        ui::models::ScanTarget::Cidr(c) => kestrel_core::scanner::expand_cidr(c).len() as u32,
                        ui::models::ScanTarget::Ip(_) | ui::models::ScanTarget::Hostname(_) => 1,
                        ui::models::ScanTarget::Range(s, e) => {
                            kestrel_core::scanner::expand_range(&s.to_string(), &e.to_string()).len() as u32
                        }
                    }
                }).sum();

                st.set(ScanStatusUi::Scanning { current: 0, total: total_hosts });
                let start_millis = chrono::Utc::now().timestamp_millis();

                let mut s = sess();
                if let Some(ref mut s) = s {
                    for t in &mut s.targets { t.status = TargetStatus::Scanning; }
                }
                sess.set(s);

                let targets_str = targets_to_strings(&targets);
                let targets_cloned = targets_str.clone();

                let handle = spawn(async move {
                    let request = api::ScanRequest { targets: targets_cloned, ports };

                    match api::run_scan(request).await {
                        Ok(results) => {
                            let count = results.len();
                            let hosts: Vec<HostInfo> = results.into_iter().map(|r| {
                                HostInfo {
                                    ip: r.ip.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                                    hostname: r.hostname,
                                    ttl: None,
                                    os_guess: r.os_guess,
                                    alive: r.alive,
                                    ports: r.ports.into_iter().map(|p| ui::models::PortInfo {
                                        port: p.port, service_name: p.service, service_version: p.version,
                                        banner: p.banner, cpe: None, cves: vec![],
                                    }).collect(),
                                    route: r.route.into_iter().map(|h| ui::models::Hop {
                                        hop: h.hop,
                                        ip: h.ip.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                                        rtt_ms: h.rtt_ms,
                                    }).collect(),
                                }
                            }).collect();

                            sr.set(hosts.clone());
                            let duration = ((chrono::Utc::now().timestamp_millis() - start_millis) / 1000) as u64;
                            let hosts_alive = hosts.iter().filter(|h| h.alive).count() as u32;
                            let record = build_scan_record(&hosts, &targets_str, duration);
                            kestrel_core::history::save_scan(&record).ok();
                            let mut h = hist();
                            h.insert(0, record);
                            hist.set(h);

                            let mut s = sess();
                            if let Some(ref mut s) = s {
                                for t in &mut s.targets { t.status = TargetStatus::Done(hosts_alive); }
                                s.hosts = hosts.clone();
                                s.status = SessionStatus::Done;
                            }
                            sess.set(s);

                            if matches!(*st.read(), ScanStatusUi::Scanning { .. }) {
                                st.set(ScanStatusUi::Done(count as u32));
                            }
                        }
                        Err(e) => {
                            let mut s = sess();
                            if let Some(ref mut s) = s {
                                for t in &mut s.targets { t.status = TargetStatus::Error(e.to_string()); }
                            }
                            sess.set(s);
                            if matches!(*st.read(), ScanStatusUi::Scanning { .. }) {
                                st.set(ScanStatusUi::Error(e.to_string()));
                            }
                        }
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
