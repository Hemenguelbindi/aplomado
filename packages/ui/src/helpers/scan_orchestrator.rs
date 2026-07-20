//! Общие функции-оркестраторы для обработки результатов сканирования.
//!
//! Вынесены из платформенных view-файлов (web, desktop) для устранения дублирования.

use dioxus::prelude::{ReadableExt, Signal, WritableExt};
use aplomado_core::history::ScanRecord;

use crate::helpers::session::build_scan_record;
use crate::models::{HostInfo, Session, SessionStatus, TargetStatus};
use crate::scan_form::types::ScanStatusUi;

/// Обрабатывает успешное завершение сканирования:
/// обновляет результаты, сохраняет запись в историю, обновляет сессию.
pub async fn handle_scan_success(
    mut scan_results: Signal<Vec<HostInfo>>,
    mut scan_status: Signal<ScanStatusUi>,
    mut history: Signal<Vec<ScanRecord>>,
    mut session: Signal<Option<Session>>,
    hosts: Vec<HostInfo>,
    targets_str: Vec<String>,
    duration_secs: u64,
) {
    let count = hosts.len() as u32;
    scan_results.set(hosts.clone());

    let hosts_alive = hosts.iter().filter(|h| h.alive).count() as u32;
    let record = build_scan_record(&hosts, &targets_str, duration_secs);
    aplomado_core::history::save_scan(&record).ok();

    let mut h = history();
    h.insert(0, record);
    history.set(h);

    let mut s = session();
    if let Some(ref mut s) = s {
        for t in &mut s.targets {
            t.status = TargetStatus::Done(hosts_alive);
        }
        s.hosts = hosts;
        s.status = SessionStatus::Done;
    }
    session.set(s);

    if matches!(*scan_status.read(), ScanStatusUi::Scanning { .. }) {
        scan_status.set(ScanStatusUi::Done(count));
    }
}

/// Обрабатывает ошибку сканирования:
/// обновляет статус целей на Error и статус UI на Error.
pub async fn handle_scan_failure(
    mut scan_status: Signal<ScanStatusUi>,
    mut session: Signal<Option<Session>>,
    error: String,
) {
    let mut s = session();
    if let Some(ref mut s) = s {
        for t in &mut s.targets {
            t.status = TargetStatus::Error(error.clone());
        }
    }
    session.set(s);

    if matches!(*scan_status.read(), ScanStatusUi::Scanning { .. }) {
        scan_status.set(ScanStatusUi::Error(error));
    }
}

/// Отмечает все цели сессии статусом Scanning.
pub fn mark_targets_scanning(mut session: Signal<Option<Session>>) {
    let mut s = session();
    if let Some(ref mut s) = s {
        for t in &mut s.targets {
            t.status = TargetStatus::Scanning;
        }
    }
    session.set(s);
}
