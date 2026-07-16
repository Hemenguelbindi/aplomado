use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::watch;

/// Прогресс сканирования — отправляется из движка в UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub total_hosts: u32,
    pub scanned_hosts: u32,
    pub current_host: String,
    pub found_ports: u32,
    pub elapsed_secs: u64,
    pub phase: ScanPhase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanPhase {
    Ping,
    PortScan,
    BannerGrab,
    Done,
}

/// Канал прогресса: sender в background task, receiver в UI.
pub type ProgressSender = Arc<watch::Sender<Option<ScanProgress>>>;
pub type ProgressReceiver = watch::Receiver<Option<ScanProgress>>;

pub fn progress_channel() -> (ProgressSender, ProgressReceiver) {
    let (tx, rx) = watch::channel(None);
    (Arc::new(tx), rx)
}
