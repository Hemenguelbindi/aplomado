use crate::models::{ScanPreset, ScanTarget, ScanTargetItem, Session};
use dioxus::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct ScanConfigUi {
    pub targets: Vec<ScanTarget>,
    pub ports: Vec<u16>,
    pub fast_mode: bool,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub enum ScanStatusUi {
    #[default]
    Idle,
    Scanning {
        current: u32,
        total: u32,
    },
    Done(u32),
    Error(String),
}

#[derive(Props, Clone, PartialEq)]
pub struct ScanFormProps {
    pub session: Session,
    pub status: ScanStatusUi,
    pub on_update_session: EventHandler<Session>,
    pub on_start_scan: EventHandler<ScanConfigUi>,
    pub on_stop_scan: EventHandler<()>,
}

pub fn get_ports_for_target(item: &ScanTargetItem) -> Vec<u16> {
    if matches!(item.preset, ScanPreset::Custom) && !item.custom_ports.is_empty() {
        item.custom_ports.clone()
    } else {
        item.preset.ports()
    }
}

pub fn build_scan_config(targets: &[ScanTargetItem]) -> Option<ScanConfigUi> {
    let first = targets.first()?;
    let ports = get_ports_for_target(first);
    if ports.is_empty() {
        return None;
    }
    let parsed: Vec<ScanTarget> = targets
        .iter()
        .filter_map(|t| super::parse_target(&t.target))
        .collect();
    if parsed.is_empty() {
        return None;
    }
    Some(ScanConfigUi {
        targets: parsed,
        ports,
        fast_mode: true,
    })
}

/// True if every target is configured with the same effective port set.
/// Used to warn the user when targets have divergent port configs before
/// running "Запустить все цели" (which applies one port list to all targets).
pub fn targets_have_same_ports(targets: &[ScanTargetItem]) -> bool {
    let Some(first) = targets.first() else { return true };
    let base = get_ports_for_target(first);
    targets
        .iter()
        .all(|t| get_ports_for_target(t) == base)
}
