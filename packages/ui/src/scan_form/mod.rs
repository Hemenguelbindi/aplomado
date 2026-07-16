pub mod types;
pub mod parse;
pub mod preset_selector;
pub mod port_input;
pub mod target_list;
pub mod status_display;
pub mod session_name;
pub mod controls;
mod scan_form;

use crate::models::{ScanPreset, ScanTargetItem, TargetStatus};
use dioxus::prelude::*;

pub use types::{ScanConfigUi, ScanStatusUi, ScanFormProps, get_ports_for_target, build_scan_config};
pub use parse::{parse_target, parse_custom_ports};
pub use preset_selector::PresetSelector;
pub use port_input::PortInput;
pub use target_list::TargetList;
pub use status_display::StatusDisplay;
pub use session_name::SessionNameEditor;
pub use controls::ScanControls;
pub use scan_form::ScanForm;

fn add_target_to_session(
    props: &ScanFormProps,
    target_input: &mut Signal<String>,
    preset: &Signal<ScanPreset>,
    custom_ports: &Signal<Vec<u16>>,
) {
    let val = target_input();
    if val.is_empty() { return; }
    let id = format!("tgt_{}", chrono::Local::now().timestamp_millis());
    let mut s = props.session.clone();
    let ports = if matches!(*preset.read(), ScanPreset::Custom) {
        custom_ports()
    } else { vec![] };

    s.targets.push(ScanTargetItem {
        id,
        target: val,
        preset: preset(),
        custom_ports: ports,
        status: TargetStatus::Queued,
    });
    props.on_update_session.call(s);
    target_input.set(String::new());
}
