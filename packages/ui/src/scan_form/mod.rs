pub mod controls;
pub mod parse;
pub mod port_input;
pub mod preset_selector;
mod scan_form;
pub mod session_name;
pub mod status_display;
pub mod target_list;
pub mod types;

use crate::models::{ScanPreset, ScanTargetItem, TargetStatus};
use dioxus::prelude::*;

pub use controls::ScanControls;
pub use parse::{parse_custom_ports, parse_target};
pub use port_input::PortInput;
pub use preset_selector::PresetSelector;
pub use scan_form::ScanForm;
pub use session_name::SessionNameEditor;
pub use status_display::StatusDisplay;
pub use target_list::TargetList;
pub use types::{
    build_scan_config, get_ports_for_target, ScanConfigUi, ScanFormProps, ScanStatusUi,
};

fn add_target_to_session(
    props: &ScanFormProps,
    target_input: &mut Signal<String>,
    preset: &Signal<ScanPreset>,
    custom_ports: &Signal<Vec<u16>>,
) {
    let val = target_input();
    if val.is_empty() {
        return;
    }
    let id = format!("tgt_{}", chrono::Local::now().timestamp_millis());
    let mut s = props.session.clone();
    let ports = if matches!(*preset.read(), ScanPreset::Custom) {
        custom_ports()
    } else {
        vec![]
    };

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
