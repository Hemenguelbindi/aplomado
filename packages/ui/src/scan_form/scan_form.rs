use super::{
    get_ports_for_target, parse_custom_ports, parse_target, ScanConfigUi, ScanFormProps,
    ScanStatusUi,
};
use super::{
    PortInput, PresetSelector, ScanControls, SessionNameEditor, StatusDisplay, TargetList,
};
use crate::components::TextInput;
use crate::models::{ScanPreset, TargetStatus};
use dioxus::prelude::*;

fn ports_info(preset: &ScanPreset) -> Option<Element> {
    if matches!(preset, ScanPreset::Custom) {
        return None;
    }
    let ports = preset.ports();
    if ports.is_empty() {
        return None;
    }
    let count = ports.len();
    let list = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Some(rsx! {
        div { class: "text-xs font-mono mt-1 text-muted-foreground",
            "Порты ({count}): {list}"
        }
    })
}

#[component]
pub fn ScanForm(props: ScanFormProps) -> Element {
    let mut target_input = use_signal(String::new);
    let mut preset = use_signal(|| ScanPreset::Standard);
    let mut custom_ports: Signal<Vec<u16>> = use_signal(Vec::new);
    let mut custom_ports_str: Signal<String> = use_signal(String::new);
    let is_scanning = matches!(props.status, ScanStatusUi::Scanning { .. });
    let current_preset = preset();
    let session = props.session.clone();
    let targets = session.targets.clone();
    let targets_empty = targets.is_empty();
    let ports_info = ports_info(&current_preset);
    let input_text = target_input();
    let show_hint =
        !input_text.is_empty() && input_text.len() < 3 && parse_target(&input_text).is_none();

    rsx! {
        div { key: "{session.id}-form", class: "space-y-4",
            SessionNameEditor { session: session.clone(), on_update: { let p = props.clone(); move |s| p.on_update_session.call(s) } }
            div { class: "relative",
                TextInput {
                    value: target_input(),
                    placeholder: "IP, CIDR (10.2.64.0/24) или хост",
                    disabled: is_scanning,
                    oninput: move |e| target_input.set(e),
                    onkeydown: { let p = props.clone(); move |e: Event<KeyboardData>| {
                        if e.key() == Key::Enter && !target_input().is_empty() {
                            e.prevent_default();
                            super::add_target_to_session(&p, &mut target_input, &preset, &custom_ports);
                        }
                    }},
                }
                if show_hint {
                    p { class: "text-[10px] mt-0.5 text-muted-foreground", "Введите IP-адрес (например, 192.168.1.1), CIDR (10.0.0.0/24) или доменное имя" }
                }
            }
            PresetSelector { active: current_preset.clone(), disabled: is_scanning, on_select: { let p = props.clone(); move |new_preset: ScanPreset| {
                preset.set(new_preset.clone());
                // Propagate the new preset to all queued (not-yet-started) targets,
                // so "Запустить все цели" scans with the currently-selected ports.
                let mut s = p.session.clone();
                let mut changed = false;
                for t in s.targets.iter_mut() {
                    if matches!(t.status, TargetStatus::Queued) {
                        t.preset = new_preset.clone();
                        t.custom_ports = if matches!(new_preset, ScanPreset::Custom) {
                            custom_ports()
                        } else {
                            vec![]
                        };
                        changed = true;
                    }
                }
                if changed { p.on_update_session.call(s); }
            }} }
            if matches!(current_preset, ScanPreset::Custom) {
                PortInput { value: custom_ports_str(), disabled: is_scanning,
                    on_input: { let p = props.clone(); move |raw: String| {
                        let parsed = parse_custom_ports(&raw);
                        custom_ports.set(parsed.clone());
                        custom_ports_str.set(raw);
                        // Propagate custom ports to all queued Custom targets.
                        let mut s = p.session.clone();
                        let mut changed = false;
                        for t in s.targets.iter_mut() {
                            if matches!(t.status, TargetStatus::Queued)
                                && matches!(t.preset, ScanPreset::Custom)
                            {
                                t.custom_ports = parsed.clone();
                                changed = true;
                            }
                        }
                        if changed { p.on_update_session.call(s); }
                    } },
                }
            }
            {ports_info}
            TargetList {
                targets: targets.clone(), is_scanning,
                on_run: { let p = props.clone(); move |idx: String| {
                    if let Some(item) = p.session.targets.iter().find(|t| t.id == idx) {
                        let ports = get_ports_for_target(item);
                        if !ports.is_empty() {
                            if let Some(t) = parse_target(&item.target) {
                                p.on_start_scan.call(ScanConfigUi { targets: vec![t], ports, fast_mode: true });
                            }
                        }
                    }
                }},
                on_remove: { let p = props.clone(); move |idx: String| {
                    let mut s = p.session.clone();
                    s.targets.retain(|t| t.id != idx);
                    p.on_update_session.call(s);
                }},
            }
            ScanControls { is_scanning, targets_empty, targets: targets.clone(),
                on_start_scan: { let p = props.clone(); move |cfg: ScanConfigUi| p.on_start_scan.call(cfg) },
                on_stop_scan: { let p = props.clone(); move |_| p.on_stop_scan.call(()) },
            }
            StatusDisplay { status: props.status.clone(), targets_empty }
        }
    }
}
