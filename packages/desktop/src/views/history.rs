use dioxus::prelude::*;
use ui::{HistoryPage};
use peregrine_core::history::ScanRecord;

#[component]
pub fn History() -> Element {
    let mut history = use_context::<Signal<Vec<ScanRecord>>>();
    let records = history();

    rsx! {
        HistoryPage {
            records: records,
            on_select: move |_id: String| {},
            on_delete: move |id: String| {
                let _ = peregrine_core::history::delete_scan(&id);
                let mut h = history();
                h.retain(|r| r.id != id);
                history.set(h);
            },
        }
    }
}
