use crate::HistoryView;
use dioxus::prelude::*;
use aplomado_core::history::ScanRecord;

#[derive(Props, Clone, PartialEq)]
pub struct HistoryPageProps {
    pub records: Vec<ScanRecord>,
    pub on_select: EventHandler<String>,
    pub on_delete: EventHandler<String>,
}

#[component]
pub fn HistoryPage(props: HistoryPageProps) -> Element {
    rsx! {
        div { class: "p-8 max-w-6xl mx-auto",
            h1 {
                class: "text-2xl font-bold mb-6",
                style: "color: var(--color-text-primary)",
                "История сканов"
            }

            HistoryView {
                records: props.records,
                on_select: move |id: String| props.on_select.call(id),
                on_delete: move |id: String| props.on_delete.call(id),
            }
        }
    }
}
