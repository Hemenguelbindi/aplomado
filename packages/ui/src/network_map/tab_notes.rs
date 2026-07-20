use crate::components::TextInput;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct NotesTabProps {
    pub value: String,
    pub oninput: EventHandler<String>,
}

#[component]
pub fn NotesTab(props: NotesTabProps) -> Element {
    rsx! {
        div { class: "space-y-3",
            TextInput {
                value: props.value,
                placeholder: "Заметки об этом хосте...",
                class: "h-32 resize-y",
                oninput: move |e| props.oninput.call(e),
            }
            div {
                class: "text-xs",
                style: "color: var(--color-text-muted)",
                "Заметки сохраняются локально в сессии"
            }
        }
    }
}
