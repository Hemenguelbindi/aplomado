use crate::components::TextInput;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct PortInputProps {
    pub value: String,
    pub disabled: bool,
    pub on_input: EventHandler<String>,
}

#[component]
pub fn PortInput(props: PortInputProps) -> Element {
    rsx! {
        TextInput {
            value: props.value,
            placeholder: "80,443,554,8000-8100",
            label: "Порты (через запятую или диапазон):",
            disabled: props.disabled,
            oninput: move |e| props.on_input.call(e),
        }
    }
}
