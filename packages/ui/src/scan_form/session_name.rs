use crate::components::{Button, ButtonVariant, TextInput};
use crate::models::Session;
use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct SessionNameProps {
    pub session: Session,
    pub on_update: EventHandler<Session>,
}

#[component]
pub fn SessionNameEditor(props: SessionNameProps) -> Element {
    let mut editing = use_signal(|| false);
    let mut name_input = use_signal(String::new);

    if editing() && props.session.name.is_empty() {
        rsx! {
            div { class: "flex gap-2",
                TextInput {
                    value: name_input(),
                    placeholder: "Название сессии (например: Аудит офиса)",
                    oninput: move |e| name_input.set(e),
                    onkeydown: {
                        let p = props.clone();
                        move |e: Event<KeyboardData>| {
                            if e.key() == Key::Enter && !name_input().is_empty() {
                                let mut s = p.session.clone();
                                s.name = name_input();
                                p.on_update.call(s);
                                editing.set(false);
                                name_input.set(String::new());
                            }
                        }
                    },
                }
                Button {
                    variant: ButtonVariant::Primary,
                    onclick: {
                        let p = props.clone();
                        move |_| {
                            let val = name_input();
                            if !val.is_empty() {
                                let mut s = p.session.clone();
                                s.name = val;
                                p.on_update.call(s);
                                editing.set(false);
                                name_input.set(String::new());
                            }
                        }
                    },
                    "Сохранить"
                }
            }
        }
    } else {
        let display_name = if props.session.name.is_empty() {
            "Новая сессия"
        } else {
            &props.session.name
        };
        rsx! {
            div { class: "flex items-center gap-2",
                h1 {
                    class: "text-2xl font-bold",
                    style: "color: var(--color-text-primary)",
                    "{display_name}"
                }
                span {
                    class: "text-xs font-mono",
                    style: "color: var(--color-text-muted)",
                    "{props.session.id}"
                }
                Button {
                    variant: ButtonVariant::Ghost,
                    onclick: move |_| editing.set(true),
                    "✏️"
                }
            }
        }
    }
}
