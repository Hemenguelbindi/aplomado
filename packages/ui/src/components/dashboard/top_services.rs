use dioxus::prelude::*;

#[component]
pub fn TopServicesChart(services: Vec<(String, usize)>) -> Element {
    if services.is_empty() {
        return rsx! { div { "Нет данных" } };
    }
    let max_count = services[0].1.max(1);
    rsx! {
        div { class: "space-y-2",
            for (service, count) in &services {
                div { class: "flex items-center gap-2",
                    span { class: "text-xs w-16 truncate", style: "color: var(--color-text-secondary)", "{service}" }
                    div { class: "flex-1 h-1.5 rounded-full overflow-hidden", style: "background: var(--color-border)",
                        div {
                            class: "h-full rounded-full",
                            style: "width: {count * 100 / max_count}%; background: var(--color-primary)"
                        }
                    }
                    span { class: "text-xs font-mono", style: "color: var(--color-text-muted)", "{count}" }
                }
            }
        }
    }
}
