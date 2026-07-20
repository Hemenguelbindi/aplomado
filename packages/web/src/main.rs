use dioxus::prelude::*;
use ui::{models::{HostInfo, Session}, Navbar, ScanStatusUi, ThemeProvider};
use views::{Dashboard, Home, Scan, History, Diff};

mod views;

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(WebNavbar)]
    #[route("/")]
    Dashboard {},
    #[route("/hosts")]
    Home {},
    #[route("/scan")]
    Scan {},
    #[route("/history")]
    History {},
    #[route("/diff")]
    Diff {},
}

const FAVICON: Asset = asset!("/assets/favicon.ico");

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let scan_results = use_signal(Vec::<HostInfo>::new);
    let scan_status = use_signal(|| ScanStatusUi::Idle);
    let history = use_signal(aplomado_core::history::load_history);
    let current_session = use_signal(|| {
        None::<Session>
    });

    {
        let mut sess = current_session;
        let mut results = scan_results;
        let mut st = scan_status;
        use_effect(move || {
            spawn(async move {
                if let Ok(sessions_json) = api::list_sessions().await {
                    if let Some(last_json) = sessions_json.into_iter().next() {
                        if let Ok(session) = serde_json::from_str::<Session>(&last_json) {
                            sess.set(Some(session));
                        }
                    }
                }
                if let Ok(Some(data)) = api::get_last_scan().await {
                    results.set(data.hosts);
                    st.set(ScanStatusUi::Done(data.count));
                }
            });
        });
    }

    use_context_provider(|| scan_results);
    use_context_provider(|| scan_status);
    use_context_provider(|| history);
    use_context_provider(|| current_session);

    rsx! {
        ThemeProvider {
            document::Title { "Aplomado — Сканер уязвимостей" }
            document::Link { rel: "icon", href: FAVICON }
            Router::<Route> {}
        }
    }
}

#[component]
fn WebNavbar() -> Element {
    let scan_status = use_context::<Signal<ScanStatusUi>>();
    let scan_results = use_context::<Signal<Vec<HostInfo>>>();
    let mut toggle = ui::theme::use_toggle_theme();

    let vuln_count: usize = scan_results
        .read()
        .iter()
        .flat_map(|h| h.ports.iter())
        .filter(|p| !p.cves.is_empty())
        .count();

    let route = use_route::<Route>();
    let current_route = match route {
        Route::Dashboard {} => "/".to_string(),
        Route::Home {} => "/hosts".to_string(),
        Route::Scan {} => "/scan".to_string(),
        Route::History {} => "/history".to_string(),
        Route::Diff {} => "/diff".to_string(),
    };

    rsx! {
        Navbar {
            current_route: Some(current_route),
            scan_status: scan_status(),
            vuln_count,
            on_theme_toggle: move |_| toggle(),
            Link {
                class: "no-underline transition-colors duration-200 hover:cursor-pointer",
                style: "color: var(--color-text-primary); margin-right: 1.25rem",
                to: Route::Dashboard {},
                "Панель"
            }
            Link {
                class: "no-underline transition-colors duration-200 hover:cursor-pointer",
                style: "color: var(--color-text-primary); margin-right: 1.25rem",
                to: Route::Home {},
                "Хосты"
            }
            Link {
                class: "no-underline transition-colors duration-200 hover:cursor-pointer",
                style: "color: var(--color-text-primary); margin-right: 1.25rem",
                to: Route::Scan {},
                "Сканер"
            }
            Link {
                class: "no-underline transition-colors duration-200 hover:cursor-pointer",
                style: "color: var(--color-text-primary); margin-right: 1.25rem",
                to: Route::History {},
                "История"
            }
            Link {
                class: "no-underline transition-colors duration-200 hover:cursor-pointer",
                style: "color: var(--color-text-primary); margin-right: 1.25rem",
                to: Route::Diff {},
                "Сравнение"
            }
        }
        Outlet::<Route> {}
    }
}
