use dioxus::prelude::*;
use ui::{models::HostInfo, Navbar, ScanStatusUi};
use views::{Dashboard, Home, Scan};

mod views;

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(MobileNavbar)]
    #[route("/")]
    Dashboard {},
    #[route("/hosts")]
    Home {},
    #[route("/scan")]
    Scan {},
}

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let scan_results = use_signal(Vec::<HostInfo>::new);
    use_context_provider(|| scan_results);

    let scan_status = use_signal(|| ScanStatusUi::Idle);
    use_context_provider(|| scan_status);

    rsx! {
        document::Stylesheet { href: ui::TAILWIND_CSS }
        Router::<Route> {}
    }
}

#[component]
fn MobileNavbar() -> Element {
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
    };

    rsx! {
        Navbar {
            current_route: Some(current_route),
            scan_status: scan_status(),
            vuln_count,
            on_theme_toggle: move |_| toggle(),
            Link { class: "text-white mr-5 no-underline transition-colors duration-200 hover:cursor-pointer hover:text-[#91a4d2]", to: Route::Dashboard {}, "Dashboard" }
            Link { class: "text-white mr-5 no-underline transition-colors duration-200 hover:cursor-pointer hover:text-[#91a4d2]", to: Route::Home {}, "Хосты" }
            Link { class: "text-white mr-5 no-underline transition-colors duration-200 hover:cursor-pointer hover:text-[#91a4d2]", to: Route::Scan {}, "Сканер" }
        }
        Outlet::<Route> {}
    }
}
