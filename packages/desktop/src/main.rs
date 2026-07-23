use clap::Parser;
use dioxus::prelude::*;
use ui::{
    models::{HostInfo, Session, SessionStatus},
    Navbar, ScanStatusUi, ThemeProvider,
};
use views::{Dashboard, History, Home, Scan};

mod views;

#[derive(Parser)]
#[command(name = "aplomado", about = "Aplomado Vulnerability Scanner")]
enum Cli {
    /// Запустить GUI (desktop)
    #[command(name = "run")]
    Run,

    /// Запустить web-сервер
    #[command(name = "serve")]
    Serve {
        #[arg(default_value = "8080")]
        port: u16,
    },

    /// Сканировать из CLI (без GUI)
    #[command(name = "scan")]
    Scan { targets: Vec<String> },

    /// Показать историю
    #[command(name = "list")]
    List,

    /// Показать детали скана
    #[command(name = "show")]
    Show {
        #[arg(long)]
        id: Option<String>,
        #[arg(short, long)]
        last: bool,
    },

    /// Экспортировать отчёт
    #[command(name = "export")]
    Export {
        #[arg(long)]
        id: Option<String>,
        #[arg(short, long)]
        last: bool,
        #[arg(default_value = "html")]
        format: String,
    },

    /// Обновить CVE базу
    #[command(name = "update-cve")]
    UpdateCve,
}

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(DesktopNavbar)]
    #[route("/")]
    Dashboard {},
    #[route("/hosts")]
    Home {},
    #[route("/scan")]
    Scan {},
    #[route("/history")]
    History {},
}

fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::Run => {
            #[cfg(feature = "desktop")]
            dioxus::launch(App);
            #[cfg(not(feature = "desktop"))]
            eprintln!("Desktop mode not available. Build with --features desktop");
        }
        Cli::Serve { port } => {
            eprintln!("Web server mode — use `dx serve` in packages/web instead. Port: {port}");
        }
        Cli::Scan { targets } => {
            run_cli_scan(&targets);
        }
        Cli::List => {
            show_history();
        }
        Cli::Show { id, last } => {
            show_scan_details(id, last);
        }
        Cli::Export { id, last, format } => {
            export_report(id, last, &format);
        }
        Cli::UpdateCve => {
            update_cve_from_sources();
        }
    }
}

#[component]
fn App() -> Element {
    let scan_results = use_signal(Vec::<HostInfo>::new);
    use_context_provider(|| scan_results);

    let scan_status = use_signal(|| ScanStatusUi::Idle);
    use_context_provider(|| scan_status);

    let current_session = use_signal(|| {
        let now = chrono::Local::now().to_rfc3339();
        Session {
            id: format!("ses_{}", chrono::Local::now().timestamp_millis()),
            name: String::new(),
            targets: vec![],
            status: SessionStatus::Idle,
            created_at: now.clone(),
            updated_at: now,
            hosts: vec![],
            duration_secs: 0,
        }
    });
    use_context_provider(|| current_session);

    let history = use_signal(aplomado_core::history::load_history);
    use_context_provider(|| history);

    aplomado_core::cve::init_cve_on_startup();

    rsx! {
        ThemeProvider {
            Router::<Route> {}
        }
    }
}

#[component]
fn DesktopNavbar() -> Element {
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
                "Dashboard"
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
        }
        Outlet::<Route> {}
    }
}

// ─── CLI commands ──────────────────────────────────────────────

fn run_cli_scan(targets: &[String]) {
    aplomado_core::cve::init_cve_on_startup();
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    rt.block_on(async {
        use std::net::ToSocketAddrs;

        for target_str in targets {
            eprintln!("Scanning: {target_str}");

            let ips: Vec<std::net::IpAddr> = if let Ok(ip) = target_str.parse() {
                vec![ip]
            } else if target_str.contains('/') {
                match aplomado_core::scanner::expand_cidr(target_str) {
                    Ok(ips) => ips,
                    Err(e) => {
                        eprintln!("  CIDR expansion failed: {e}");
                        continue;
                    }
                }
            } else {
                match (target_str.as_str(), 0).to_socket_addrs() {
                    Ok(addrs) => addrs.map(|a| a.ip()).collect(),
                    Err(e) => {
                        eprintln!("  DNS resolution failed: {e}");
                        continue;
                    }
                }
            };

            for ip in &ips {
                let host =
                    aplomado_core::scanner::engine::scan_single_target(*ip, ui::COMMON_PORTS, None)
                        .await;
                let status = if host.alive { "ALIVE" } else { "DOWN" };
                println!(
                    "{ip}\t{status}\t{}",
                    host.os_guess.as_deref().unwrap_or("?")
                );
                for p in &host.ports {
                    let ver = p.service_version.as_deref().unwrap_or("");
                    let banner = p.banner.as_deref().unwrap_or("");
                    println!("  {}/tcp\t{}\t{ver}\t{banner}", p.port, p.service_name);
                }
            }
        }
    });
}

fn show_history() {
    let records = aplomado_core::history::load_history();
    if records.is_empty() {
        println!("No scan history found.");
        return;
    }
    println!(
        "{:<36} {:<30} {:>6} {:>6} {:>6} {:>6}",
        "ID", "Targets", "Hosts", "Alive", "Ports", "Time"
    );
    println!("{}", "-".repeat(100));
    for r in &records {
        let targets = r.targets.join(", ");
        let short_targets = if targets.len() > 28 {
            format!("{}..", &targets[..28])
        } else {
            targets
        };
        println!(
            "{:<36} {:<30} {:>6} {:>6} {:>6} {:>5}s",
            &r.id[..36.min(r.id.len())],
            short_targets,
            r.hosts_total,
            r.hosts_alive,
            r.ports_total,
            r.duration_secs,
        );
    }
}

fn show_scan_details(id: Option<String>, last: bool) {
    let records = aplomado_core::history::load_history();
    let record = if last {
        records.first()
    } else if let Some(id) = id {
        records.iter().find(|r| r.id == id)
    } else {
        eprintln!("Provide --id <ID> or --last");
        return;
    };

    match record {
        Some(r) => {
            println!("Scan: {}", r.id);
            println!("Date: {}", r.timestamp);
            println!("Targets: {}", r.targets.join(", "));
            println!("Duration: {}s", r.duration_secs);
            println!("Hosts: {} total, {} alive", r.hosts_total, r.hosts_alive);
            println!("Ports found: {}", r.ports_total);
            println!();
            for h in &r.hosts {
                let status = if h.alive { "ALIVE" } else { "DOWN" };
                println!(
                    "  {} ({}) [{status}]",
                    h.ip,
                    h.hostname.as_deref().unwrap_or("?"),
                );
                if let Some(os) = &h.os_guess {
                    println!("    OS: {os}");
                }
                for p in &h.ports {
                    let ver = p.version.as_deref().unwrap_or("");
                    println!("    {}/tcp  {}  {ver}", p.port, p.service);
                }
            }
        }
        None => eprintln!("Scan not found."),
    }
}

fn export_report(id: Option<String>, last: bool, format: &str) {
    let fmt: aplomado_core::export::ExportFormat = format
        .parse()
        .expect("Unsupported format. Use: html, json, txt");
    let records = aplomado_core::history::load_history();
    let record = if last {
        records.first()
    } else if let Some(id) = id {
        records.iter().find(|r| r.id == id)
    } else {
        eprintln!("Provide --id <ID> or --last");
        return;
    };

    match record {
        Some(r) => {
            let output = std::path::Path::new("aplomado-report").with_extension(fmt.extension());
            aplomado_core::export::save_report(r, fmt, &output).expect("Failed to save report");
            println!("Report saved: {}", output.display());
        }
        None => eprintln!("Scan not found."),
    }
}

fn update_cve_from_sources() {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    let count = rt.block_on(aplomado_core::cve::update_cve_if_stale());
    if count > 0 {
        println!("CVE database updated: {count} entries");
    } else {
        eprintln!("CVE update failed or no new data available.");
    }
}
