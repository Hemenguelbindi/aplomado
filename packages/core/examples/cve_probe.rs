//! Manual CVE detection test — scan Apache 2.4.49 on localhost:9001
//! Run: cargo run --bin cve_probe
use std::net::IpAddr;
use std::str::FromStr;

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // 1. Init CVE DB
    let path = aplomado_core::cve::cve_db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    aplomado_core::cve::matcher::init_cve_db(&path);
    eprintln!("CVE DB path: {:?}", path);

    // 2. Scan 127.0.0.1:9001,9002
    let ip = IpAddr::from_str("127.0.0.1").unwrap();
    let ports = [9001, 9002];

    eprintln!("Scanning 127.0.0.1:{:?} ...", ports);
    let host = rt.block_on(aplomado_core::scanner::engine::scan_single_target(
        ip, &ports, None,
    ));

    eprintln!("Alive: {}", host.alive);
    eprintln!("OS: {:?}", host.os_guess);

    for p in &host.ports {
        eprintln!(
            "Port {} ({}) banner={:?}",
            p.port, p.service_name, p.banner
        );
        eprintln!("  CVEs:");
        for c in &p.cves {
            eprintln!(
                "    {} | severity={} | cvss={} | confidence={}",
                c.id, c.severity, c.cvss_score, c.confidence
            );
        }
        if p.cves.is_empty() {
            eprintln!("    (none)");
        }
    }
}
