//! Force CVE database update with full logging.
//! Run: cargo run -p aplomado-core --example cve_update --features fingerprint,database,cve-client,scanner
fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let path = aplomado_core::cve::cve_db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    eprintln!("Updating CVE database at {:?} ...", path);
    let result = rt.block_on(aplomado_core::cve::update::update_cve_from_sources(&path));

    match result {
        Ok(entries) => eprintln!("DONE: {} entries after dedup", entries.len()),
        Err(e) => eprintln!("ERROR: {e}"),
    }
}
