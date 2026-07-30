//! CVE accuracy integration tests.
//! Requires Docker + aplomado-core built with scanner+fingerprint features.
//! Run: cargo test -p aplomado-core --test cve_accuracy --features fingerprint,database,cve-client,scanner -- --ignored --nocapture

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, TcpStream};
use std::path::Path;
use std::process::Command as StdCommand;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use serde::Deserialize;

// When scanner engine is not available, show a skip message
#[cfg(not(feature = "fingerprint"))]
#[test]
fn cve_accuracy_requires_fingerprint_feature() {
    eprintln!("SKIP: cve_accuracy tests require 'fingerprint' feature");
}

// ─── All test logic behind feature gate ────────────────────────────

#[cfg(feature = "fingerprint")]
mod test_impl {
    use super::*;

    #[derive(Deserialize)]
    struct TestCase {
        #[allow(dead_code)]
        name: String,
        compose: ComposeConfig,
        target: String,
        ports: Vec<u16>,
        expected_cves: HashMap<String, Vec<String>>,
        #[serde(default = "default_min_precision")]
        min_precision: f64,
        #[serde(default = "default_min_recall")]
        min_recall: f64,
        ready_condition: ReadyCondition,
    }

    fn default_min_precision() -> f64 { 0.5 }
    fn default_min_recall() -> f64 { 0.4 }

    #[derive(Deserialize)]
    struct ComposeConfig {
        services: HashMap<String, ComposeService>,
    }

    #[derive(Deserialize)]
    struct ComposeService {
        image: String,
        ports: Vec<String>,
        #[serde(default)]
        command: Option<Vec<String>>,
    }

    #[derive(Deserialize)]
    struct ReadyCondition {
        port: u16,
        #[serde(default = "default_delay")]
        delay_secs: u64,
    }

    fn default_delay() -> u64 { 5 }

    struct CaseSummary {
        tp: usize,
        fp: usize,
        fn_count: usize,
        precision: f64,
        recall: f64,
        found_cves: HashMap<u16, Vec<String>>,
        expected_cves: HashMap<u16, Vec<String>>,
    }

    // ─── Main test ─────────────────────────────────────────────────

    #[test]
    #[ignore = "requires Docker"]
    fn test_cve_accuracy_all_cases() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

        // Ensure CVE DB is initialized
        let path = aplomado_core::cve::cve_db_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        aplomado_core::cve::matcher::init_cve_db(&path);

        let cases_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("cve_cases");

        let mut entries: Vec<_> = std::fs::read_dir(&cases_dir)
            .expect("tests/cve_cases/ not found")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        if entries.is_empty() {
            eprintln!("WARNING: No test cases in {:?}", cases_dir);
            return;
        }

        let mut total_tp = 0usize;
        let mut total_fp = 0usize;
        let mut total_fn = 0usize;
        let mut passed = 0usize;
        let mut failed_cases = Vec::new();

        for entry in &entries {
            let case_path = entry.path();
            let case_name = entry.file_name().into_string().unwrap_or_default();
            eprintln!("\n━━━ Test case: {case_name} ━━━");

            match rt.block_on(run_single_case(&case_path, &case_name)) {
                Ok(summary) => {
                    total_tp += summary.tp;
                    total_fp += summary.fp;
                    total_fn += summary.fn_count;
                    passed += 1;
                    print_summary(&summary, true);
                }
                Err(err) => {
                    eprintln!("  FAILED: {err}");
                    failed_cases.push(case_name);
                }
            }
        }

        let precision = if total_tp + total_fp > 0 {
            total_tp as f64 / (total_tp + total_fp) as f64
        } else {
            1.0
        };
        let recall = if total_tp + total_fn > 0 {
            total_tp as f64 / (total_tp + total_fn) as f64
        } else {
            1.0
        };

        eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("  CVE Accuracy Summary");
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("  Cases:    {}/{} passed", passed, entries.len());
        eprintln!("  TP: {total_tp}, FP: {total_fp}, FN: {total_fn}");
        eprintln!("  Precision: {:.1}%", precision * 100.0);
        eprintln!("  Recall:    {:.1}%", recall * 100.0);
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        if !failed_cases.is_empty() {
            panic!("Failed: {}. See logs.", failed_cases.join(", "));
        }
    }

    // ─── Single case runner ────────────────────────────────────────

    async fn run_single_case(case_path: &Path, case_name: &str) -> Result<CaseSummary, String> {
        let config: TestCase = {
            let json_path = case_path.join("expected.json");
            let content =
                std::fs::read_to_string(&json_path).map_err(|e| format!("read {json_path:?}: {e}"))?;
            serde_json::from_str(&content)
                .map_err(|e| format!("parse {case_name}/expected.json: {e}"))?
        };

        // Write compose file
        let compose_file = case_path.join("docker-compose.yml");
        write_compose_file(&config, &compose_file)?;

        // Docker compose up
        let project_name = format!("aplomado-test-{case_name}");
        let up_ok = StdCommand::new("docker")
            .args([
                "compose", "-p", &project_name, "-f",
                compose_file.to_str().unwrap(), "up", "-d", "--wait",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !up_ok {
            let _ = StdCommand::new("docker")
                .args(["compose", "-p", &project_name, "down", "-v"])
                .status();
            let _ = std::fs::remove_file(&compose_file);
            return Err("docker compose up failed".into());
        }

        // Wait for readiness
        let ready = wait_for_ready(&config.ready_condition, &config.target);
        if !ready {
            let _ = StdCommand::new("docker")
                .args(["compose", "-p", &project_name, "down", "-v"])
                .status();
            let _ = std::fs::remove_file(&compose_file);
            return Err("container not ready in time".into());
        }

        // Run scanner
        let scan_result = run_scanner(&config.target, &config.ports).await;

        // Cleanup
        let _ = StdCommand::new("docker")
            .args(["compose", "-p", &project_name, "down", "-v"])
            .status();
        let _ = std::fs::remove_file(&compose_file);

        let scan_result = scan_result?;

        // Compare
        let expected_by_port: HashMap<u16, Vec<String>> = config
            .expected_cves
            .iter()
            .map(|(p, cves)| (p.parse::<u16>().unwrap_or(0), cves.clone()))
            .collect();

        let all_expected: HashSet<&str> = expected_by_port
            .values()
            .flatten()
            .map(|s| s.as_str())
            .collect();
        let all_found: HashSet<&str> = scan_result
            .values()
            .flatten()
            .map(|s| s.as_str())
            .collect();

        let tp = all_expected.intersection(&all_found).count();
        let fp = all_found.difference(&all_expected).count();
        let fn_count = all_expected.difference(&all_found).count();

        let precision = if tp + fp > 0 {
            tp as f64 / (tp + fp) as f64
        } else {
            1.0
        };
        let recall = if tp + fn_count > 0 {
            tp as f64 / (tp + fn_count) as f64
        } else {
            1.0
        };

        if precision < config.min_precision {
            return Err(format!(
                "precision {:.1}% < min {:.1}%",
                precision * 100.0,
                config.min_precision * 100.0
            ));
        }
        if recall < config.min_recall {
            return Err(format!(
                "recall {:.1}% < min {:.1}%",
                recall * 100.0,
                config.min_recall * 100.0
            ));
        }

        Ok(CaseSummary { tp, fp, fn_count, precision, recall, found_cves: scan_result, expected_cves: expected_by_port })
    }

    fn write_compose_file(config: &TestCase, path: &Path) -> Result<(), String> {
        let mut yaml = String::from("services:\n");
        for (name, svc) in &config.compose.services {
            yaml.push_str(&format!("  {name}:\n"));
            yaml.push_str(&format!("    image: {}\n", svc.image));
            yaml.push_str(&format!("    ports: [{}]\n", svc.ports.join(", ")));
            if let Some(cmd) = &svc.command {
                yaml.push_str(&format!(
                    "    command: [{}]\n",
                    cmd.iter()
                        .map(|c| format!("\"{c}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        std::fs::write(path, yaml).map_err(|e| format!("write compose: {e}"))
    }

    fn wait_for_ready(condition: &ReadyCondition, target: &str) -> bool {
        thread::sleep(Duration::from_secs(condition.delay_secs));
        for _ in 0..20 {
            let addr = format!("{}:{}", target, condition.port);
            if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(3)).is_ok()
            {
                return true;
            }
            thread::sleep(Duration::from_secs(2));
        }
        false
    }

    async fn run_scanner(target: &str, ports: &[u16]) -> Result<HashMap<u16, Vec<String>>, String> {
        let ip = IpAddr::from_str(target).map_err(|e| format!("bad IP {target}: {e}"))?;
        let host = aplomado_core::scanner::engine::scan_single_target(ip, ports, None).await;

        let mut result = HashMap::new();
        for p in &host.ports {
            let cves: Vec<String> = p.cves.iter().map(|c| c.id.clone()).collect();
            if !cves.is_empty() {
                result.insert(p.port, cves);
            }
        }

        eprintln!("  Found CVEs:");
        for (port, cves) in &result {
            for cve in cves {
                eprintln!("    Port {port}: {cve}");
            }
        }
        Ok(result)
    }

    fn print_summary(summary: &CaseSummary, _passed: bool) {
        eprintln!(
            "  Precision: {:.1}%  (TP={}, FP={}, FN={})",
            summary.precision * 100.0,
            summary.tp,
            summary.fp,
            summary.fn_count,
        );
        eprintln!("  Recall: {:.1}%", summary.recall * 100.0);

        let all_found: HashSet<&str> =
            summary.found_cves.values().flatten().map(|s| s.as_str()).collect();
        let all_expected: HashSet<&str> =
            summary.expected_cves.values().flatten().map(|s| s.as_str()).collect();

        let fn_cves: Vec<_> = all_expected.difference(&all_found).collect();
        if !fn_cves.is_empty() {
            eprintln!("  FN (missed): {fn_cves:?}");
        }
        let fp_cves: Vec<_> = all_found.difference(&all_expected).collect();
        if !fp_cves.is_empty() {
            eprintln!("  FP (unexpected): {fp_cves:?}");
        }
    }
}
