//! CVE accuracy integration tests.
//! Requires Docker. Run with:
//!   cargo test -p aplomado-core --test cve_accuracy -- --ignored --nocapture
//!
//! Each test case in tests/cve_cases/<name>/expected.json defines:
//!   - Docker compose service to spin up
//!   - Expected CVEs per port
//!   - Precision/recall thresholds
//!
//! The test runner:
//!   1. Spins up the container via docker compose
//!   2. Waits for readiness (HTTP 200 or TCP connect)
//!   3. Runs the scanner against the target
//!   4. Compares found CVEs with expected CVEs
//!   5. Reports precision and recall
//!   6. Tears down the container

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command as StdCommand;
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;

// ─── Test case config ──────────────────────────────────────────────

#[derive(Deserialize)]
struct TestCase {
    name: String,
    description: String,
    compose: ComposeConfig,
    target: String,
    ports: Vec<u16>,
    /// Expected CVEs per local port (mapped from container port)
    expected_cves: HashMap<String, Vec<String>>,
    /// CVEs that MUST NOT appear
    #[serde(default)]
    forbidden_cves: Vec<String>,
    /// Minimum acceptable precision (TP / (TP + FP))
    #[serde(default = "default_min_precision")]
    min_precision: f64,
    /// Minimum acceptable recall (TP / (TP + FN))
    #[serde(default = "default_min_recall")]
    min_recall: f64,
    /// How to check the container is ready
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
#[serde(tag = "type")]
enum ReadyCondition {
    #[serde(rename = "http")]
    Http {
        port: u16,
        path: String,
        #[serde(default = "default_expected_status")]
        expected_status: u16,
    },
    #[serde(rename = "tcp")]
    Tcp {
        port: u16,
        #[serde(default = "default_delay")]
        delay_secs: u64,
    },
}

fn default_expected_status() -> u16 { 200 }
fn default_delay() -> u64 { 5 }

// ─── Main test ─────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker"]
async fn test_cve_accuracy_all_cases() {
    // Ensure all CVE data is up to date before testing
    init_cve_db();

    let cases_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("cve_cases");

    let mut entries: Vec<_> = std::fs::read_dir(&cases_dir)
        .expect("tests/cve_cases/ directory not found")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    if entries.is_empty() {
        eprintln!(
            "WARNING: No test cases found in {:?}",
            cases_dir
        );
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

        let result = run_single_case(&case_path, &case_name).await;

        match result {
            Ok(summary) => {
                total_tp += summary.tp;
                total_fp += summary.fp;
                total_fn += summary.fn_count;
                passed += 1;
                print_case_result(&case_name, &summary, true);
            }
            Err(err) => {
                eprintln!("  FAILED: {err}");
                failed_cases.push(case_name);
            }
        }
    }

    // ─── Summary ───────────────────────────────────────────────────
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
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  CVE Accuracy Summary");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  Cases:    {}/{} passed", passed, entries.len());
    eprintln!("  TP:       {total_tp}");
    eprintln!("  FP:       {total_fp}");
    eprintln!("  FN:       {total_fn}");
    eprintln!("  Precision: {:.1}%", precision * 100.0);
    eprintln!("  Recall:    {:.1}%", recall * 100.0);
    eprintln!("  F1:        {:.1}%", f1 * 100.0);
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if !failed_cases.is_empty() {
        panic!(
            "Failed cases: {}. See logs above for details.",
            failed_cases.join(", ")
        );
    }
}

// ─── Single case runner ────────────────────────────────────────────

struct CaseSummary {
    tp: usize,
    fp: usize,
    fn_count: usize,
    precision: f64,
    recall: f64,
    found_cves: HashMap<u16, Vec<String>>,
    expected_cves: HashMap<u16, Vec<String>>,
}

async fn run_single_case(
    case_path: &Path,
    case_name: &str,
) -> Result<CaseSummary, String> {
    let config: TestCase = {
        let json_path = case_path.join("expected.json");
        let content = std::fs::read_to_string(&json_path)
            .map_err(|e| format!("failed to read {json_path:?}: {e}"))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse {case_name}/expected.json: {e}"))?
    };

    // 1. Generate docker-compose YAML
    let mut compose_yaml = String::from("services:\n");
    for (svc_name, svc) in &config.compose.services {
        compose_yaml.push_str(&format!("  {svc_name}:\n"));
        compose_yaml.push_str(&format!("    image: {}\n", svc.image));
        compose_yaml.push_str(&format!("    ports: [{}]\n", svc.ports.join(", ")));
        if let Some(cmd) = &svc.command {
            compose_yaml.push_str(&format!(
                "    command: [{}]\n",
                cmd.iter()
                    .map(|c| format!("\"{c}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    let compose_file = case_path.join("docker-compose.yml");
    std::fs::write(&compose_file, &compose_yaml)
        .map_err(|e| format!("failed to write compose file: {e}"))?;

    let project_name = format!("aplomado-test-{case_name}");
    let status = StdCommand::new("docker")
        .args([
            "compose",
            "-p",
            &project_name,
            "-f",
            compose_file.to_str().unwrap(),
            "up",
            "-d",
            "--wait",
        ])
        .status()
        .map_err(|e| format!("docker compose up failed: {e}"))?;

    if !status.success() {
        let _ = StdCommand::new("docker")
            .args(["compose", "-p", &project_name, "down", "-v"])
            .status();
        let _ = std::fs::remove_file(&compose_file);
        return Err("docker compose up returned non-zero".into());
    }

    // 2. Wait for readiness
    let ready = wait_for_ready(&config.ready_condition, &config.target).await;
    if !ready {
        let _ = StdCommand::new("docker")
            .args(["compose", "-p", &project_name, "down", "-v"])
            .status();
        let _ = std::fs::remove_file(&compose_file);
        return Err("container did not become ready in time".into());
    }

    // 3. Run scanner
    let scan_result = run_scanner(&config.target, &config.ports).await;

    // 4. Cleanup
    let _ = StdCommand::new("docker")
        .args(["compose", "-p", &project_name, "down", "-v"])
        .status();
    let _ = std::fs::remove_file(&compose_file);

    let scan_result = scan_result?;

    // 5. Compare
    let expected_by_port: HashMap<u16, Vec<String>> = config
        .expected_cves
        .iter()
        .map(|(port_str, cves)| (port_str.parse::<u16>().unwrap_or(0), cves.clone()))
        .collect();

    let mut tp = 0usize;
    let mut fp = 0usize;

    for (port, found) in &scan_result {
        let expected = expected_by_port.get(port).cloned().unwrap_or_default();
        let expected_set: HashSet<&str> = expected.iter().map(|s| s.as_str()).collect();
        let found_set: HashSet<&str> = found.iter().map(|s| s.as_str()).collect();

        for cve in &found_set {
            if expected_set.contains(cve) {
                tp += 1;
            } else {
                fp += 1;
            }
        }
    }

    // FN = expected but not found
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

    let summary = CaseSummary {
        tp,
        fp,
        fn_count,
        precision,
        recall,
        found_cves: scan_result,
        expected_cves: expected_by_port,
    };

    // Check thresholds
    if precision < config.min_precision {
        return Err(format!(
            "precision {:.1}% < minimum {:.1}%",
            precision * 100.0,
            config.min_precision * 100.0
        ));
    }
    if recall < config.min_recall {
        return Err(format!(
            "recall {:.1}% < minimum {:.1}%",
            recall * 100.0,
            config.min_recall * 100.0
        ));
    }

    Ok(summary)
}

// ─── Wait for ready ────────────────────────────────────────────────

async fn wait_for_ready(condition: &ReadyCondition, target: &str) -> bool {
    match condition {
        ReadyCondition::Http {
            port,
            path: _,
            expected_status: _,
        } => {
            // TCP connect is sufficient for readiness (HTTP would need reqwest dep)
            for _ in 0..30 {
                if tokio::net::TcpStream::connect((target, *port))
                    .await
                    .is_ok()
                {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    return true;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            false
        }
        ReadyCondition::Tcp { port, delay_secs } => {
            tokio::time::sleep(Duration::from_secs(*delay_secs)).await;
            for _ in 0..20 {
                if tokio::net::TcpStream::connect((target, *port))
                    .await
                    .is_ok()
                {
                    return true;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            false
        }
    }
}

// ─── Scanner wrapper ───────────────────────────────────────────────

async fn run_scanner(
    target: &str,
    ports: &[u16],
) -> Result<HashMap<u16, Vec<String>>, String> {
    let ip = IpAddr::from_str(target)
        .map_err(|e| format!("invalid target IP {target}: {e}"))?;

    // Init CVE DB from current sources
    #[cfg(feature = "database")]
    {
        let path = aplomado_core::cve::cve_db_path();
        aplomado_core::cve::matcher::init_cve_db(&path);
    }

    let ports_vec: Vec<u16> = ports.to_vec();
    let host = aplomado_core::scanner::engine::scan_single_target(ip, &ports_vec, None).await;

    let mut result: HashMap<u16, Vec<String>> = HashMap::new();
    for port_info in &host.ports {
        let cves: Vec<String> = port_info
            .cves
            .iter()
            .map(|c| c.id.clone())
            .collect();
        if !cves.is_empty() {
            result.insert(port_info.port, cves);
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

// ─── Reporting ─────────────────────────────────────────────────────

fn print_case_result(_case_name: &str, summary: &CaseSummary, passed: bool) {
    let status = if passed { "PASS" } else { "FAIL" };
    eprintln!("  ── {status} ──");
    eprintln!("  Precision: {:.1}%  ({}/{} TP, {} FP)",
        summary.precision * 100.0,
        summary.tp,
        summary.tp + summary.fp + summary.fn_count,
        summary.fp,
    );
    eprintln!("  Recall:    {:.1}%  ({}/{} TP, {} FN)",
        summary.recall * 100.0,
        summary.tp,
        summary.tp + summary.fn_count,
        summary.fn_count,
    );

    // List FN and FP
    let all_expected: HashSet<&str> = summary
        .expected_cves
        .values()
        .flatten()
        .map(|s| s.as_str())
        .collect();
    let all_found: HashSet<&str> = summary
        .found_cves
        .values()
        .flatten()
        .map(|s| s.as_str())
        .collect();

    let fn_cves: Vec<&&str> = all_expected.difference(&all_found).collect();
    if !fn_cves.is_empty() {
        eprintln!("  FN (missed): {:?}", fn_cves);
    }
    let fp_cves: Vec<&&str> = all_found.difference(&all_expected).collect();
    if !fp_cves.is_empty() {
        eprintln!("  FP (unexpected): {:?}", fp_cves);
    }
}

// ─── CVE DB init ───────────────────────────────────────────────────

fn init_cve_db() {
    #[cfg(feature = "database")]
    {
        let path = aplomado_core::cve::cve_db_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        aplomado_core::cve::matcher::init_cve_db(&path);
    }
}
