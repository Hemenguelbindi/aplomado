//! OS fingerprinting — определение ОС по баннерам сервисов.

/// Определить ОС по открытым портам и баннерам.
/// Без root, без raw socket. Использует уже полученные баннеры (HTTP, SSH, SMB etc).
pub fn guess_os(ports: &[(u16, String, Option<String>)]) -> Option<String> {
    if ports.is_empty() {
        return None;
    }

    let mut windows_score = 0i32;
    let mut linux_score = 0i32;

    for (port, service, banner) in ports {
        let banner_lower = banner.as_deref().unwrap_or("").to_lowercase();

        // === Windows признаки ===
        if banner_lower.contains("microsoft-iis") {
            windows_score += 3;
        }
        if banner_lower.contains("microsoft") || banner_lower.contains("windows") {
            windows_score += 2;
        }
        if banner_lower.contains("openssh_for_windows") {
            windows_score += 3;
        }
        if *port == 3389 {
            windows_score += 2;
        }
        if *port == 135 || *port == 139 || *service == "msrpc" {
            windows_score += 1;
        }
        if banner_lower.contains("exchange") && *port == 25 {
            windows_score += 2;
        }

        // === Linux признаки ===
        if banner_lower.contains("ubuntu") || banner_lower.contains("debian") {
            linux_score += 3;
        }
        if banner_lower.contains("centos") || banner_lower.contains("red hat") {
            linux_score += 3;
        }
        if banner_lower.contains("rhel") || banner_lower.contains("fedora") {
            linux_score += 3;
        }
        if banner_lower.contains("apache") && !banner_lower.contains("iis") {
            linux_score += 1;
        }
        if banner_lower.contains("nginx") {
            linux_score += 1;
        }
        if banner_lower.contains("openssh") && !banner_lower.contains("windows") {
            linux_score += 1;
        }
        if banner_lower.contains("samba") {
            linux_score += 1;
        }
    }

    // === Итоговое решение ===
    if windows_score >= 3 && windows_score > linux_score {
        Some("Windows".to_string())
    } else if linux_score >= 3 && linux_score > windows_score {
        Some("Linux".to_string())
    } else if windows_score > 0 && linux_score == 0 {
        Some("Windows".to_string())
    } else if linux_score > 0 && windows_score == 0 {
        Some("Linux".to_string())
    } else {
        let port_set: std::collections::HashSet<u16> = ports.iter().map(|(p, _, _)| *p).collect();

        let win_ports = [135, 139, 445, 3389, 593, 1433];
        let linux_ports = [22, 53, 80, 443, 3306, 5432, 6379, 27017, 9090, 9200];

        let win_count = win_ports.iter().filter(|p| port_set.contains(p)).count();
        let linux_count = linux_ports.iter().filter(|p| port_set.contains(p)).count();

        if win_count >= 2 && port_set.contains(&3389) {
            Some("Likely Windows (RDP + RPC)".to_string())
        } else if linux_count >= 3 {
            Some("Likely Linux".to_string())
        } else if win_count >= 2 {
            Some("Likely Windows".to_string())
        } else if port_set.contains(&3389) {
            Some("Likely Windows".to_string())
        } else if port_set.contains(&22) {
            Some("Likely Linux/Unix".to_string())
        } else {
            None
        }
    }
}
