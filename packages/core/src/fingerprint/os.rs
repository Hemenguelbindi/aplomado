/// OS fingerprinting — определение ОС и дистрибутива по баннерам.

/// Определить ОС (с дистрибутивом) по открытым портам и баннерам.
pub fn guess_os(ports: &[(u16, String, Option<String>)]) -> Option<String> {
    if ports.is_empty() {
        return None;
    }

    // First pass: try to detect specific distro from SSH/HTTP banners
    if let Some(distro) = detect_distro_from_banners(ports) {
        return Some(distro);
    }

    // Fallback: family-level detection (Windows vs Linux/Unix)
    fallback_os_family(ports)
}

/// Try to detect a specific Linux distribution from service banners.
fn detect_distro_from_banners(ports: &[(u16, String, Option<String>)]) -> Option<String> {
    let mut distros: Vec<&str> = Vec::new();

    for (port, _service, banner) in ports {

        // SSH banner format: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
        if *port == 22 {
            if let Some(ref banner) = banner {
                let lower = banner.to_lowercase();
                if lower.contains("ubuntu") {
                    distros.push("Ubuntu");
                    continue;
                }
                if lower.contains("debian-") || lower.contains("debian ") {
                    distros.push("Debian");
                    continue;
                }
                if lower.contains("rhel") {
                    distros.push("RHEL");
                    continue;
                }
                if lower.contains("centos") {
                    distros.push("CentOS");
                    continue;
                }
                if lower.contains("fedora") {
                    distros.push("Fedora");
                    continue;
                }
                if lower.contains("alpine") {
                    distros.push("Alpine");
                    continue;
                }
                if lower.contains("freebsd") {
                    distros.push("FreeBSD");
                    continue;
                }
                if lower.contains("openbsd") {
                    distros.push("OpenBSD");
                    continue;
                }
            }
        }

        // HTTP Server header may contain distro in parentheses:
        // "Server: Apache/2.4.41 (Ubuntu)" or "Server: nginx/1.18.0 (Ubuntu)"
        if *port == 80 || *port == 443 || *port == 8080 || *port == 8443 {
            if let Some(ref banner) = banner {
                let lower = banner.to_lowercase();
                for distro in &[
                    ("ubuntu", "Ubuntu"),
                    ("debian", "Debian"),
                    ("centos", "CentOS"),
                    ("rhel", "RHEL"),
                    ("fedora", "Fedora"),
                    ("alpine", "Alpine"),
                    ("freebsd", "FreeBSD"),
                    ("windows", "Windows"),
                ] {
                    if lower.contains(distro.0) {
                        distros.push(distro.1);
                        break;
                    }
                }
            }
        }
    }

    // Return the most frequently detected distro
    if distros.is_empty() {
        return None;
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for d in &distros {
        *counts.entry(d).or_insert(0) += 1;
    }
    let best = counts.into_iter().max_by_key(|(_, c)| *c).map(|(d, _)| d)?;

    match best {
        "Windows" => Some("Windows".to_string()),
        "FreeBSD" => Some("FreeBSD".to_string()),
        "OpenBSD" => Some("OpenBSD".to_string()),
        other => Some(format!("{other} Linux")),
    }
}

/// Determine OS family (Windows vs Linux/Unix) using port and banner heuristics.
fn fallback_os_family(ports: &[(u16, String, Option<String>)]) -> Option<String> {
    let mut windows_score = 0i32;
    let mut linux_score = 0i32;

    for (port, service, banner) in ports {
        let banner_lower = banner.as_deref().unwrap_or("").to_lowercase();

        // Windows
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

        // Linux/Unix
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

    if windows_score >= 3 && windows_score > linux_score {
        return Some("Windows".to_string());
    }
    if linux_score >= 3 && linux_score > windows_score {
        return Some("Linux".to_string());
    }
    if windows_score > 0 && linux_score == 0 {
        return Some("Windows".to_string());
    }
    if linux_score > 0 && windows_score == 0 {
        return Some("Linux".to_string());
    }

    let port_set: std::collections::HashSet<u16> = ports.iter().map(|(p, _, _)| *p).collect();
    let win_ports = [135, 139, 445, 3389, 593, 1433];
    let linux_ports = [22, 53, 80, 443, 3306, 5432, 6379, 27017, 9090, 9200];

    let win_count = win_ports.iter().filter(|p| port_set.contains(p)).count();
    let linux_count = linux_ports.iter().filter(|p| port_set.contains(p)).count();

    if win_count >= 2 && port_set.contains(&3389) {
        Some("Likely Windows (RDP + RPC)".to_string())
    } else if linux_count >= 3 {
        Some("Likely Linux".to_string())
    } else if port_set.contains(&3389) || win_count >= 2 {
        Some("Likely Windows".to_string())
    } else if port_set.contains(&22) {
        Some("Likely Linux/Unix".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubuntu_ssh() {
        let ports = vec![(
            22,
            "ssh".to_string(),
            Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".to_string()),
        )];
        assert_eq!(guess_os(&ports), Some("Ubuntu Linux".to_string()));
    }

    #[test]
    fn test_debian_ssh() {
        let ports = vec![(
            22,
            "ssh".to_string(),
            Some("SSH-2.0-OpenSSH_8.9p1 Debian-3+deb11u1".to_string()),
        )];
        assert_eq!(guess_os(&ports), Some("Debian Linux".to_string()));
    }

    #[test]
    fn test_windows_rdp() {
        let ports = vec![(3389, "rdp".to_string(), None)];
        assert_eq!(guess_os(&ports), Some("Windows".to_string()));
    }

    #[test]
    fn test_ubuntu_http() {
        let ports = vec![(
            80,
            "http".to_string(),
            Some("Server: Apache/2.4.41 (Ubuntu)".to_string()),
        )];
        assert_eq!(guess_os(&ports), Some("Ubuntu Linux".to_string()));
    }

    #[test]
    fn test_empty_returns_none() {
        assert_eq!(guess_os(&[]), None);
    }

    #[test]
    fn test_rhel_ssh() {
        let ports = vec![(
            22,
            "ssh".to_string(),
            Some("SSH-2.0-OpenSSH_8.9p1 RHEL 8".to_string()),
        )];
        assert_eq!(guess_os(&ports), Some("RHEL Linux".to_string()));
    }
}
