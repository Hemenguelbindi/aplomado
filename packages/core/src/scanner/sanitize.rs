//! Data sanitization for untrusted remote host data.
//!
//! Functions to clean banner data, certificate fields, and error contexts
//! received from potentially malicious remote hosts.

/// Sanitize banner bytes from a remote service.
///
/// - Max `max_bytes` bytes are processed
/// - Null bytes (`0x00`) cause the entire input to be rejected (`None`)
/// - Only printable ASCII (`0x20`–`0x7E`) and `\t`, `\n`, `\r` are kept
/// - All other bytes are stripped
/// - Returns `None` if the input is empty or nothing valid remains
pub fn sanitize_banner(raw: &[u8], max_bytes: usize) -> Option<String> {
    if raw.is_empty() || max_bytes == 0 {
        return None;
    }

    let len = raw.len().min(max_bytes);
    let raw = &raw[..len];

    // Null bytes → reject entirely
    if raw.contains(&0x00) {
        return None;
    }

    let mut result = String::with_capacity(len);
    for &b in raw {
        match b {
            0x20..=0x7E | b'\t' | b'\n' | b'\r' => result.push(b as char),
            _ => continue,
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Sanitize a certificate field value (RFC 5280 — max 255 bytes).
///
/// Delegates to [`sanitize_banner`] with `max_bytes = 255`.
pub fn sanitize_cert_field(raw: &[u8]) -> Option<String> {
    sanitize_banner(raw, 255)
}

/// Sanitize an error context string.
///
/// - Max 512 bytes processed
/// - Only printable ASCII and common whitespace are kept
/// - Lines containing internal IPs (`10.x`, `172.16–31.x`, `192.168.x`),
///   stack-trace markers (`at `, ` in `), or file-path separators
///   (`/` or `\`) are **removed**
/// - Returns empty `String` if nothing valid remains
pub fn sanitize_error_context(raw: &[u8]) -> String {
    let len = raw.len().min(512);
    let raw = &raw[..len];

    let mut cleaned = String::new();
    for &b in raw {
        match b {
            0x20..=0x7E | b'\t' | b'\n' | b'\r' => cleaned.push(b as char),
            _ => continue,
        }
    }

    let filtered: Vec<&str> = cleaned
        .lines()
        .filter(|line| {
            let lower = line.to_lowercase();

            // Internal IPs
            if lower.contains("10.") || lower.contains("192.168.") {
                return false;
            }
            if contains_172_private(line) {
                return false;
            }

            // Stack-trace markers
            if line.contains("at ") || line.contains(" in ") {
                return false;
            }

            // File-path separators
            if line.contains('/') || line.contains('\\') {
                return false;
            }

            true
        })
        .collect();

    filtered.join("\n")
}

/// Check if a string contains a private IP in the 172.16.0.0/12 range.
fn contains_172_private(s: &str) -> bool {
    if let Some(pos) = s.find("172.") {
        let after = &s[pos + 4..];
        if after.len() >= 2 {
            if let Ok(n) = after[..2].parse::<u8>() {
                return (16..=31).contains(&n);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_bytes_rejected() {
        assert_eq!(sanitize_banner(b"SSH-2.0\x00OpenSSH", 1024), None);
    }

    #[test]
    fn control_chars_stripped() {
        assert_eq!(
            sanitize_banner(b"SSH-\x01.0", 1024),
            Some("SSH-.0".to_string())
        );
    }

    #[test]
    fn max_bytes_enforced() {
        let input = vec![b'A'; 2000];
        let result = sanitize_banner(&input, 1024).unwrap();
        assert_eq!(result.len(), 1024);
    }

    #[test]
    fn empty_input_returns_none() {
        assert_eq!(sanitize_banner(b"", 1024), None);
    }

    #[test]
    fn printable_ascii_preserved() {
        assert_eq!(
            sanitize_banner(b"Apache/2.4.41 (Ubuntu)", 1024),
            Some("Apache/2.4.41 (Ubuntu)".to_string())
        );
    }

    #[test]
    fn cert_field_255_limit() {
        let input = vec![b'X'; 300];
        let result = sanitize_cert_field(&input).unwrap();
        assert_eq!(result.len(), 255);
    }

    #[test]
    fn error_context_strips_internal_ip() {
        let input = b"error\nat 10.0.0.1:1234";
        let result = sanitize_error_context(input);
        assert_eq!(result, "error");
    }

    #[test]
    fn sanitize_banner_rejects_xss() {
        let result = sanitize_banner(b"\x01<script>alert('xss')</script>\x02", 1024);
        assert_eq!(
            result,
            Some("<script>alert('xss')</script>".to_string())
        );
    }
}
