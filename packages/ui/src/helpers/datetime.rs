/// Formatiert ISO-Timestamp in lesbare Form: "2024-01-15 14:30:00"
pub fn format_datetime(iso: &str) -> String {
    // Versuche RFC3339 zu parsen, sonst schneide rohes ISO
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(iso) {
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    } else if iso.len() >= 19 {
        iso[..19].replace("T", " ")
    } else {
        iso.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_datetime_rfc3339() {
        assert_eq!(
            format_datetime("2024-01-15T14:30:00+00:00"),
            "2024-01-15 14:30:00"
        );
    }

    #[test]
    fn test_format_datetime_iso_like() {
        assert_eq!(
            format_datetime("2024-01-15T14:30:00"),
            "2024-01-15 14:30:00"
        );
    }

    #[test]
    fn test_format_datetime_short() {
        assert_eq!(format_datetime("2024"), "2024");
    }

    #[test]
    fn test_format_datetime_empty() {
        assert_eq!(format_datetime(""), "");
    }
}
