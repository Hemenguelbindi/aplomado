use crate::history::ScanRecord;
use std::io;
use std::path::Path;

mod csv;
mod html;
mod json;
mod txt;
mod zip;

/// Supported export formats for scan reports.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExportFormat {
    Html,
    Json,
    Txt,
    Csv,
    /// ZIP archive (requires the `export` feature).
    Zip,
}

impl ExportFormat {
    /// Parse format from a string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "html" => Some(Self::Html),
            "json" => Some(Self::Json),
            "txt" | "text" => Some(Self::Txt),
            "csv" => Some(Self::Csv),
            "zip" => Some(Self::Zip),
            _ => None,
        }
    }

    /// Return the file extension for this format (without dot).
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Json => "json",
            Self::Txt => "txt",
            Self::Csv => "csv",
            Self::Zip => "zip",
        }
    }
}

// Re-export individual format functions for direct use / backward compat.
pub use csv::export_csv;
pub use html::{export_html, export_html_multi};
pub use json::export_json;
pub use txt::{export_txt, export_txt_multi};

// ── Single-record helpers (backward compat) ──────────────────────────────

/// Export a single record to string by format.
pub fn export_results(record: &ScanRecord, format: ExportFormat) -> Result<String, &'static str> {
    match format {
        ExportFormat::Html => Ok(html::export_html(record)),
        ExportFormat::Json => Ok(json::export_json(record)),
        ExportFormat::Txt => Ok(txt::export_txt(record)),
        ExportFormat::Csv => Err("CSV export requires multiple records; use save_reports instead"),
        ExportFormat::Zip => Err("ZIP export requires multiple records; use save_reports instead"),
    }
}

/// Save a single record to a file.
///
/// Supports Html, Json, Txt formats.
pub fn save_report(
    record: &ScanRecord,
    format: ExportFormat,
    output_path: &Path,
) -> io::Result<()> {
    let content = match format {
        ExportFormat::Html => html::export_html(record),
        ExportFormat::Json => json::export_json(record),
        ExportFormat::Txt => txt::export_txt(record),
        ExportFormat::Csv => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CSV export requires multiple records; use save_reports",
            ));
        }
        ExportFormat::Zip => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ZIP export requires multiple records; use save_reports",
            ));
        }
    };
    std::fs::write(output_path, &content)
}

// ── Multi-record helpers ─────────────────────────────────────────────────

/// Save multiple records to a single file (or ZIP archive).
pub fn save_reports(
    records: &[ScanRecord],
    format: ExportFormat,
    output_path: &Path,
) -> io::Result<()> {
    match format {
        ExportFormat::Json => save_reports_json(records, output_path),
        ExportFormat::Html => save_reports_html(records, output_path),
        ExportFormat::Txt => save_reports_txt(records, output_path),
        ExportFormat::Csv => save_reports_csv(records, output_path),
        ExportFormat::Zip => zip::save_reports_zip(records, output_path),
    }
}

fn save_reports_json(records: &[ScanRecord], output_path: &Path) -> io::Result<()> {
    let json = serde_json::to_string_pretty(records).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("JSON serialization error: {e}"),
        )
    })?;
    std::fs::write(output_path, &json)
}

fn save_reports_html(records: &[ScanRecord], output_path: &Path) -> io::Result<()> {
    let html = html::export_html_multi(records);
    std::fs::write(output_path, &html)
}

fn save_reports_txt(records: &[ScanRecord], output_path: &Path) -> io::Result<()> {
    let txt = txt::export_txt_multi(records);
    std::fs::write(output_path, &txt)
}

fn save_reports_csv(records: &[ScanRecord], output_path: &Path) -> io::Result<()> {
    let csv = csv::export_csv(records);
    std::fs::write(output_path, &csv)
}
