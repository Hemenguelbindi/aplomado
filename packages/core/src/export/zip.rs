use crate::history::ScanRecord;
use std::path::Path;

/// Create a ZIP archive containing HTML, JSON, and TXT reports for each record.
#[cfg(not(feature = "export"))]
pub fn save_reports_zip(_records: &[ScanRecord], _output_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "ZIP export requires the 'export' feature",
    ))
}

/// Create a ZIP archive containing HTML, JSON, and TXT reports for each record.
#[cfg(feature = "export")]
pub fn save_reports_zip(records: &[ScanRecord], output_path: &Path) -> std::io::Result<()> {
    use std::io::Write;

    use super::html::export_html;
    use super::json::export_json;
    use super::txt::export_txt;

    let file = std::fs::File::create(output_path)?;
    let mut zip_writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for record in records {
        let html = export_html(record);
        let json = export_json(record);
        let txt = export_txt(record);

        let base_name = sanitize_filename(&record.id);
        for (ext, content) in [("html", &html), ("json", &json), ("txt", &txt)] {
            let entry_path = format!("{base_name}.{ext}");
            zip_writer
                .start_file(&entry_path, options)
                .map_err(|e| std::io::Error::other(format!("ZIP entry error: {e}")))?;
            zip_writer
                .write_all(content.as_bytes())
                .map_err(|e| std::io::Error::other(format!("ZIP write error: {e}")))?;
        }
    }

    zip_writer
        .finish()
        .map_err(|e| std::io::Error::other(format!("ZIP finish error: {e}")))?;
    Ok(())
}

#[cfg(feature = "export")]
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
}
