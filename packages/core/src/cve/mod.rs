pub mod client;
pub mod database;
pub mod matcher;

#[cfg(feature = "cve-client")]
pub mod update;

pub use database::{CveDatabase, CveEntry, CveSeverity, VersionRange};
pub use matcher::{get_cve_db, init_cve_db, match_cves};
