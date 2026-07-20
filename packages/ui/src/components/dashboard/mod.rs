pub mod critical_alerts;
pub mod recent_scans;
pub mod stat_card;
pub mod top_services;
pub mod types;

pub use critical_alerts::CriticalAlertsCard;
pub use recent_scans::RecentScansTable;
pub use stat_card::StatCard;
pub use top_services::TopServicesChart;
pub use types::{calculate_stats, CriticalVulnItem, DashboardStats};
