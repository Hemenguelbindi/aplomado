//! Модели данных для сканера.
//!
//! Все типы перенесены в `aplomado-types` — единый источник истины.

pub use aplomado_types::{
    extract_version, extract_version_num, CveSummary, Hop, HostInfo, PortInfo, PortState,
    ScanResult, ScanTarget, TransportProto,
};
