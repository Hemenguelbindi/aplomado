//! Модели данных для сканера.
//!
//! Все типы перенесены в `aplomado-types` — единый источник истины.

pub use aplomado_types::{
    ScanTarget, HostInfo, PortInfo, TransportProto, PortState, ScanResult, Hop,
    CveSummary,
    extract_version, extract_version_num,
};
