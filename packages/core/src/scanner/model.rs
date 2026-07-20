//! Модели данных для сканера.
//!
//! Все типы перенесены в `peregrine-types` — единый источник истины.

pub use peregrine_types::{
    ScanTarget, HostInfo, PortInfo, TransportProto, PortState, ScanResult, Hop,
    CveSummary,
    extract_version, extract_version_num,
};
