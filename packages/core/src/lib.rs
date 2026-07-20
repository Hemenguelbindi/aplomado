//! Aplomado Core — чистая бизнес-логика сканера уязвимостей.
//! Не зависит от Dioxus, может использоваться из CLI, GUI, агентов.

pub mod scanner;

pub mod history;
pub mod export;

#[cfg(feature = "scanner")]
pub mod traceroute;

#[cfg(feature = "fingerprint")]
pub mod fingerprint;

#[cfg(feature = "database")]
pub mod database;

pub mod cve;
