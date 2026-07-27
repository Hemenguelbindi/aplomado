pub mod dns;
pub mod mongodb;
pub mod postgres;
pub mod sip;
pub mod smb;
pub mod tls;

use std::future::Future;
use std::pin::Pin;

use crate::scanner::sanitize::sanitize_error_context;

use super::{ProbeError, ProbeMatch};

pub type ProbeFuture = Pin<Box<dyn Future<Output = Result<ProbeMatch, ProbeError>> + Send>>;

/// Construct a sanitized `ProbeError::Failed` from a raw error message.
pub fn sanitized_error(msg: impl Into<String>) -> ProbeError {
    let raw = msg.into();
    let clean = sanitize_error_context(raw.as_bytes());
    ProbeError::Failed { context: clean }
}
