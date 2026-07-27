use std::net::IpAddr;
use std::time::Duration;

use crate::scanner::config::ScanConfig;
use aplomado_types::VersionConfidence;

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ProbeMatch {
    pub service: &'static str,
    pub version: Option<String>,
    pub confidence: VersionConfidence,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    #[error("all probes timed out")]
    AllTimedOut,
    #[error("no matching protocol found")]
    NoMatch,
    #[error("probe failed: {context}")]
    Failed { context: String },
}

pub type ProbeResult = Result<ProbeMatch, ProbeError>;

/// Run the probe chain: try known-service probe first, then fall through
/// priority-ordered protocol probes, bounded by timeouts from `config`.
pub async fn probe_chain(
    ip: IpAddr,
    port: u16,
    config: &ScanConfig,
    _open_ports: &[u16],
) -> ProbeResult {
    let svc = crate::scanner::port::known_service(port);
    let start = std::time::Instant::now();

    if svc != "unknown" {
        let probe_result = try_known_probe(svc, ip, port, config.probe_chain_timeout).await;
        if let Ok(m) = probe_result {
            return Ok(m);
        }
    }

    let deadline = config.probe_chain_max_total;
    let elapsed = start.elapsed();
    if elapsed >= deadline {
        return Err(ProbeError::AllTimedOut);
    }

    let probes: &[(
        &str,
        fn(IpAddr, u16, Duration) -> crate::fingerprint::probes::ProbeFuture,
    )] = &[
        ("tls", crate::fingerprint::probes::tls::probe),
        ("sip", crate::fingerprint::probes::sip::probe),
        ("dns", crate::fingerprint::probes::dns::probe),
        ("smb", crate::fingerprint::probes::smb::probe),
        ("postgresql", crate::fingerprint::probes::postgres::probe),
        ("mongodb", crate::fingerprint::probes::mongodb::probe),
    ];

    for (_name, probe_fn) in probes {
        let remaining = deadline.saturating_sub(start.elapsed());
        if remaining < Duration::from_millis(100) {
            break;
        }
        let timeout = remaining.min(config.probe_chain_timeout);
        match tokio::time::timeout(timeout, probe_fn(ip, port, timeout)).await {
            Ok(Ok(m)) => return Ok(m),
            Ok(Err(_)) => continue,
            Err(_) => continue,
        }
    }

    Err(ProbeError::NoMatch)
}

async fn try_known_probe(
    svc: &str,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> ProbeResult {
    match svc {
        "postgresql" => crate::fingerprint::probes::postgres::probe(ip, port, timeout).await,
        "mongodb" => crate::fingerprint::probes::mongodb::probe(ip, port, timeout).await,
        "https" | "https-alt" => crate::fingerprint::probes::tls::probe(ip, port, timeout).await,
        "smb" => crate::fingerprint::probes::smb::probe(ip, port, timeout).await,
        "dns" => crate::fingerprint::probes::dns::probe(ip, port, timeout).await,
        _ => Err(ProbeError::NoMatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn known_port_matches() {
        let result = probe_chain(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            22,
            &ScanConfig::default(),
            &[22],
        )
        .await;
        // Closed port — should return an error, not panic
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn known_service_probe_lookup() {
        let svc = crate::scanner::port::known_service(5432);
        assert_eq!(svc, "postgresql");
        let svc = crate::scanner::port::known_service(27017);
        assert_eq!(svc, "mongodb");
    }

    #[test]
    fn probe_match_debug_clone() {
        let m = ProbeMatch {
            service: "test",
            version: Some("1.0".into()),
            confidence: VersionConfidence::Exact,
        };
        let _ = format!("{m:?}");
        let _ = m.clone();
    }

    #[test]
    fn probe_error_display() {
        let err = ProbeError::AllTimedOut;
        assert_eq!(format!("{err}"), "all probes timed out");
        let err = ProbeError::NoMatch;
        assert_eq!(format!("{err}"), "no matching protocol found");
        let err = ProbeError::Failed {
            context: "broken".into(),
        };
        assert_eq!(format!("{err}"), "probe failed: broken");
    }
}


