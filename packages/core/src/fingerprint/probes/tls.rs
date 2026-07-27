use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::scanner::sanitize::sanitize_cert_field;

use super::{ProbeError, ProbeFuture, ProbeMatch};
use aplomado_types::VersionConfidence;

/// Connect and perform a TLS handshake with SNI. Extract the Common Name
/// and Subject Alternative Names from the server's leaf certificate.
pub fn probe(ip: IpAddr, port: u16, timeout: Duration) -> ProbeFuture {
    Box::pin(async move {
        crate::fingerprint::banner::ensure_crypto_provider();

        let tcp = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("connect: {e}")))?;

        let server_name = ip.to_string();
        let domain = rustls::pki_types::ServerName::try_from(server_name.clone())
            .map_err(|_| super::sanitized_error("invalid server name"))?;

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.into(),
            })
            .with_no_client_auth();

        // Disable ALPN so we can probe any TLS service
        config.alpn_protocols.clear();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let stream = tokio::time::timeout(timeout, connector.connect(domain, tcp))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("tls handshake: {e}")))?;

        // Extract peer certificate(s)
        let (_, session) = stream.get_ref();
        let certs = session.peer_certificates().ok_or(ProbeError::NoMatch)?;
        let leaf = certs.first().ok_or(ProbeError::NoMatch)?;

        // Parse the certificate and extract CN + SANs
        let cert = x509_parser::parse_x509_certificate(leaf.as_ref())
            .map_err(|_| super::sanitized_error("cert parse failed"))?;

        let (_, parsed) = cert;

        // Subject Common Name
        let cn = parsed
            .tbs_certificate
            .subject
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .and_then(|s| sanitize_cert_field(s.as_bytes()))
            .unwrap_or_default();

        // Subject Alternative Names
        use x509_parser::extensions::GeneralName;
        let sans = parsed
            .tbs_certificate
            .extensions()
            .iter()
            .map(|ext| ext.parsed_extension().clone())
            .filter_map(|ext| match ext {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                    Some(san.general_names)
                }
                _ => None,
            })
            .flatten()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(name) => Some(name.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();

        let mut version = cn;
        if !sans.is_empty() {
            if !version.is_empty() {
                version.push_str("; ");
            }
            version.push_str(&sans.join(", "));
        }

        if version.is_empty() {
            return Err(ProbeError::NoMatch);
        }

        Ok(ProbeMatch {
            service: "tls",
            version: Some(version),
            confidence: VersionConfidence::BannerExact,
        })
    })
}
