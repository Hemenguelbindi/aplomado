//! Banner grabbing — получение версий сервисов по протоколу.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Ensure the rustls ring crypto provider is installed exactly once.
/// Safe to call multiple times — subsequent calls are no-ops.
pub fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Попробовать прочитать баннер с TCP-порта
pub async fn grab_banner(host: &str, port: u16) -> Option<String> {
    match port {
        22 => ssh_banner(host).await,
        80 | 8080 | 8443 => http_banner(host, port).await,
        443 => {
            // Сначала пробуем HTTPS, если не получилось — HTTP (fallback)
            let banner = https_banner(host, port).await;
            if banner.is_some() {
                banner
            } else {
                http_banner(host, port).await
            }
        }
        21 => ftp_banner(host).await,
        25 => smtp_banner(host).await,
        3306 => mysql_banner(host).await,
        6379 => redis_banner(host).await,
        _ => generic_banner(host, port).await,
    }
}

async fn connect(host: &str, port: u16) -> Option<TcpStream> {
    tokio::time::timeout(Duration::from_secs(3), TcpStream::connect((host, port)))
        .await
        .ok()?
        .ok()
}

async fn read_banner(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()
        .and_then(|n| {
            if n > 0 {
                let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                if text.is_empty() { None } else { Some(text) }
            } else {
                None
            }
        })
}

async fn ssh_banner(host: &str) -> Option<String> {
    let mut stream = connect(host, 22).await?;
    read_banner(&mut stream).await
}

async fn http_banner(host: &str, port: u16) -> Option<String> {
    let mut stream = connect(host, port).await?;
    let req = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
    stream.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let resp = String::from_utf8_lossy(&buf[..n]);
    for line in resp.lines() {
        if line.to_lowercase().starts_with("server:") {
            return Some(line.trim().to_string());
        }
    }
    Some(resp.lines().next()?.to_string())
}

async fn https_banner(host: &str, port: u16) -> Option<String> {
    #[cfg(feature = "rustls")]
    {
        use tokio_rustls::TlsConnector;
        use rustls::ClientConfig;

        ensure_crypto_provider();

        // Use standard TLS verification with webpki roots.
        // Security scanners have a tension: we want to read banners from
        // arbitrary hosts (incl. self-signed / internal). The pragmatic
        // approach: try strict verification first; if it fails the caller
        // falls back to HTTP banner grabbing (see `grab_banner` port 443).
        //
        // `webpki-roots` bundles Mozilla's CA list so standard CA-signed
        // certs verify correctly.
        let mut config = ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.into(),
            })
            .with_no_client_auth();

        config.alpn_protocols = vec![b"http/1.1".into()];

        let connector = TlsConnector::from(Arc::new(config));

        let tcp = connect(host, port).await?;
        let domain = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
        let mut stream = connector.connect(domain, tcp).await.ok()?;

        let req = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
        stream.write_all(req.as_bytes()).await.ok()?;

        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        let resp = String::from_utf8_lossy(&buf[..n]);
        for line in resp.lines() {
            if line.to_lowercase().starts_with("server:") {
                return Some(line.trim().to_string());
            }
        }
        Some(resp.lines().next()?.to_string())
    }

    #[cfg(not(feature = "rustls"))]
    {
        let _ = (host, port);
        None
    }
}

async fn ftp_banner(host: &str) -> Option<String> {
    let mut stream = connect(host, 21).await?;
    read_banner(&mut stream).await
}

async fn smtp_banner(host: &str) -> Option<String> {
    let mut stream = connect(host, 25).await?;
    read_banner(&mut stream).await
}

async fn mysql_banner(host: &str) -> Option<String> {
    let mut stream = connect(host, 3306).await?;
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n > 5 {
        let version_end = buf[5..].iter().position(|&b| b == 0).unwrap_or(n - 5);
        let version = String::from_utf8_lossy(&buf[5..5 + version_end]);
        Some(format!("MySQL {}", version))
    } else {
        None
    }
}

async fn redis_banner(host: &str) -> Option<String> {
    let mut stream = connect(host, 6379).await?;
    stream.write_all(b"PING\r\n").await.ok()?;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

async fn generic_banner(host: &str, port: u16) -> Option<String> {
    let mut stream = connect(host, port).await?;
    read_banner(&mut stream).await
}

// SkipVerifier removed — now using standard `webpki_roots` TLS verification.
