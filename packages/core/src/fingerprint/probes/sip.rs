use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::scanner::sanitize::sanitize_banner;

use super::{ProbeError, ProbeFuture, ProbeMatch};
use aplomado_types::VersionConfidence;

/// Connect to a SIP port, send an OPTIONS request, and extract the Server header.
pub fn probe(ip: IpAddr, port: u16, timeout: Duration) -> ProbeFuture {
    Box::pin(async move {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("connect: {e}")))?;

        let mut stream = stream;
        let call_id = format!("aplomado-{}", std::process::id());

        let options = format!(
            "OPTIONS sip:ping@{} SIP/2.0\r\n\
             Via: SIP/2.0/TCP 127.0.0.1:5060\r\n\
             From: <sip:probe@aplomado>\r\n\
             To: <sip:ping@{}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\
             \r\n",
            ip, ip,
        );

        stream
            .write_all(options.as_bytes())
            .await
            .map_err(|e| super::sanitized_error(format!("write: {e}")))?;

        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("read: {e}")))?;

        if n == 0 {
            return Err(ProbeError::NoMatch);
        }

        let resp = String::from_utf8_lossy(&buf[..n]);
        for line in resp.lines() {
            if line.to_lowercase().starts_with("server:") {
                let val = line["server:".len()..].trim();
                if let Some(clean) = sanitize_banner(val.as_bytes(), 256) {
                    return Ok(ProbeMatch {
                        service: "sip",
                        version: Some(clean),
                        confidence: VersionConfidence::BannerExact,
                    });
                }
                break;
            }
        }

        Err(ProbeError::NoMatch)
    })
}
