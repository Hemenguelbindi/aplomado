use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::scanner::sanitize::sanitize_banner;

use super::{ProbeError, ProbeFuture, ProbeMatch};
use aplomado_types::VersionConfidence;

/// Connect to a PostgreSQL port, send a startup packet with an invalid user,
/// and extract version information from the server's error response.
pub fn probe(ip: IpAddr, port: u16, timeout: Duration) -> ProbeFuture {
    Box::pin(async move {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("connect: {e}")))?;

        // Build PostgreSQL startup packet (protocol 3.0) with dummy user
        let user = b"aplomado_probe\x00";
        let database = b"aplomado\x00";
        let params = [b"user\x00" as &[u8], user, b"database\x00", database, b"\x00"].concat();
        let len = 4 + 4 + params.len() as i32; // length self + protocol + params
        let mut startup = Vec::with_capacity(len as usize);
        startup.extend_from_slice(&len.to_be_bytes());
        startup.extend_from_slice(&196608i32.to_be_bytes()); // protocol 3.0
        startup.extend_from_slice(&params);

        let mut stream = stream;
        stream
            .write_all(&startup)
            .await
            .map_err(|e| super::sanitized_error(format!("write: {e}")))?;

        // Read response
        loop {
            let mut header = [0u8; 5];
            let n = tokio::time::timeout(timeout, stream.read(&mut header))
                .await
                .map_err(|_| ProbeError::AllTimedOut)?
                .map_err(|e| super::sanitized_error(format!("read: {e}")))?;
            if n < 5 {
                break;
            }

            let msg_type = header[0];
            let msg_len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            let msg_len = msg_len.saturating_sub(4).min(4096);
            let mut payload = vec![0u8; msg_len];
            let _ = stream.read_exact(&mut payload).await;

            match msg_type {
                b'R' => {
                    // AuthenticationRequest — we don't authenticate, move on
                    // Extract auth type for context
                    if payload.len() >= 4 {
                        let _auth_type = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    }
                    // Send terminate to be polite
                    let term = [0i32.to_be_bytes(), 0i32.to_be_bytes()].concat();
                    let _ = stream.write_all(&term).await;
                    return Err(ProbeError::NoMatch);
                }
                b'E' => {
                    // ErrorResponse — extract message field
                    let msg = extract_pg_error(&payload);
                    if let Some(ref m) = msg {
                        if let Some(clean) = sanitize_banner(m.as_bytes(), 512) {
                            return Ok(ProbeMatch {
                                service: "postgresql",
                                version: Some(clean),
                                confidence: VersionConfidence::BannerRegex,
                            });
                        }
                    }
                    return Err(ProbeError::NoMatch);
                }
                b'N' => {
                    // NoticeResponse — similar to ErrorResponse
                    let msg = extract_pg_error(&payload);
                    if let Some(ref m) = msg {
                        if let Some(clean) = sanitize_banner(m.as_bytes(), 512) {
                            return Ok(ProbeMatch {
                                service: "postgresql",
                                version: Some(clean),
                                confidence: VersionConfidence::BannerRegex,
                            });
                        }
                    }
                    continue;
                }
                _ => {
                    // Unknown message type — continue reading or break
                    break;
                }
            }
        }

        Err(ProbeError::NoMatch)
    })
}

/// Extract the Message field ('M') from a PostgreSQL ErrorResponse/NoticeResponse payload.
fn extract_pg_error(payload: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < payload.len() {
        let field_type = payload[i];
        i += 1;
        if field_type == 0 {
            break;
        }
        // Find null terminator
        let start = i;
        while i < payload.len() && payload[i] != 0 {
            i += 1;
        }
        let value = &payload[start..i];
        if field_type == b'M' {
            return Some(String::from_utf8_lossy(value).to_string());
        }
        if i < payload.len() {
            i += 1; // skip null
        }
    }
    None
}
