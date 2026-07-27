use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::scanner::sanitize::sanitize_banner;

use super::{ProbeError, ProbeFuture, ProbeMatch};
use aplomado_types::VersionConfidence;

/// Connect to a DNS port (TCP), send a `version.bind CHAOS TXT` query,
/// and parse the response text.
pub fn probe(ip: IpAddr, port: u16, timeout: Duration) -> ProbeFuture {
    Box::pin(async move {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("connect: {e}")))?;

        let mut stream = stream;

        // Build DNS query: version.bind CHAOS TXT
        let query = build_dns_query();
        let len_prefix = (query.len() as u16).to_be_bytes();
        let packet = [&len_prefix[..], &query].concat();

        stream
            .write_all(&packet)
            .await
            .map_err(|e| super::sanitized_error(format!("write: {e}")))?;

        // Read DNS response (TCP: 2-byte length prefix + message)
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("read len: {e}")))?;

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len < 12 || msg_len > 4096 {
            return Err(ProbeError::NoMatch);
        }

        let mut msg = vec![0u8; msg_len];
        tokio::time::timeout(timeout, stream.read_exact(&mut msg))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("read msg: {e}")))?;

        // Parse response: extract answer TXT record
        if let Some(txt) = parse_dns_response(&msg) {
            if let Some(clean) = sanitize_banner(txt.as_bytes(), 256) {
                return Ok(ProbeMatch {
                    service: "dns",
                    version: Some(clean),
                    confidence: VersionConfidence::BannerExact,
                });
            }
        }

        Err(ProbeError::NoMatch)
    })
}

/// Build a DNS query for `version.bind CHAOS TXT`.
fn build_dns_query() -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // Header
    let id: u16 = 0xAAAA; // transaction ID
    let flags: u16 = 0x0100; // standard query, recursion desired
    let qdcount: u16 = 1u16;
    let ancount: u16 = 0u16;
    let nscount: u16 = 0u16;
    let arcount: u16 = 0u16;

    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&qdcount.to_be_bytes());
    buf.extend_from_slice(&ancount.to_be_bytes());
    buf.extend_from_slice(&nscount.to_be_bytes());
    buf.extend_from_slice(&arcount.to_be_bytes());

    // Question: QNAME = "version.bind" (encoded as 7version4bind0)
    buf.push(7); // length of "version"
    buf.extend_from_slice(b"version");
    buf.push(4); // length of "bind"
    buf.extend_from_slice(b"bind");
    buf.push(0); // end of QNAME

    // QTYPE = TXT (16)
    buf.extend_from_slice(&16u16.to_be_bytes());
    // QCLASS = CHAOS (3)
    buf.extend_from_slice(&3u16.to_be_bytes());

    buf
}

/// Parse a DNS response and extract the first TXT record text.
fn parse_dns_response(msg: &[u8]) -> Option<String> {
    if msg.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);

    if qdcount == 0 || ancount == 0 {
        return None;
    }

    // Skip header (12) + question section
    let mut offset: usize = 12;

    // Parse questions to find end of question section
    for _ in 0..qdcount {
        // Skip QNAME (sequence of length-prefixed labels ending with 0)
        offset = skip_dns_name(msg, offset)?;
        if offset + 4 > msg.len() {
            return None;
        }
        offset += 4; // QTYPE (2) + QCLASS (2)
    }

    // Parse answers
    for _ in 0..ancount {
        offset = skip_dns_name(msg, offset)?;
        if offset + 10 > msg.len() {
            return None;
        }
        let _qtype = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
        let _qclass = u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]);
        let _ttl = u32::from_be_bytes([msg[offset + 4], msg[offset + 5], msg[offset + 6], msg[offset + 7]]);
        let rdlength = u16::from_be_bytes([msg[offset + 8], msg[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > msg.len() {
            return None;
        }

        // TXT record: one or more <length><text> sequences
        let rdata = &msg[offset..offset + rdlength];
        if !rdata.is_empty() {
            let txt_len = rdata[0] as usize;
            if txt_len > 0 && 1 + txt_len <= rdata.len() {
                let txt = &rdata[1..1 + txt_len];
                return Some(String::from_utf8_lossy(txt).to_string());
            }
        }

        offset += rdlength;
    }

    None
}

/// Skip a DNS name (sequence of labels or pointer).
fn skip_dns_name(msg: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= msg.len() {
            return None;
        }
        let byte = msg[offset];
        if byte == 0 {
            return Some(offset + 1);
        }
        // Check for compression pointer (top 2 bits = 11)
        if byte & 0xC0 == 0xC0 {
            return Some(offset + 2);
        }
        // Regular label
        let len = byte as usize;
        offset += 1 + len;
        if offset > msg.len() {
            return None;
        }
    }
}
