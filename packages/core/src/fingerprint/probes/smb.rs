use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{ProbeError, ProbeFuture, ProbeMatch};
use aplomado_types::VersionConfidence;

/// Connect to an SMB port, send an SMB2 Negotiate request,
/// and extract the negotiated dialect version.
pub fn probe(ip: IpAddr, port: u16, timeout: Duration) -> ProbeFuture {
    Box::pin(async move {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("connect: {e}")))?;

        let mut stream = stream;

        // Build SMB2 Negotiate packet
        let negotiate = build_smb2_negotiate();

        // NetBIOS session header (4 bytes): length prefix
        let len_prefix = (negotiate.len() as u32).to_be_bytes();
        let packet = [&len_prefix[..], &negotiate].concat();

        stream
            .write_all(&packet)
            .await
            .map_err(|e| super::sanitized_error(format!("write: {e}")))?;

        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| super::sanitized_error(format!("read: {e}")))?;

        if n < 4 {
            return Err(ProbeError::NoMatch);
        }

        // NetBIOS session header + SMB2 header
        let smb_start = 4;
        if n < smb_start + 64 {
            return Err(ProbeError::NoMatch);
        }

        // Check SMB2 magic
        if &buf[smb_start..smb_start + 4] != b"\xfeSMB" {
            return Err(ProbeError::NoMatch);
        }

        // SMB2 header: command (2 bytes at offset 12), status (4 at offset 8),
        // then body starts at offset 64
        let body_offset = smb_start + 64;

        // Negotiate response: structure size (2 bytes), security mode (2),
        // dialect revision (2 bytes)
        if n < body_offset + 2 {
            return Err(ProbeError::NoMatch);
        }

        let dialect = u16::from_le_bytes([
            buf[body_offset],
            buf[body_offset + 1],
        ]);

        let version_str = match dialect {
            0x0202 => "SMB 2.0.2",
            0x0210 => "SMB 2.1",
            0x0300 => "SMB 3.0",
            0x0302 => "SMB 3.0.2",
            0x0311 => "SMB 3.1.1",
            _ => return Err(ProbeError::NoMatch),
        };

        Ok(ProbeMatch {
            service: "smb",
            version: Some(version_str.to_string()),
            confidence: VersionConfidence::BannerExact,
        })
    })
}

/// Build an SMB2 Negotiate request packet (without NetBIOS header).
fn build_smb2_negotiate() -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // SMB2 Protocol ID
    buf.extend_from_slice(b"\xfeSMB");
    // Structure size (2) = 64
    buf.extend_from_slice(&64u16.to_le_bytes());
    // Credit charge (2)
    buf.extend_from_slice(&[0u8; 2]);
    // Status / Channel sequence (4)
    buf.extend_from_slice(&[0u8; 4]);
    // Command (2) = SMB2_NEGOTIATE = 0x0000
    buf.extend_from_slice(&0u16.to_le_bytes());
    // Credits (2) = 1
    buf.extend_from_slice(&1u16.to_le_bytes());
    // Flags (4)
    buf.extend_from_slice(&0u32.to_le_bytes());
    // Next offset (4)
    buf.extend_from_slice(&0u32.to_le_bytes());
    // Message ID (8)
    buf.extend_from_slice(&0u64.to_le_bytes());
    // Process ID (4)
    buf.extend_from_slice(&0x0000_0000u32.to_le_bytes());
    // Tree ID (4)
    buf.extend_from_slice(&0u32.to_le_bytes());
    // Session ID (8)
    buf.extend_from_slice(&0u64.to_le_bytes());
    // Signature (16)
    buf.extend_from_slice(&[0u8; 16]);

    // Negotiate body
    // Structure size (2) = 36
    buf.extend_from_slice(&36u16.to_le_bytes());
    // Dialect count (2) = 4
    buf.extend_from_slice(&4u16.to_le_bytes());
    // Security mode (2) = 0x01 (signing enabled)
    buf.extend_from_slice(&1u16.to_le_bytes());
    // Reserved (2)
    buf.extend_from_slice(&[0u8; 2]);
    // Capabilities (8)
    buf.extend_from_slice(&0u64.to_le_bytes());
    // Client GUID (16)
    buf.extend_from_slice(&[0u8; 16]);
    // Negotiate context offset (8)
    buf.extend_from_slice(&0u64.to_le_bytes());
    // Negotiate context count (4)
    buf.extend_from_slice(&0u32.to_le_bytes());
    // Reserved (2)
    buf.extend_from_slice(&[0u8; 2]);

    // Dialects: SMB 2.0.2, 2.1, 3.0, 3.1.1
    buf.extend_from_slice(&0x0202u16.to_le_bytes());
    buf.extend_from_slice(&0x0210u16.to_le_bytes());
    buf.extend_from_slice(&0x0300u16.to_le_bytes());
    buf.extend_from_slice(&0x0311u16.to_le_bytes());

    buf
}
