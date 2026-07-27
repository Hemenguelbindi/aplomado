use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::scanner::sanitize::sanitize_banner;

use super::{ProbeError, ProbeFuture, ProbeMatch};
use aplomado_types::VersionConfidence;

/// Connect to a MongoDB port, send an `isMaster` command via OP_QUERY,
/// and parse the `version` field from the BSON reply.
pub fn probe(ip: IpAddr, port: u16, timeout: Duration) -> ProbeFuture {
    Box::pin(async move {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| ProbeError::Failed {
                context: format!("connect: {e}"),
            })?;

        let mut stream = stream;
        let mut buf = Vec::with_capacity(4096);

        // Build isMaster query document (BSON)
        // { isMaster: 1 }
        let query_doc = bson_build_document(&[("isMaster", bson_int32(1))]);

        // MongoDB OP_QUERY on admin.$cmd
        // Wire protocol header (16 bytes) + OP_QUERY body
        let opcode = 2004i32; // OP_QUERY
        let flags = 0i32;
        let full_collection = b"admin.$cmd\x00";
        let skip = 0i32;
        let ret = -1i32; // unlimited

        let body = [
            &flags.to_bytes_le()[..],
            full_collection,
            &skip.to_bytes_le()[..],
            &ret.to_bytes_le()[..],
            &query_doc,
        ]
        .concat();

        let req_id = 1i32;
        let resp_to = 0i32;

        let msg_len = 16 + body.len() as i32;
        let mut header = Vec::with_capacity(16);
        header.extend_from_slice(&msg_len.to_bytes_le());
        header.extend_from_slice(&req_id.to_bytes_le());
        header.extend_from_slice(&resp_to.to_bytes_le());
        header.extend_from_slice(&opcode.to_bytes_le());

        let packet = [&header[..], &body].concat();

        stream
            .write_all(&packet)
            .await
            .map_err(|e| ProbeError::Failed {
                context: format!("write: {e}"),
            })?;

        // Read response header (16 bytes)
        tokio::time::timeout(timeout, stream.read_exact(&mut buf))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| ProbeError::Failed {
                context: format!("read header: {e}"),
            })?;

        let resp_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if resp_len < 36 || resp_len > 65536 {
            return Err(ProbeError::NoMatch);
        }

        // Read rest of response
        let _remaining = resp_len.saturating_sub(16);
        buf.resize(resp_len, 0);
        tokio::time::timeout(timeout, stream.read_exact(&mut buf[16..]))
            .await
            .map_err(|_| ProbeError::AllTimedOut)?
            .map_err(|e| ProbeError::Failed {
                context: format!("read body: {e}"),
            })?;

        // Parse OP_REPLY: skip header (16) + flags(4) + cursorID(8) + startFrom(4) + numReturned(4) = 36 total
        if resp_len < 36 {
            return Err(ProbeError::NoMatch);
        }
        let doc_offset = 36;

        if doc_offset >= resp_len {
            return Err(ProbeError::NoMatch);
        }

        // Scan BSON document for "version" field
        if let Some(version) = bson_extract_string(&buf[doc_offset..resp_len], "version") {
            if let Some(clean) = sanitize_banner(version.as_bytes(), 128) {
                return Ok(ProbeMatch {
                    service: "mongodb",
                    version: Some(clean),
                    confidence: VersionConfidence::BannerExact,
                });
            }
        }

        Err(ProbeError::NoMatch)
    })
}

// ---------------------------------------------------------------------------
// Minimal BSON helpers (big-endian — BSON uses little-endian ints)
// ---------------------------------------------------------------------------

trait BsonEndian {
    fn to_bytes_le(&self) -> Vec<u8>;
}

impl BsonEndian for i32 {
    fn to_bytes_le(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

fn u32_from_le_bytes(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn bson_int32(v: i32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn bson_build_document(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Placeholder for length
    buf.extend_from_slice(&[0u8; 4]);
    for (name, value) in fields {
        buf.push(0x10); // int32 type
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&value);
    }
    buf.push(0); // terminator
    let len = buf.len() as i32;
    let len_bytes = len.to_le_bytes();
    buf[..4].copy_from_slice(&len_bytes);
    buf
}

/// Extract a UTF-8 string field value from a BSON document by field name.
fn bson_extract_string(doc: &[u8], field_name: &str) -> Option<String> {
    if doc.len() < 5 {
        return None;
    }
    let doc_len = u32_from_le_bytes(&doc[0..4]) as usize;
    if doc_len > doc.len() || doc_len < 5 {
        return None;
    }
    let mut offset = 4; // skip length
    while offset < doc_len - 1 {
        let etype = doc[offset];
        if etype == 0 {
            break; // terminator
        }
        offset += 1;

        // Read cstring (field name)
        let name_start = offset;
        while offset < doc_len && doc[offset] != 0 {
            offset += 1;
        }
        if offset >= doc_len {
            return None;
        }
        let name = &doc[name_start..offset];
        offset += 1; // skip null

        if name == field_name.as_bytes() {
            return match etype {
                0x02 => {
                    // UTF-8 string
                    if offset + 4 > doc_len {
                        return None;
                    }
                    let str_len = u32_from_le_bytes(&doc[offset..offset + 4]) as usize;
                    if str_len == 0 || offset + 4 + str_len > doc_len {
                        return None;
                    }
                    // str_len includes null terminator
                    let str_bytes = &doc[offset + 4..offset + 4 + str_len - 1];
                    String::from_utf8(str_bytes.to_vec()).ok()
                }
                _ => None,
            };
        }

        // Skip value
        match etype {
            0x01 => offset += 8,       // double
            0x02 => {
                // UTF-8 string
                if offset + 4 > doc_len {
                    return None;
                }
                let str_len = u32_from_le_bytes(&doc[offset..offset + 4]) as usize;
                offset += 4 + str_len;
            }
            0x03 | 0x04 => {
                // Embedded document / array
                if offset + 4 > doc_len {
                    return None;
                }
                let sub_len = u32_from_le_bytes(&doc[offset..offset + 4]) as usize;
                offset += sub_len;
            }
            0x05 => offset += 5,       // binary (1+4 bytes prefix)
            0x06 => return None,       // undefined — skip rest
            0x07 => offset += 12,      // ObjectId
            0x08 => offset += 1,       // boolean
            0x09 => offset += 8,       // UTC datetime
            0x0A => {}                 // null value — no bytes
            0x0B => offset += 2,       // regex (two cstrings)
            0x0C => offset += 4,       // DBPointer
            0x0D => offset += 4,       // JavaScript code
            0x0E => {
                // Symbol
                if offset + 4 > doc_len {
                    return None;
                }
                let sym_len = u32_from_le_bytes(&doc[offset..offset + 4]) as usize;
                offset += 4 + sym_len;
            }
            0x0F => {
                // Code with scope
                if offset + 4 > doc_len {
                    return None;
                }
                let cs_len = u32_from_le_bytes(&doc[offset..offset + 4]) as usize;
                offset += cs_len;
            }
            0x10 => offset += 4,       // int32
            0x11 => offset += 8,       // uint64 / timestamp
            0x12 => offset += 8,       // int64
            0x13 => offset += 8,       // decimal128
            _ => return None,
        }

        if offset > doc_len {
            return None;
        }
    }

    None
}
