use anyhow::{Context, Result};
use sockcast_proto::v1::{ProcessContext, PublicKey};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::client::CoordinatorClient;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH2_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH2_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
pub const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH2_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
pub const SSH_AGENTC_EXTENSION: u8 = 27;

/// Maximum allowed SSH agent frame length (1 MiB) to prevent memory exhaustion.
pub const MAX_AGENT_FRAME_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignRequest {
    pub key_blob: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u32,
}

/// Handles a single SSH agent session over an async stream (e.g. `UnixStream`) until EOF.
pub async fn handle_agent_session<S>(
    mut stream: S,
    coord: Arc<CoordinatorClient>,
    process_context: ProcessContext,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let Some(frame) = read_agent_frame(&mut stream).await? else {
            return Ok(());
        };
        let reply = process_agent_frame(&frame, &coord, &process_context).await;
        write_agent_frame(&mut stream, &reply).await?;
    }
}

/// Processes a single SSH agent request payload and returns the response payload (excluding the 4-byte length prefix).
pub async fn process_agent_frame(
    frame: &[u8],
    coord: &Arc<CoordinatorClient>,
    process_context: &ProcessContext,
) -> Vec<u8> {
    let Some((&msg_type, body)) = frame.split_first() else {
        return vec![SSH_AGENT_FAILURE];
    };

    match msg_type {
        SSH2_AGENTC_REQUEST_IDENTITIES => {
            let keys = coord.get_identities().await;
            encode_identities_answer(&keys)
        }
        SSH2_AGENTC_SIGN_REQUEST => {
            let Some(req) = parse_agent_sign_request(body) else {
                tracing::warn!("Malformed SSH2_AGENTC_SIGN_REQUEST from pid={}", process_context.pid);
                return vec![SSH_AGENT_FAILURE];
            };

            match coord
                .sign_challenge(req.key_blob, req.data, req.flags, process_context.clone())
                .await
            {
                Ok(resp) if resp.approved && !resp.signature_blob.is_empty() => {
                    encode_sign_response(&resp.signature_blob)
                }
                Ok(resp) => {
                    tracing::info!(
                        "Sign request denied or empty (pid={}, comm={}, reason={})",
                        process_context.pid,
                        process_context.comm,
                        resp.error_message
                    );
                    vec![SSH_AGENT_FAILURE]
                }
                Err(e) => {
                    tracing::warn!(
                        "Sign request failed (pid={}, comm={}): {}",
                        process_context.pid,
                        process_context.comm,
                        e
                    );
                    vec![SSH_AGENT_FAILURE]
                }
            }
        }
        // Hardening: explicitly reject all mutating and unsupported operations with SSH_AGENT_FAILURE
        SSH2_AGENTC_ADD_IDENTITY
        | SSH2_AGENTC_REMOVE_IDENTITY
        | SSH2_AGENTC_REMOVE_ALL_IDENTITIES
        | SSH_AGENTC_ADD_SMARTCARD_KEY
        | SSH_AGENTC_REMOVE_SMARTCARD_KEY
        | SSH_AGENTC_LOCK
        | SSH_AGENTC_UNLOCK
        | SSH2_AGENTC_ADD_ID_CONSTRAINED
        | SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED
        | SSH_AGENTC_EXTENSION
        | _ => vec![SSH_AGENT_FAILURE],
    }
}

pub async fn read_agent_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("failed to read SSH agent frame length"),
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_AGENT_FRAME_LEN {
        anyhow::bail!("invalid SSH agent frame length: {len}");
    }

    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .context("failed to read SSH agent frame body")?;
    Ok(Some(buf))
}

pub async fn write_agent_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub fn encode_identities_answer(keys: &[PublicKey]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + keys.len() * 128);
    out.push(SSH2_AGENT_IDENTITIES_ANSWER);
    out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for k in keys {
        write_ssh_string(&mut out, &k.key_blob);
        write_ssh_string(&mut out, k.comment.as_bytes());
    }
    out
}

pub fn encode_sign_response(signature_blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + signature_blob.len());
    out.push(SSH2_AGENT_SIGN_RESPONSE);
    write_ssh_string(&mut out, signature_blob);
    out
}

pub fn parse_agent_sign_request(body: &[u8]) -> Option<ParsedSignRequest> {
    let mut cursor = body;
    let key_blob = read_ssh_string(&mut cursor)?.to_vec();
    let data = read_ssh_string(&mut cursor)?.to_vec();
    let flags = if cursor.len() >= 4 {
        u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]])
    } else {
        0
    };
    Some(ParsedSignRequest {
        key_blob,
        data,
        flags,
    })
}

fn write_ssh_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn read_ssh_string<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    if cursor.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
    *cursor = &cursor[4..];
    if cursor.len() < len {
        return None;
    }
    let slice = &cursor[..len];
    *cursor = &cursor[len..];
    Some(slice)
}
