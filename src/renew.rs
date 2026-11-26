use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use prost::Message;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use sshcast_proto::bundle::decode_user_cert_token;
use sshcast_proto::crypto::{create_node_auth, verify_user_cert};
use sshcast_proto::v1::{NodeGrant, UserCert};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const RENEW_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize)]
struct RenewCertRequest {
    node_auth_proto_b64: String,
}

#[derive(Deserialize)]
struct RenewCertResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    cert_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Returns `true` if `cert` is an expiring `UserCert` that has expired or reached its renewal window.
///
/// Self-hosted allowlist mode (`None`) and non-expiring certs (`expires_at_unix_sec == 0`) never
/// trigger proactive renewal.
pub fn cert_needs_renewal(cert: Option<&UserCert>, now_sec: u64) -> bool {
    let Some(c) = cert else {
        return false;
    };
    if c.expires_at_unix_sec == 0 {
        return false;
    }
    if now_sec >= c.expires_at_unix_sec {
        return true;
    }
    let remaining = c.expires_at_unix_sec - now_sec;
    let total_ttl = c.expires_at_unix_sec.saturating_sub(c.issued_at_unix_sec);
    let half = total_ttl / 2;
    let threshold = if total_ttl >= 7200 {
        half.max(3600)
    } else {
        half
    };
    remaining <= threshold
}

fn build_tls_client_config() -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    if !native.certs.is_empty() {
        roots.add_parsable_certificates(native.certs);
    }
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("failed to configure TLS protocol versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

async fn send_http1_post<IO>(
    io: IO,
    req: http::Request<Full<Bytes>>,
) -> Result<(http::StatusCode, Bytes)>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .context("HTTP/1.1 handshake failed")?;
    let conn_task = tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("operator HTTP connection closed: {}", e);
        }
    });
    let resp = sender
        .send_request(req)
        .await
        .context("failed to send renewal HTTP POST request")?;
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .context("failed to read renewal HTTP response body")?
        .to_bytes();
    drop(sender);
    conn_task.abort();
    Ok((status, body))
}

/// Calls `POST <operator_url>/api/v1/renew` with a fresh `NodeAuth` (with `grant.user_cert = None`
/// so dormant relays with an expired `UserCert` can still renew) and returns the verified `UserCert`.
pub async fn renew_user_cert_http(
    operator_url: &str,
    grant: &NodeGrant,
    node_signing_key: &SigningKey,
) -> Result<UserCert> {
    // Strip user_cert before calling create_node_auth so verify_node_grant on the operator
    // does not reject an expired UserCert during dormant renewal.
    let mut stripped_grant = grant.clone();
    stripped_grant.user_cert = None;

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let auth = create_node_auth(stripped_grant, node_signing_key, now_ms)
        .context("failed to sign NodeAuth for cert renewal")?;
    let mut auth_bytes = Vec::new();
    auth.encode(&mut auth_bytes)
        .context("failed to encode NodeAuth protobuf")?;
    let payload = RenewCertRequest {
        node_auth_proto_b64: URL_SAFE_NO_PAD.encode(auth_bytes),
    };
    let req_body = serde_json::to_vec(&payload).context("failed to serialize renewal JSON")?;

    let base_trimmed = operator_url.trim().trim_end_matches('/');
    let uri: http::Uri = base_trimmed
        .parse()
        .with_context(|| format!("invalid operator_url {operator_url:?}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow::anyhow!("operator_url {operator_url:?} missing scheme"))?;
    let use_tls = match scheme {
        "https" => true,
        "http" => false,
        other => anyhow::bail!("unsupported operator_url scheme {other:?}"),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("operator_url {operator_url:?} missing host"))?;
    let raw_host = authority.host();
    let connect_host = raw_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if connect_host.is_empty() {
        anyhow::bail!("operator_url {operator_url:?} has empty host");
    }
    let port = authority.port_u16().unwrap_or(if use_tls { 443 } else { 80 });
    let host_header = authority.as_str().to_string();
    let base_path = uri.path().trim_end_matches('/');
    let request_path = if base_path.is_empty() || base_path == "/" {
        "/api/v1/renew".to_string()
    } else {
        format!("{base_path}/api/v1/renew")
    };

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(&request_path)
        .header(http::header::HOST, &host_header)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::ACCEPT, "application/json")
        .header(http::header::CONNECTION, "close")
        .body(Full::new(Bytes::from(req_body)))
        .context("failed to build renewal HTTP request")?;

    let (status, resp_body) = tokio::time::timeout(RENEW_TIMEOUT, async move {
        let tcp = TcpStream::connect((connect_host.as_str(), port))
            .await
            .with_context(|| format!("failed to connect to operator {connect_host}:{port}"))?;
        if use_tls {
            let tls_cfg = build_tls_client_config()?;
            let server_name = ServerName::try_from(connect_host.clone())
                .with_context(|| format!("invalid TLS server name {connect_host:?}"))?;
            let tls_stream = TlsConnector::from(tls_cfg)
                .connect(server_name, tcp)
                .await
                .with_context(|| format!("TLS handshake failed with operator {connect_host}:{port}"))?;
            send_http1_post(tls_stream, req).await
        } else {
            send_http1_post(tcp, req).await
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("operator cert renewal timed out after {:?}", RENEW_TIMEOUT))??;

    let parsed: Option<RenewCertResponse> = serde_json::from_slice(&resp_body).ok();
    if !status.is_success() {
        let err_detail = parsed
            .and_then(|p| p.error)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                let preview = String::from_utf8_lossy(&resp_body);
                if preview.trim().is_empty() {
                    status.to_string()
                } else {
                    format!("{status}: {}", preview.trim())
                }
            });
        anyhow::bail!("operator cert renewal failed: {err_detail}");
    }

    let parsed = parsed.with_context(|| {
        format!(
            "invalid JSON from operator /api/v1/renew: {}",
            String::from_utf8_lossy(&resp_body)
        )
    })?;
    if !parsed.ok {
        let err_detail = parsed
            .error
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown operator error".to_string());
        anyhow::bail!("operator cert renewal rejected: {err_detail}");
    }

    let cert_token = parsed
        .cert_token
        .filter(|t| !t.trim().is_empty())
        .context("operator /api/v1/renew returned ok=true without cert_token")?;
    let cert = decode_user_cert_token(&cert_token)
        .context("failed to decode renewed UserCert token")?;
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    verify_user_cert(&cert, &grant.user_pubkey, now_sec)
        .context("renewed UserCert failed cryptographic verification")?;

    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(issued_at: u64, expires_at: u64) -> UserCert {
        UserCert {
            user_id: "sc_u_test".to_string(),
            user_pubkey: vec![0x11; 32],
            operator_pubkey: vec![0x22; 32],
            issued_at_unix_sec: issued_at,
            expires_at_unix_sec: expires_at,
            operator_signature: vec![0x33; 64],
        }
    }

    #[test]
    fn test_cert_needs_renewal_cases() {
        let now = 1_750_000_000u64;

        // None (self-hosted allowlist mode)
        assert!(!cert_needs_renewal(None, now));

        // Non-expiring cert (expires_at == 0)
        let non_expiring = make_cert(now - 1000, 0);
        assert!(!cert_needs_renewal(Some(&non_expiring), now));

        // Fresh 7-day cert (issued 100s ago, 604700s remaining > 302400s)
        let seven_days = 7 * 86400;
        let fresh_7d = make_cert(now - 100, now - 100 + seven_days);
        assert!(!cert_needs_renewal(Some(&fresh_7d), now));

        // Past 50% TTL on 7-day cert (exactly 3.5 days left -> renew)
        let half_7d = make_cert(now - seven_days / 2, now + seven_days / 2);
        assert!(cert_needs_renewal(Some(&half_7d), now));

        // Short test cert (60s TTL): 40s left -> fresh, 30s left -> renew
        let short_fresh = make_cert(now - 20, now + 40);
        assert!(!cert_needs_renewal(Some(&short_fresh), now));
        let short_due = make_cert(now - 30, now + 30);
        assert!(cert_needs_renewal(Some(&short_due), now));

        // Already expired or at expiration
        let at_expiry = make_cert(now - 600, now);
        assert!(cert_needs_renewal(Some(&at_expiry), now));
        let expired = make_cert(now - 700, now - 10);
        assert!(cert_needs_renewal(Some(&expired), now));
    }

    #[test]
    fn test_build_tls_client_config_offline() {
        build_tls_client_config().expect("TLS client config with ring + roots should build");
    }
}
