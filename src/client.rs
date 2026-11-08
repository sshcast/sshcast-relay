use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sockcast_proto::crypto::{create_node_auth, sign_sign_request};
use sockcast_proto::ssh::parse_ssh_auth_context;
use sockcast_proto::v1::sockcast_service_client::SockcastServiceClient;
use sockcast_proto::v1::{
    GetIdentitiesRequest, ProcessContext, PublicKey, SignRequest, SignResponse,
};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::config::RelayConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedPublicKeyDisk {
    pub key_blob_b64: String,
    pub comment: String,
    pub fingerprint_sha256: String,
    pub key_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PubkeyDiskCacheFile {
    pub updated_at_unix_sec: u64,
    pub keys: Vec<CachedPublicKeyDisk>,
}

struct MemoryKeyCache {
    keys: Vec<PublicKey>,
    fetched_at: Option<Instant>,
}

pub struct CoordinatorClient {
    cfg: RelayConfig,
    channels: RwLock<Vec<Option<Channel>>>,
    preferred_idx: AtomicUsize,
    key_cache: RwLock<MemoryKeyCache>,
}

impl CoordinatorClient {
    pub fn new(cfg: RelayConfig) -> Self {
        let num_servers = cfg.servers.len();
        let mut init_channels = Vec::with_capacity(num_servers);
        init_channels.resize_with(num_servers, || None);

        let initial_keys = load_disk_pubkey_cache(&cfg.pubkey_cache_path).unwrap_or_default();

        Self {
            cfg,
            channels: RwLock::new(init_channels),
            preferred_idx: AtomicUsize::new(0),
            key_cache: RwLock::new(MemoryKeyCache {
                keys: initial_keys,
                fetched_at: None,
            }),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.cfg.grant.node_id
    }

    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    async fn get_or_connect_channel(&self, idx: usize) -> Result<Channel> {
        {
            let guard = self.channels.read().await;
            if let Some(Some(ch)) = guard.get(idx) {
                return Ok(ch.clone());
            }
        }

        let url = &self.cfg.servers[idx];
        let mut endpoint = Endpoint::from_shared(url.clone())
            .with_context(|| format!("invalid server endpoint URL {url}"))?
            .connect_timeout(Duration::from_millis(self.cfg.connect_timeout_ms))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .http2_keep_alive_interval(Duration::from_secs(25))
            .keep_alive_timeout(Duration::from_secs(10));

        if url.trim().starts_with("https://") {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_enabled_roots())
                .with_context(|| format!("failed to configure TLS roots for {url}"))?;
        }

        let t_conn = Instant::now();
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Failed to connect gRPC channel to {} after {}ms: {}",
                    url,
                    t_conn.elapsed().as_millis(),
                    e
                );
                e
            })
            .with_context(|| format!("failed to connect to coordinator {url}"))?;
        tracing::info!(
            "Connected gRPC channel to {} in {}ms",
            url,
            t_conn.elapsed().as_millis()
        );

        {
            let mut guard = self.channels.write().await;
            if let Some(slot) = guard.get_mut(idx) {
                *slot = Some(channel.clone());
            }
        }

        Ok(channel)
    }

    async fn invalidate_channel(&self, idx: usize) {
        let mut guard = self.channels.write().await;
        if let Some(slot) = guard.get_mut(idx) {
            *slot = None;
        }
    }

    /// Returns cached public keys if within TTL, or queries `GetIdentities` across configured
    /// `sockcast-server` endpoints with automatic failover and disk cache fallback.
    pub async fn get_identities(&self) -> Vec<PublicKey> {
        let ttl = Duration::from_secs(self.cfg.key_cache_ttl_secs);
        if ttl > Duration::ZERO {
            let guard = self.key_cache.read().await;
            if let Some(fetched_at) = guard.fetched_at {
                if fetched_at.elapsed() < ttl && !guard.keys.is_empty() {
                    tracing::info!(
                        "GetIdentities served {} key(s) from memory cache in 0ms",
                        guard.keys.len()
                    );
                    return guard.keys.clone();
                }
            }
        }

        let t_id = Instant::now();
        match self.fetch_identities_remote().await {
            Ok(remote_keys) if !remote_keys.is_empty() => {
                tracing::info!(
                    "GetIdentities fetched {} key(s) from coordinator in {}ms",
                    remote_keys.len(),
                    t_id.elapsed().as_millis()
                );
                {
                    let mut guard = self.key_cache.write().await;
                    guard.keys = remote_keys.clone();
                    guard.fetched_at = Some(Instant::now());
                }
                if let Err(e) = save_disk_pubkey_cache(&self.cfg.pubkey_cache_path, &remote_keys) {
                    tracing::debug!("Failed to persist pubkey disk cache: {}", e);
                }
                remote_keys
            }
            Ok(_empty) => {
                // Server returned 0 keys (e.g. cold coordinator restart while workstation is offline).
                // Fall back to in-memory or disk cache if present.
                let guard = self.key_cache.read().await;
                if !guard.keys.is_empty() {
                    return guard.keys.clone();
                }
                drop(guard);
                load_disk_pubkey_cache(&self.cfg.pubkey_cache_path).unwrap_or_default()
            }
            Err(e) => {
                tracing::warn!("GetIdentities RPC failed across coordinators ({}); using cached keys", e);
                let guard = self.key_cache.read().await;
                if !guard.keys.is_empty() {
                    return guard.keys.clone();
                }
                drop(guard);
                load_disk_pubkey_cache(&self.cfg.pubkey_cache_path).unwrap_or_default()
            }
        }
    }

    async fn fetch_identities_remote(&self) -> Result<Vec<PublicKey>> {
        let num_servers = self.cfg.servers.len();
        let start = self.preferred_idx.load(Ordering::Relaxed) % num_servers;
        let mut last_err = None;

        for offset in 0..num_servers {
            let idx = (start + offset) % num_servers;
            let ch = match self.get_or_connect_channel(idx).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let auth = create_node_auth(
                self.cfg.grant.clone(),
                &self.cfg.node_signing_key,
                Self::now_unix_ms(),
            )?;

            let mut client = SockcastServiceClient::new(ch);
            let mut req = tonic::Request::new(GetIdentitiesRequest { auth: Some(auth) });
            req.set_timeout(Duration::from_millis(self.cfg.connect_timeout_ms.max(3000)));

            match client.get_identities(req).await {
                Ok(resp) => {
                    self.preferred_idx.store(idx, Ordering::Relaxed);
                    let keys = resp.into_inner().keys;
                    // If this coordinator has keys or it's the only server, return immediately.
                    // If it returned 0 keys and there are other coordinators, check if another has keys cached.
                    if !keys.is_empty() || offset + 1 == num_servers {
                        return Ok(keys);
                    }
                }
                Err(status) => {
                    self.invalidate_channel(idx).await;
                    last_err = Some(anyhow::anyhow!(
                        "GetIdentities on {} failed: {}",
                        self.cfg.servers[idx],
                        status
                    ));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no coordinator servers available")))
    }

    /// Packages, cryptographically signs end-to-end with the relay's Ed25519 private key,
    /// and dispatches a `SignRequest` to configured `sockcast-server` endpoints with failover.
    pub async fn sign_challenge(
        &self,
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
        process_context: ProcessContext,
    ) -> Result<SignResponse> {
        let now_ms = Self::now_unix_ms();
        let request_id = generate_request_id();
        let ssh_auth_context = parse_ssh_auth_context(&data);

        let auth = create_node_auth(
            self.cfg.grant.clone(),
            &self.cfg.node_signing_key,
            now_ms,
        )?;

        let mut sign_req = SignRequest {
            request_id,
            timestamp_unix_ms: now_ms,
            key_blob,
            data,
            flags,
            process_context: Some(process_context),
            ssh_auth_context: Some(ssh_auth_context),
            relay_grant: Some(self.cfg.grant.clone()),
            relay_signature: Vec::new(),
            auth: Some(auth),
        };

        sign_sign_request(&mut sign_req, &self.cfg.node_signing_key)
            .context("failed to sign SignRequest with relay Ed25519 key")?;

        let num_servers = self.cfg.servers.len();
        let start = self.preferred_idx.load(Ordering::Relaxed) % num_servers;
        let mut last_err = None;

        for offset in 0..num_servers {
            let idx = (start + offset) % num_servers;
            let ch = match self.get_or_connect_channel(idx).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let mut client = SockcastServiceClient::new(ch);
            let mut rpc_req = tonic::Request::new(sign_req.clone());
            rpc_req.set_timeout(Duration::from_secs(self.cfg.sign_timeout_secs));

            let t_sign = Instant::now();
            tracing::info!(
                "Dispatching SignRequest {} to {}",
                sign_req.request_id,
                self.cfg.servers[idx]
            );
            match client.sign(rpc_req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    tracing::info!(
                        "SignRequest {} returned from {} in {}ms (approved={}, handled_by={})",
                        sign_req.request_id,
                        self.cfg.servers[idx],
                        t_sign.elapsed().as_millis(),
                        inner.approved,
                        inner.handled_by_node_id
                    );
                    if inner.approved {
                        self.preferred_idx.store(idx, Ordering::Relaxed);
                        return Ok(inner);
                    }
                    // If explicitly denied by user or workstation, do NOT re-prompt on another coordinator!
                    if !inner.handled_by_node_id.is_empty()
                        || inner.error_message.contains("denied")
                        || inner.error_message.contains("rejected")
                    {
                        return Ok(inner);
                    }
                    // Otherwise (e.g., no workstation connected to this coordinator), try next server if any.
                    last_err = Some(anyhow::anyhow!(
                        "coordinator {} could not route sign request: {}",
                        self.cfg.servers[idx],
                        inner.error_message
                    ));
                }
                Err(status) => {
                    self.invalidate_channel(idx).await;
                    last_err = Some(anyhow::anyhow!(
                        "Sign RPC on {} failed: {}",
                        self.cfg.servers[idx],
                        status
                    ));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Sign request failed across all servers")))
    }
}

fn generate_request_id() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("req_{}", hex::encode(bytes))
}

pub fn save_disk_pubkey_cache(path: &Path, keys: &[PublicKey]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let entries = keys
        .iter()
        .map(|k| CachedPublicKeyDisk {
            key_blob_b64: STANDARD.encode(&k.key_blob),
            comment: k.comment.clone(),
            fingerprint_sha256: k.fingerprint_sha256.clone(),
            key_type: k.key_type.clone(),
        })
        .collect();
    let file = PubkeyDiskCacheFile {
        updated_at_unix_sec: now_sec,
        keys: entries,
    };
    let json = serde_json::to_vec_pretty(&file)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_disk_pubkey_cache(path: &Path) -> Result<Vec<PublicKey>> {
    let raw = std::fs::read(path)?;
    let file: PubkeyDiskCacheFile = serde_json::from_slice(&raw)?;
    let mut out = Vec::with_capacity(file.keys.len());
    for k in file.keys {
        let blob = STANDARD.decode(k.key_blob_b64.trim())?;
        out.push(PublicKey {
            key_blob: blob,
            comment: k.comment,
            fingerprint_sha256: k.fingerprint_sha256,
            key_type: k.key_type,
        });
    }
    Ok(out)
}
