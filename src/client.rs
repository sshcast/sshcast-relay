use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sshcast_proto::crypto::{create_node_auth, sign_sign_request};
use sshcast_proto::ssh::parse_ssh_auth_context;
use sshcast_proto::v1::sshcast_service_client::SshcastServiceClient;
use sshcast_proto::v1::{
    GetIdentitiesRequest, GetIdentitiesResponse, NodeGrant, ProcessContext, PublicKey,
    SshAuthContext, SignRequest, SignResponse,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::config::RelayConfig;
use crate::renew::{cert_needs_renewal, renew_user_cert_http};

const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

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

struct ResolvedServersCache {
    urls: Vec<String>,
    resolved_at: Option<Instant>,
}

pub struct CoordinatorClient {
    cfg: RelayConfig,
    grant: RwLock<NodeGrant>,
    renew_lock: Mutex<()>,
    resolved_operator_url: RwLock<Option<String>>,
    has_dns_discovery: bool,
    resolved_servers: RwLock<ResolvedServersCache>,
    channels: RwLock<HashMap<String, Channel>>,
    connect_lock: Mutex<()>,
    preferred_idx: AtomicUsize,
    key_cache: RwLock<MemoryKeyCache>,
    refresh_in_flight: AtomicBool,
}

impl CoordinatorClient {
    pub fn new(cfg: RelayConfig) -> Self {
        let has_dns_discovery = cfg
            .servers
            .iter()
            .any(|s| sshcast_proto::dns::is_dns_discovery_entry(s).is_some());
        let initial_urls = if has_dns_discovery {
            Vec::new()
        } else {
            cfg.servers
                .iter()
                .filter_map(|s| sshcast_proto::dns::normalize_coordinator_url(s))
                .collect()
        };

        let initial_keys = load_disk_pubkey_cache(&cfg.pubkey_cache_path).unwrap_or_default();
        let initial_grant = cfg.grant.clone();
        let initial_operator_url = cfg
            .operator_url
            .as_deref()
            .and_then(sshcast_proto::dns::normalize_coordinator_url);

        Self {
            cfg,
            grant: RwLock::new(initial_grant),
            renew_lock: Mutex::new(()),
            resolved_operator_url: RwLock::new(initial_operator_url),
            has_dns_discovery,
            resolved_servers: RwLock::new(ResolvedServersCache {
                urls: initial_urls,
                resolved_at: None,
            }),
            channels: RwLock::new(HashMap::new()),
            connect_lock: Mutex::new(()),
            preferred_idx: AtomicUsize::new(0),
            key_cache: RwLock::new(MemoryKeyCache {
                keys: initial_keys,
                fetched_at: None,
            }),
            refresh_in_flight: AtomicBool::new(false),
        }
    }

    pub fn config(&self) -> &RelayConfig {
        &self.cfg
    }

    pub fn node_id(&self) -> &str {
        &self.cfg.grant.node_id
    }

    pub async fn current_grant(&self) -> NodeGrant {
        self.grant.read().await.clone()
    }

    pub async fn update_operator_url(&self, op_url: String) {
        let mut op_guard = self.resolved_operator_url.write().await;
        if op_guard.as_ref() != Some(&op_url) {
            tracing::info!("Resolved operator URL via _sshcast DNS TXT: {}", op_url);
            *op_guard = Some(op_url);
        }
    }

    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn now_unix_sec() -> u64 {
        Self::now_unix_ms() / 1000
    }

    async fn resolve_operator_url(&self) -> Option<String> {
        if let Some(url) = self.resolved_operator_url.read().await.clone() {
            return Some(url);
        }
        if !self.has_dns_discovery {
            return None;
        }
        let configured = self.cfg.servers.clone();
        let discovery = tokio::task::spawn_blocking(move || {
            sshcast_proto::dns::resolve_swarm_discovery(&configured)
        })
        .await
        .unwrap_or_default();
        if let Some(op_url) = discovery.operator_url {
            self.update_operator_url(op_url.clone()).await;
            return Some(op_url);
        }
        None
    }

    /// Renews the embedded `UserCert` from the operator API if needed (or if `force` is `true`).
    /// Returns `true` if `self.grant` now holds a freshly renewed (or concurrently renewed) `UserCert`.
    pub async fn maybe_renew_cert(&self, force: bool) -> bool {
        let now_sec = Self::now_unix_sec();
        let prev_cert = {
            let guard = self.grant.read().await;
            if !force && !cert_needs_renewal(guard.user_cert.as_ref(), now_sec) {
                return false;
            }
            guard.user_cert.clone()
        };

        let _renew_guard = self.renew_lock.lock().await;
        let now_sec = Self::now_unix_sec();
        let grant_snapshot = {
            let guard = self.grant.read().await;
            if !force && !cert_needs_renewal(guard.user_cert.as_ref(), now_sec) {
                return false;
            }
            if force
                && guard.user_cert != prev_cert
                && guard.user_cert.is_some()
                && !cert_needs_renewal(guard.user_cert.as_ref(), now_sec)
            {
                return true;
            }
            guard.clone()
        };

        let Some(op_url) = self.resolve_operator_url().await else {
            tracing::debug!("Skipping UserCert renewal: no operator_url configured or discovered");
            return false;
        };

        match renew_user_cert_http(&op_url, &grant_snapshot, &self.cfg.node_signing_key).await {
            Ok(new_cert) => {
                {
                    let mut guard = self.grant.write().await;
                    guard.user_cert = Some(new_cert.clone());
                }
                if let Some(cfg_path) = self.cfg.config_path.clone() {
                    let cert_to_save = new_cert.clone();
                    match tokio::task::spawn_blocking(move || {
                        RelayConfig::persist_user_cert(&cfg_path, &cert_to_save)
                    })
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            tracing::warn!(
                                "Renewed UserCert in memory, but failed to persist to relay.toml: {}",
                                e
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Renewed UserCert in memory, but persistence task panicked: {}",
                                e
                            );
                        }
                    }
                }
                tracing::info!(
                    "Renewed UserCert from operator {} (expires_at={})",
                    op_url,
                    new_cert.expires_at_unix_sec
                );
                true
            }
            Err(e) => {
                tracing::warn!("Failed to renew UserCert from operator {}: {}", op_url, e);
                false
            }
        }
    }

    async fn get_active_server_urls(&self) -> Vec<String> {
        if !self.has_dns_discovery {
            let guard = self.resolved_servers.read().await;
            return guard.urls.clone();
        }
        {
            let guard = self.resolved_servers.read().await;
            if !guard.urls.is_empty() {
                if let Some(t) = guard.resolved_at {
                    if t.elapsed() < DNS_REFRESH_INTERVAL {
                        return guard.urls.clone();
                    }
                }
            }
        }
        let configured = self.cfg.servers.clone();
        let discovery = tokio::task::spawn_blocking(move || {
            sshcast_proto::dns::resolve_swarm_discovery(&configured)
        })
        .await
        .unwrap_or_default();

        if let Some(op_url) = discovery.operator_url {
            self.update_operator_url(op_url).await;
        }
        let resolved = discovery.servers;

        let mut guard = self.resolved_servers.write().await;
        if !resolved.is_empty() {
            if guard.urls != resolved {
                tracing::info!(
                    "Resolved coordinator servers via _sshcast DNS TXT: {}",
                    resolved.join(", ")
                );
            }
            guard.urls = resolved.clone();
            guard.resolved_at = Some(Instant::now());
            return resolved;
        }
        guard.urls.clone()
    }

    async fn get_or_connect_channel(&self, url: &str) -> Result<Channel> {
        {
            let guard = self.channels.read().await;
            if let Some(ch) = guard.get(url) {
                return Ok(ch.clone());
            }
        }

        let _conn_guard = self.connect_lock.lock().await;
        {
            let guard = self.channels.read().await;
            if let Some(ch) = guard.get(url) {
                return Ok(ch.clone());
            }
        }

        let mut endpoint = Endpoint::from_shared(url.to_string())
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
            guard.insert(url.to_string(), channel.clone());
        }

        Ok(channel)
    }

    async fn invalidate_channel(&self, url: &str) {
        let mut guard = self.channels.write().await;
        guard.remove(url);
    }

    /// Returns cached public keys immediately (0ms) using stale-while-revalidate when cached keys
    /// are available in memory or on disk, or queries `GetIdentities` synchronously on first cold boot.
    pub async fn get_identities(self: &Arc<Self>) -> Vec<PublicKey> {
        let ttl = Duration::from_secs(self.cfg.key_cache_ttl_secs);
        if ttl > Duration::ZERO {
            let guard = self.key_cache.read().await;
            if !guard.keys.is_empty() {
                let is_fresh = guard
                    .fetched_at
                    .map(|t| t.elapsed() < ttl)
                    .unwrap_or(false);
                let cached = guard.keys.clone();
                drop(guard);

                if is_fresh {
                    tracing::info!(
                        "GetIdentities served {} key(s) from fresh memory cache in 0ms",
                        cached.len()
                    );
                } else {
                    tracing::info!(
                        "GetIdentities served {} key(s) from cache in 0ms (revalidating in background)",
                        cached.len()
                    );
                    self.spawn_background_refresh();
                }
                return cached;
            }
        }

        self.refresh_identities_now().await
    }

    fn spawn_background_refresh(self: &Arc<Self>) {
        if self
            .refresh_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let me = Arc::clone(self);
            tokio::spawn(async move {
                let _ = me.refresh_identities_now().await;
                me.refresh_in_flight.store(false, Ordering::Release);
            });
        }
    }

    async fn refresh_identities_now(&self) -> Vec<PublicKey> {
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

    async fn call_get_identities(
        &self,
        ch: Channel,
    ) -> std::result::Result<tonic::Response<GetIdentitiesResponse>, tonic::Status> {
        let grant = self.current_grant().await;
        let auth = create_node_auth(grant, &self.cfg.node_signing_key, Self::now_unix_ms())
            .map_err(|e| tonic::Status::internal(format!("failed to create NodeAuth: {e}")))?;
        let mut client = SshcastServiceClient::new(ch);
        let mut req = tonic::Request::new(GetIdentitiesRequest { auth: Some(auth) });
        req.set_timeout(Duration::from_millis(self.cfg.connect_timeout_ms.max(3000)));
        client.get_identities(req).await
    }

    async fn build_signed_sign_request(
        &self,
        request_id: String,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
        process_context: &ProcessContext,
        ssh_auth_context: &SshAuthContext,
    ) -> Result<SignRequest> {
        let now_ms = Self::now_unix_ms();
        let grant = self.current_grant().await;
        let auth = create_node_auth(
            grant.clone(),
            &self.cfg.node_signing_key,
            now_ms,
        )?;
        let mut sign_req = SignRequest {
            request_id,
            timestamp_unix_ms: now_ms,
            key_blob: key_blob.to_vec(),
            data: data.to_vec(),
            flags,
            process_context: Some(process_context.clone()),
            ssh_auth_context: Some(ssh_auth_context.clone()),
            relay_grant: Some(grant),
            relay_signature: Vec::new(),
            auth: Some(auth),
        };
        sign_sign_request(&mut sign_req, &self.cfg.node_signing_key)
            .context("failed to sign SignRequest with relay Ed25519 key")?;
        Ok(sign_req)
    }

    async fn call_sign(
        &self,
        ch: Channel,
        sign_req: &SignRequest,
        url: &str,
    ) -> std::result::Result<SignResponse, tonic::Status> {
        let mut client = SshcastServiceClient::new(ch);
        let mut rpc_req = tonic::Request::new(sign_req.clone());
        rpc_req.set_timeout(Duration::from_secs(self.cfg.sign_timeout_secs));
        let t_sign = Instant::now();
        tracing::info!(
            "Dispatching SignRequest {} to {}",
            sign_req.request_id,
            url
        );
        let resp = client.sign(rpc_req).await?;
        let inner = resp.into_inner();
        tracing::info!(
            "SignRequest {} returned from {} in {}ms (approved={}, handled_by={})",
            sign_req.request_id,
            url,
            t_sign.elapsed().as_millis(),
            inner.approved,
            inner.handled_by_node_id
        );
        Ok(inner)
    }

    async fn fetch_identities_remote(&self) -> Result<Vec<PublicKey>> {
        self.maybe_renew_cert(false).await;

        let servers = self.get_active_server_urls().await;
        if servers.is_empty() {
            anyhow::bail!("no coordinator servers resolved from configuration");
        }
        let num_servers = servers.len();
        let start = self.preferred_idx.load(Ordering::Relaxed) % num_servers;
        let mut last_err = None;
        let mut renewed_on_auth_err = false;

        for offset in 0..num_servers {
            let idx = (start + offset) % num_servers;
            let url = &servers[idx];
            let ch = match self.get_or_connect_channel(url).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let mut res = self.call_get_identities(ch.clone()).await;
            if let Err(ref status) = res {
                if !renewed_on_auth_err
                    && matches!(
                        status.code(),
                        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
                    )
                {
                    renewed_on_auth_err = true;
                    if self.maybe_renew_cert(true).await {
                        res = self.call_get_identities(ch).await;
                    }
                }
            }

            match res {
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
                    self.invalidate_channel(url).await;
                    last_err = Some(anyhow::anyhow!(
                        "GetIdentities on {} failed: {}",
                        url,
                        status
                    ));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no coordinator servers available")))
    }

    /// Packages, cryptographically signs end-to-end with the relay's Ed25519 private key,
    /// and dispatches a `SignRequest` to configured `sshcast-server` endpoints with failover.
    pub async fn sign_challenge(
        &self,
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
        process_context: ProcessContext,
    ) -> Result<SignResponse> {
        self.maybe_renew_cert(false).await;

        let request_id = generate_request_id();
        let ssh_auth_context = parse_ssh_auth_context(&data);
        let mut sign_req = self
            .build_signed_sign_request(
                request_id.clone(),
                &key_blob,
                &data,
                flags,
                &process_context,
                &ssh_auth_context,
            )
            .await?;

        let servers = self.get_active_server_urls().await;
        if servers.is_empty() {
            anyhow::bail!("no coordinator servers resolved from configuration");
        }
        let num_servers = servers.len();
        let start = self.preferred_idx.load(Ordering::Relaxed) % num_servers;
        let mut last_err = None;
        let mut renewed_on_auth_err = false;

        for offset in 0..num_servers {
            let idx = (start + offset) % num_servers;
            let url = &servers[idx];
            let ch = match self.get_or_connect_channel(url).await {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let mut res = self.call_sign(ch.clone(), &sign_req, url).await;
            if let Err(ref status) = res {
                if !renewed_on_auth_err
                    && matches!(
                        status.code(),
                        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
                    )
                {
                    renewed_on_auth_err = true;
                    if self.maybe_renew_cert(true).await {
                        sign_req = self
                            .build_signed_sign_request(
                                request_id.clone(),
                                &key_blob,
                                &data,
                                flags,
                                &process_context,
                                &ssh_auth_context,
                            )
                            .await?;
                        res = self.call_sign(ch, &sign_req, url).await;
                    }
                }
            }

            match res {
                Ok(inner) => {
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
                        url,
                        inner.error_message
                    ));
                }
                Err(status) => {
                    self.invalidate_channel(url).await;
                    last_err = Some(anyhow::anyhow!(
                        "Sign RPC on {} failed: {}",
                        url,
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
