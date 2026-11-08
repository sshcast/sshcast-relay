use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use prost::Message;
use serde::{Deserialize, Serialize};
use sockcast_proto::bundle::EnrollmentBundle;
use sockcast_proto::v1::NodeGrant;
use std::path::{Path, PathBuf};

fn default_idle_timeout_secs() -> u64 {
    900 // 15 minutes
}

fn default_key_cache_ttl_secs() -> u64 {
    60 // 60 seconds
}

fn default_connect_timeout_ms() -> u64 {
    3000 // 3 seconds
}

fn default_sign_timeout_secs() -> u64 {
    65 // 65 seconds (slightly above server's 60s SignResponse wait)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfigFile {
    /// Coordinator server URLs (e.g. ["https://sockcast.example.com", "http://127.0.0.1:50051"])
    pub servers: Vec<String>,
    /// Base64 URL-safe encoded 32-byte Ed25519 private key seed for this relay node.
    pub node_privkey_seed_b64: String,
    /// Base64 URL-safe encoded protobuf `NodeGrant` signed by the user's root key.
    pub grant_proto_b64: String,
    /// Optional Unix socket path override (defaults to `/run/user/$UID/sockcast.sock`).
    #[serde(default)]
    pub socket_path: Option<String>,
    /// Idle timeout in seconds before auto-exiting when no connections are active (default: 900s = 15m; 0 = never exit).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// In-memory public key cache TTL in seconds (default: 60s).
    #[serde(default = "default_key_cache_ttl_secs")]
    pub key_cache_ttl_secs: u64,
    /// Optional disk cache path for public keys (defaults to `~/.cache/sockcast/pubkeys.json`).
    #[serde(default)]
    pub pubkey_cache_path: Option<String>,
    /// Per-server gRPC connect timeout in milliseconds (default: 3000ms).
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Overall Sign RPC timeout in seconds (default: 65s).
    #[serde(default = "default_sign_timeout_secs")]
    pub sign_timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub servers: Vec<String>,
    pub node_signing_key: SigningKey,
    pub grant: NodeGrant,
    pub socket_path: PathBuf,
    pub idle_timeout_secs: u64,
    pub key_cache_ttl_secs: u64,
    pub pubkey_cache_path: PathBuf,
    pub connect_timeout_ms: u64,
    pub sign_timeout_secs: u64,
}

impl RelayConfigFile {
    pub fn from_bundle(bundle: &EnrollmentBundle) -> Self {
        let mut grant_bytes = Vec::new();
        bundle
            .grant
            .encode(&mut grant_bytes)
            .expect("prost encode cannot fail on Vec");
        Self {
            servers: bundle.servers.clone(),
            node_privkey_seed_b64: URL_SAFE_NO_PAD.encode(bundle.node_signing_key.to_bytes()),
            grant_proto_b64: URL_SAFE_NO_PAD.encode(grant_bytes),
            socket_path: None,
            idle_timeout_secs: default_idle_timeout_secs(),
            key_cache_ttl_secs: default_key_cache_ttl_secs(),
            pubkey_cache_path: None,
            connect_timeout_ms: default_connect_timeout_ms(),
            sign_timeout_secs: default_sign_timeout_secs(),
        }
    }
}

impl RelayConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let cfg_path = match path {
            Some(p) => p.to_path_buf(),
            None => default_config_path()?,
        };
        let raw = std::fs::read_to_string(&cfg_path)
            .with_context(|| format!("failed to read relay config {}", cfg_path.display()))?;
        Self::from_toml_str(&raw)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self> {
        let file: RelayConfigFile =
            toml::from_str(raw).context("failed to parse relay.toml")?;
        Self::from_config_file(file)
    }

    pub fn from_config_file(file: RelayConfigFile) -> Result<Self> {
        if file.servers.is_empty() {
            anyhow::bail!("relay configuration must specify at least one server URL");
        }

        let seed_vec = URL_SAFE_NO_PAD
            .decode(file.node_privkey_seed_b64.trim())
            .context("invalid base64 in node_privkey_seed_b64")?;
        let seed: [u8; 32] = seed_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("node_privkey_seed_b64 must decode to 32 bytes"))?;
        let node_signing_key = SigningKey::from_bytes(&seed);

        let grant_bytes = URL_SAFE_NO_PAD
            .decode(file.grant_proto_b64.trim())
            .context("invalid base64 in grant_proto_b64")?;
        let grant = NodeGrant::decode(grant_bytes.as_slice())
            .context("failed to decode NodeGrant protobuf")?;

        let socket_path = match file.socket_path {
            Some(s) if !s.trim().is_empty() => PathBuf::from(s),
            _ => default_socket_path(),
        };

        let pubkey_cache_path = match file.pubkey_cache_path {
            Some(s) if !s.trim().is_empty() => PathBuf::from(s),
            _ => default_pubkey_cache_path(),
        };

        Ok(Self {
            servers: file.servers,
            node_signing_key,
            grant,
            socket_path,
            idle_timeout_secs: file.idle_timeout_secs,
            key_cache_ttl_secs: file.key_cache_ttl_secs,
            pubkey_cache_path,
            connect_timeout_ms: file.connect_timeout_ms,
            sign_timeout_secs: file.sign_timeout_secs,
        })
    }
}

pub fn current_euid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn home_dir() -> Result<PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    anyhow::bail!("HOME environment variable is not set")
}

pub fn default_config_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("sockcast"));
        }
    }
    Ok(home_dir()?.join(".config").join("sockcast"))
}

pub fn default_config_path() -> Result<PathBuf> {
    Ok(default_config_dir()?.join("relay.toml"))
}

pub fn default_cache_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("sockcast");
        }
    }
    if let Ok(home) = home_dir() {
        return home.join(".cache").join("sockcast");
    }
    PathBuf::from(format!("/tmp/sockcast-cache-{}", current_euid()))
}

pub fn default_pubkey_cache_path() -> PathBuf {
    default_cache_dir().join("pubkeys.json")
}

pub fn default_socket_path() -> PathBuf {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !runtime_dir.is_empty() {
            return PathBuf::from(runtime_dir).join("sockcast.sock");
        }
    }
    PathBuf::from(format!("/run/user/{}/sockcast.sock", current_euid()))
}
