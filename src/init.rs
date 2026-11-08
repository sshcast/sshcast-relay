use anyhow::{Context, Result};
use sockcast_proto::bundle::EnrollmentBundle;
use sockcast_proto::crypto::verify_node_grant;
use sockcast_proto::v1::NodeRole;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{default_config_path, home_dir, RelayConfigFile};

pub const SYSTEMD_SOCKET_UNIT: &str = r#"[Unit]
Description=Sockcast Roaming SSH Agent Relay Socket
Documentation=https://github.com/theraphim/sockcast-relay

[Socket]
ListenStream=%t/sockcast.sock
FileDescriptorName=sockcast.sock
SocketMode=0600
DirectoryMode=0700

[Install]
WantedBy=sockets.target
"#;

pub fn render_systemd_service_unit(binary_path: &str) -> String {
    format!(
        r#"[Unit]
Description=Sockcast Roaming SSH Agent Relay Daemon
Documentation=https://github.com/theraphim/sockcast-relay
Requires=sockcast-relay.socket
After=sockcast-relay.socket network-online.target

[Service]
Type=simple
ExecStart={binary_path} run
Restart=no
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
Also=sockcast-relay.socket
"#
    )
}

#[derive(Debug, Clone)]
pub struct InitOptions {
    pub bundle_token: String,
    pub config_path: Option<PathBuf>,
    pub systemd_user_dir: Option<PathBuf>,
    pub global_systemd_user_dir: PathBuf,
    pub skip_systemctl: bool,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            bundle_token: String::new(),
            config_path: None,
            systemd_user_dir: None,
            global_systemd_user_dir: PathBuf::from("/usr/lib/systemd/user"),
            skip_systemctl: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InitOutcome {
    pub config_path: PathBuf,
    pub node_id: String,
    pub user_id: String,
    pub servers: Vec<String>,
    pub installed_local_units: bool,
    pub socket_unit_path: Option<PathBuf>,
    pub service_unit_path: Option<PathBuf>,
}

pub fn run_init(opts: &InitOptions) -> Result<InitOutcome> {
    let bundle = EnrollmentBundle::decode(&opts.bundle_token)
        .context("failed to decode enrollment bundle token")?;

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    verify_node_grant(&bundle.grant, now_sec)
        .context("enrollment bundle NodeGrant signature or expiration verification failed")?;

    if bundle.grant.role != NodeRole::Relay as i32 {
        anyhow::bail!(
            "enrollment bundle role is not RELAY (got {})",
            bundle.grant.role
        );
    }

    let cfg_path = match &opts.config_path {
        Some(p) => p.clone(),
        None => default_config_path()?,
    };

    if let Some(parent) = cfg_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory {}", parent.display()))?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    let cfg_file = RelayConfigFile::from_bundle(&bundle);
    let toml_str =
        toml::to_string_pretty(&cfg_file).context("failed to serialize relay.toml")?;
    std::fs::write(&cfg_path, &toml_str)
        .with_context(|| format!("failed to write {}", cfg_path.display()))?;
    std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set 0600 permissions on {}", cfg_path.display()))?;

    let global_socket = opts.global_systemd_user_dir.join("sockcast-relay.socket");
    let global_service = opts.global_systemd_user_dir.join("sockcast-relay.service");

    let mut installed_local_units = false;
    let mut socket_unit_path = None;
    let mut service_unit_path = None;

    if !global_socket.exists() || !global_service.exists() {
        let user_systemd_dir = match &opts.systemd_user_dir {
            Some(d) => d.clone(),
            None => default_systemd_user_dir()?,
        };
        std::fs::create_dir_all(&user_systemd_dir).with_context(|| {
            format!(
                "failed to create user systemd directory {}",
                user_systemd_dir.display()
            )
        })?;

        let sock_path = user_systemd_dir.join("sockcast-relay.socket");
        let svc_path = user_systemd_dir.join("sockcast-relay.service");

        let bin_path = resolve_binary_path();
        std::fs::write(&sock_path, SYSTEMD_SOCKET_UNIT)
            .with_context(|| format!("failed to write {}", sock_path.display()))?;
        std::fs::write(&svc_path, render_systemd_service_unit(&bin_path))
            .with_context(|| format!("failed to write {}", svc_path.display()))?;

        installed_local_units = true;
        socket_unit_path = Some(sock_path);
        service_unit_path = Some(svc_path);
    }

    if !opts.skip_systemctl {
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let status = Command::new("systemctl")
            .args(["--user", "enable", "--now", "sockcast-relay.socket"])
            .status();
        match status {
            Ok(s) if s.success() => {
                tracing::info!("Enabled and started systemd user unit: sockcast-relay.socket");
            }
            Ok(s) => {
                tracing::warn!(
                    "systemctl --user enable --now sockcast-relay.socket exited with {}",
                    s
                );
            }
            Err(e) => {
                tracing::warn!("Could not execute systemctl --user: {}", e);
            }
        }
        check_systemd_linger();
    }

    Ok(InitOutcome {
        config_path: cfg_path,
        node_id: bundle.grant.node_id,
        user_id: bundle.grant.user_id,
        servers: bundle.servers,
        installed_local_units,
        socket_unit_path,
        service_unit_path,
    })
}

fn default_systemd_user_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("systemd").join("user"));
        }
    }
    Ok(home_dir()?.join(".config").join("systemd").join("user"))
}

fn resolve_binary_path() -> String {
    if Path::new("/usr/bin/sockcast-relay").exists() {
        return "/usr/bin/sockcast-relay".to_string();
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "/usr/bin/sockcast-relay".to_string())
}

fn check_systemd_linger() {
    let user = std::env::var("USER").unwrap_or_default();
    if user.is_empty() {
        return;
    }
    let linger_file = Path::new("/var/lib/systemd/linger").join(&user);
    if !linger_file.exists() {
        eprintln!(
            "Note: systemd user linger is not enabled for user '{user}'.\n\
             To keep sockcast-relay.socket active inside detached Zellij/tmux sessions after SSH logout, run:\n\
             sudo loginctl enable-linger {user}"
        );
    }
}
