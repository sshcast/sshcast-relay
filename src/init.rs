use anyhow::{Context, Result};
use sshcast_proto::bundle::EnrollmentBundle;
use sshcast_proto::crypto::verify_node_grant;
use sshcast_proto::v1::NodeRole;
use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{
    default_config_path, default_pubkey_cache_path, home_dir, write_file_atomic_0600, RelayConfig,
    RelayConfigFile,
};

pub const SYSTEMD_SOCKET_UNIT: &str = r#"[Unit]
Description=Sshcast Roaming SSH Agent Relay Socket
Documentation=https://github.com/sshcast/sshcast-relay

[Socket]
ListenStream=%t/sshcast.sock
FileDescriptorName=sshcast.sock
SocketMode=0600
DirectoryMode=0700

[Install]
WantedBy=sockets.target
"#;

pub fn render_systemd_service_unit(binary_path: &str) -> String {
    format!(
        r#"[Unit]
Description=Sshcast Roaming SSH Agent Relay Daemon
Documentation=https://github.com/sshcast/sshcast-relay
Requires=sshcast-relay.socket
After=sshcast-relay.socket network-online.target

[Service]
Type=simple
Environment=TERM=xterm-256color
ExecStart={binary_path} run
Restart=no
NoNewPrivileges=yes
KillMode=process

[Install]
Also=sshcast-relay.socket
"#
    )
}

pub fn render_systemd_zellij_web_service_unit(port: u16) -> String {
    format!(
        r#"[Unit]
Description=Sshcast Zellij Web Local Server
Documentation=https://github.com/sshcast/sshcast-relay
After=network.target

[Service]
Type=simple
Environment=TERM=xterm-256color
ExecStart=/usr/bin/zellij web --ip 127.0.0.1 --port {port}
Restart=on-failure
RestartSec=2
KillMode=process

[Install]
WantedBy=default.target
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
    pub enable_zellij: bool,
    pub force: bool,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            bundle_token: String::new(),
            config_path: None,
            systemd_user_dir: None,
            global_systemd_user_dir: PathBuf::from("/usr/lib/systemd/user"),
            skip_systemctl: false,
            enable_zellij: false,
            force: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Skipped,
    NotRunning,
    Started,
    Restarted,
    RestartFailed,
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
    pub overwrote_existing: bool,
    pub service_action: ServiceAction,
}

#[derive(Debug, Clone)]
pub struct ExistingConfigInfo {
    pub config_path: PathBuf,
    pub current_node_id: Option<String>,
    pub current_user_id: Option<String>,
    pub current_servers: Vec<String>,
    pub current_zellij_enabled: Option<bool>,
    pub new_node_id: String,
    pub new_user_id: String,
    pub new_servers: Vec<String>,
    pub new_enable_zellij: bool,
}

/// Prompts interactively on `stderr`/`stdin` before overwriting an existing `relay.toml`.
pub fn prompt_overwrite_confirmation(info: &ExistingConfigInfo) -> Result<bool> {
    prompt_overwrite_confirmation_io(
        info,
        std::io::stdin().is_terminal(),
        &mut std::io::stdin().lock(),
        &mut std::io::stderr(),
    )
}

pub fn prompt_overwrite_confirmation_io(
    info: &ExistingConfigInfo,
    is_tty: bool,
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
) -> Result<bool> {
    if !is_tty {
        anyhow::bail!(
            "relay config already exists at {}; re-run interactively to confirm or pass --force to overwrite",
            info.config_path.display()
        );
    }

    if let (Some(cur_node), Some(cur_user)) = (&info.current_node_id, &info.current_user_id) {
        writeln!(
            writer,
            "Existing relay config found at {}:",
            info.config_path.display()
        )?;
        writeln!(
            writer,
            "  Current: node '{}' (user '{}', coordinators: {})",
            cur_node,
            cur_user,
            info.current_servers.join(", ")
        )?;
        writeln!(
            writer,
            "  New:     node '{}' (user '{}', coordinators: {})",
            info.new_node_id,
            info.new_user_id,
            info.new_servers.join(", ")
        )?;
        if info.current_zellij_enabled == Some(true) && !info.new_enable_zellij {
            writeln!(
                writer,
                "Note: existing config has Zellij Web enabled; pass --enable-zellij to keep it enabled."
            )?;
        }
    } else {
        writeln!(
            writer,
            "Existing file found at {} (could not parse as relay config).",
            info.config_path.display()
        )?;
        writeln!(
            writer,
            "  New:     node '{}' (user '{}', coordinators: {})",
            info.new_node_id,
            info.new_user_id,
            info.new_servers.join(", ")
        )?;
    }

    write!(writer, "Overwrite existing configuration? [y/N]: ")?;
    writer.flush()?;

    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(false);
    }
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub fn run_init(opts: &InitOptions) -> Result<InitOutcome> {
    run_init_with_confirm(opts, |info| {
        anyhow::bail!(
            "relay config already exists at {} (pass --force to overwrite)",
            info.config_path.display()
        );
    })
}

pub fn run_init_with_confirm<F>(opts: &InitOptions, confirm_overwrite: F) -> Result<InitOutcome>
where
    F: FnOnce(&ExistingConfigInfo) -> Result<bool>,
{
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

    let existed = cfg_path.symlink_metadata().is_ok();
    let mut old_pubkey_cache_path: Option<PathBuf> = None;

    if existed {
        let mut current_node_id: Option<String> = None;
        let mut current_user_id: Option<String> = None;
        let mut current_servers: Vec<String> = Vec::new();
        let mut current_zellij_enabled: Option<bool> = None;

        if let Ok(raw) = std::fs::read_to_string(&cfg_path) {
            if let Ok(file) = toml::from_str::<RelayConfigFile>(&raw) {
                old_pubkey_cache_path = file
                    .pubkey_cache_path
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from);
                current_zellij_enabled = Some(file.zellij_enabled);
                if let Ok(cfg) = RelayConfig::from_config_file(file) {
                    current_node_id = Some(cfg.grant.node_id);
                    current_user_id = Some(cfg.grant.user_id);
                    current_servers = cfg.servers;
                }
            }
        }

        if !opts.force {
            let info = ExistingConfigInfo {
                config_path: cfg_path.clone(),
                current_node_id,
                current_user_id,
                current_servers,
                current_zellij_enabled,
                new_node_id: bundle.grant.node_id.clone(),
                new_user_id: bundle.grant.user_id.clone(),
                new_servers: bundle.servers.clone(),
                new_enable_zellij: opts.enable_zellij,
            };
            if !confirm_overwrite(&info)? {
                anyhow::bail!(
                    "aborted: existing relay configuration at {} was not overwritten",
                    cfg_path.display()
                );
            }
        }
    }

    if let Some(parent) = cfg_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory {}", parent.display()))?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    let mut cfg_file = RelayConfigFile::from_bundle(&bundle);
    cfg_file.zellij_enabled = opts.enable_zellij;
    let toml_str =
        toml::to_string_pretty(&cfg_file).context("failed to serialize relay.toml")?;
    write_file_atomic_0600(&cfg_path, toml_str.as_bytes())?;

    if existed {
        let cache_path = old_pubkey_cache_path.or_else(|| {
            if opts.config_path.is_none() {
                Some(default_pubkey_cache_path())
            } else {
                None
            }
        });
        if let Some(p) = cache_path {
            let _ = std::fs::remove_file(p);
        }
    }

    let global_socket = opts.global_systemd_user_dir.join("sshcast-relay.socket");
    let global_service = opts.global_systemd_user_dir.join("sshcast-relay.service");

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

        let sock_path = user_systemd_dir.join("sshcast-relay.socket");
        let svc_path = user_systemd_dir.join("sshcast-relay.service");
        let zellij_svc_path = user_systemd_dir.join("sshcast-zellij-web.service");

        let bin_path = resolve_binary_path();
        std::fs::write(&sock_path, SYSTEMD_SOCKET_UNIT)
            .with_context(|| format!("failed to write {}", sock_path.display()))?;
        std::fs::write(&svc_path, render_systemd_service_unit(&bin_path))
            .with_context(|| format!("failed to write {}", svc_path.display()))?;
        std::fs::write(
            &zellij_svc_path,
            render_systemd_zellij_web_service_unit(cfg_file.zellij_web_port),
        )
        .with_context(|| format!("failed to write {}", zellij_svc_path.display()))?;

        installed_local_units = true;
        socket_unit_path = Some(sock_path);
        service_unit_path = Some(svc_path);
    }

    let service_action = if !opts.skip_systemctl {
        if opts.enable_zellij {
            let _ = crate::zellij::ensure_zellij_web_sharing_enabled();
        }
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let status = Command::new("systemctl")
            .args(["--user", "enable", "--now", "sshcast-relay.socket"])
            .status();
        match status {
            Ok(s) if s.success() => {
                tracing::info!("Enabled and started systemd user unit: sshcast-relay.socket");
            }
            Ok(s) => {
                tracing::warn!(
                    "systemctl --user enable --now sshcast-relay.socket exited with {}",
                    s
                );
            }
            Err(e) => {
                tracing::warn!("Could not execute systemctl --user: {}", e);
            }
        }

        let was_active = Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", "sshcast-relay.service"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        let action = if opts.enable_zellij {
            let _ = Command::new("systemctl")
                .args(["--user", "enable", "--now", "sshcast-zellij-web.service"])
                .status();
            match Command::new("systemctl")
                .args(["--user", "restart", "sshcast-relay.service"])
                .status()
            {
                Ok(s) if s.success() => {
                    if was_active {
                        tracing::info!("Restarted systemd user service: sshcast-relay.service");
                        ServiceAction::Restarted
                    } else {
                        tracing::info!("Started systemd user service: sshcast-relay.service");
                        ServiceAction::Started
                    }
                }
                Ok(s) => {
                    tracing::warn!(
                        "systemctl --user restart sshcast-relay.service exited with {}",
                        s
                    );
                    ServiceAction::RestartFailed
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not execute systemctl --user restart sshcast-relay.service: {}",
                        e
                    );
                    ServiceAction::RestartFailed
                }
            }
        } else {
            match Command::new("systemctl")
                .args(["--user", "try-restart", "sshcast-relay.service"])
                .status()
            {
                Ok(s) if s.success() => {
                    if was_active {
                        tracing::info!("Restarted systemd user service: sshcast-relay.service");
                        ServiceAction::Restarted
                    } else {
                        ServiceAction::NotRunning
                    }
                }
                Ok(s) => {
                    tracing::warn!(
                        "systemctl --user try-restart sshcast-relay.service exited with {}",
                        s
                    );
                    if was_active || existed {
                        ServiceAction::RestartFailed
                    } else {
                        ServiceAction::NotRunning
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not execute systemctl --user try-restart sshcast-relay.service: {}",
                        e
                    );
                    if was_active || existed {
                        ServiceAction::RestartFailed
                    } else {
                        ServiceAction::NotRunning
                    }
                }
            }
        };

        check_systemd_linger();
        action
    } else {
        ServiceAction::Skipped
    };

    Ok(InitOutcome {
        config_path: cfg_path,
        node_id: bundle.grant.node_id,
        user_id: bundle.grant.user_id,
        servers: bundle.servers,
        installed_local_units,
        socket_unit_path,
        service_unit_path,
        overwrote_existing: existed,
        service_action,
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
    if Path::new("/usr/bin/sshcast-relay").exists() {
        return "/usr/bin/sshcast-relay".to_string();
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "/usr/bin/sshcast-relay".to_string())
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
             To keep sshcast-relay.socket active inside detached Zellij/tmux sessions after SSH logout, run:\n\
             sudo loginctl enable-linger {user}"
        );
    }
}
