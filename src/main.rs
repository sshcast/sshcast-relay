use anyhow::Result;
use clap::{Parser, Subcommand};
use sshcast_relay::config::RelayConfig;
use sshcast_relay::init::{
    prompt_overwrite_confirmation, run_init_with_confirm, InitOptions, ServiceAction,
};
use sshcast_relay::listener::run_daemon;
use sshcast_relay::zellij::{discover_zellij_sessions, ensure_zellij_web_sharing_enabled};
use std::path::PathBuf;
use std::process::Command;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sshcast-relay",
    version,
    about = "Sshcast Roaming SSH Agent Target Host Relay"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Enroll this Linux host using a Base64 enrollment bundle from `sshcast-client grant-relay`
    Init {
        /// Compact enrollment bundle token (`sc1_<base64>`)
        #[arg(long)]
        bundle: String,

        /// Optional custom path for `relay.toml` (defaults to `~/.config/sshcast/relay.toml`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Skip running `systemctl --user enable --now sshcast-relay.socket`
        #[arg(long, default_value_t = false)]
        no_systemctl: bool,

        /// Enable Zellij Web session advertisement and tunneling (`zellij web` on 127.0.0.1)
        #[arg(long, default_value_t = false)]
        enable_zellij: bool,

        /// Overwrite an existing `relay.toml` without prompting for confirmation
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Run the SSH agent relay daemon (invoked via `systemd --user` socket activation or standalone)
    Run {
        /// Optional custom path for `relay.toml` (defaults to `~/.config/sshcast/relay.toml`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Optional override for Unix socket path
        #[arg(long)]
        socket: Option<PathBuf>,

        /// Optional override for idle auto-exit timeout in seconds (0 = never exit)
        #[arg(long)]
        idle_timeout_secs: Option<u64>,
    },
    /// Configure or inspect Zellij Web session advertisement and tunneling on this relay host
    Zellij {
        #[command(subcommand)]
        action: ZellijAction,
    },
    /// Import an operator-signed user certificate (`sc_cert_<base64>`) into `relay.toml`
    ImportCert {
        /// Operator-signed user certificate token (`sc_cert_<base64>`)
        #[arg(long)]
        cert: String,

        /// Optional custom path for `relay.toml` (defaults to `~/.config/sshcast/relay.toml`)
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ZellijAction {
    /// Enable Zellij Web advertisement and tunneling on this relay host
    Enable {
        /// Optional custom path for `relay.toml`
        #[arg(long)]
        config: Option<PathBuf>,
        /// Optional loopback port for `zellij web` (default: 8082)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Disable Zellij Web advertisement and tunneling on this relay host
    Disable {
        /// Optional custom path for `relay.toml`
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show Zellij Web configuration and discovered local Zellij sessions
    Status {
        /// Optional custom path for `relay.toml`
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            bundle,
            config,
            no_systemctl,
            enable_zellij,
            force,
        } => {
            let opts = InitOptions {
                bundle_token: bundle,
                config_path: config,
                skip_systemctl: no_systemctl,
                enable_zellij,
                force,
                ..Default::default()
            };
            let outcome = run_init_with_confirm(&opts, prompt_overwrite_confirmation)?;
            println!(
                "Enrolled sshcast-relay node '{}' for user '{}'",
                outcome.node_id, outcome.user_id
            );
            println!("  Config written to: {}", outcome.config_path.display());
            println!("  Coordinators:      {}", outcome.servers.join(", "));
            println!(
                "  Zellij Web:        {}",
                if enable_zellij { "enabled" } else { "disabled" }
            );
            if outcome.installed_local_units {
                if let Some(sock) = &outcome.socket_unit_path {
                    println!("  User socket unit:  {}", sock.display());
                }
            } else {
                println!("  Using global RPM systemd user units in /usr/lib/systemd/user/");
            }
            match outcome.service_action {
                ServiceAction::Restarted => {
                    println!("  Service:           restarted sshcast-relay.service");
                }
                ServiceAction::Started => {
                    println!("  Service:           started sshcast-relay.service");
                }
                ServiceAction::RestartFailed => {
                    eprintln!(
                        "Warning: could not automatically restart sshcast-relay.service; if running, run `systemctl --user restart sshcast-relay.service` to apply the new configuration."
                    );
                }
                ServiceAction::Skipped if outcome.overwrote_existing => {
                    println!(
                        "  Note:              if sshcast-relay is currently running, restart it to apply the new configuration"
                    );
                }
                ServiceAction::NotRunning | ServiceAction::Skipped => {}
            }
            println!(
                "\nEnsure your shell profile exports:\n  bash/zsh: export SSH_AUTH_SOCK=\"$XDG_RUNTIME_DIR/sshcast.sock\"\n  fish:     set -gx SSH_AUTH_SOCK \"$XDG_RUNTIME_DIR/sshcast.sock\""
            );
            Ok(())
        }
        Commands::Run {
            config,
            socket,
            idle_timeout_secs,
        } => {
            let mut cfg = RelayConfig::load(config.as_deref())?;
            if let Some(sock) = socket {
                cfg.socket_path = sock;
            }
            if let Some(idle) = idle_timeout_secs {
                cfg.idle_timeout_secs = idle;
            }
            run_daemon(cfg).await
        }
        Commands::Zellij { action } => match action {
            ZellijAction::Enable { config, port } => {
                let path = RelayConfig::set_zellij_config(config.as_deref(), true, port)?;
                println!("Enabled Zellij Web tunneling in {}", path.display());
                if let Ok(Some(z_cfg)) = ensure_zellij_web_sharing_enabled() {
                    println!(
                        "Enabled `web_sharing \"on\"` in {} for terminal Zellij sessions",
                        z_cfg.display()
                    );
                }
                let _ = Command::new("systemctl")
                    .args(["--user", "daemon-reload"])
                    .status();
                if port.unwrap_or(8082) == 8082 {
                    let _ = Command::new("systemctl")
                        .args(["--user", "enable", "--now", "sshcast-zellij-web.service"])
                        .status();
                }
                let _ = Command::new("systemctl")
                    .args(["--user", "restart", "sshcast-relay.service"])
                    .status();
                Ok(())
            }
            ZellijAction::Disable { config } => {
                let path = RelayConfig::set_zellij_config(config.as_deref(), false, None)?;
                println!("Disabled Zellij Web tunneling in {}", path.display());
                let _ = Command::new("systemctl")
                    .args(["--user", "disable", "--now", "sshcast-zellij-web.service"])
                    .status();
                let _ = Command::new("systemctl")
                    .args(["--user", "restart", "sshcast-relay.service"])
                    .status();
                Ok(())
            }
            ZellijAction::Status { config } => {
                let cfg = RelayConfig::load(config.as_deref())?;
                println!("Node ID:         {}", cfg.grant.node_id);
                println!("Zellij Enabled:  {}", cfg.zellij_enabled);
                println!("Zellij Web Port: 127.0.0.1:{}", cfg.zellij_web_port);
                println!("STUN Servers:    {}", cfg.stun_servers.join(", "));
                let sessions = discover_zellij_sessions();
                if sessions.is_empty() {
                    println!("Active Sessions: (none)");
                } else {
                    println!("Active Sessions ({}):", sessions.len());
                    for s in sessions {
                        println!(
                            "  - {} {} {}",
                            s.name,
                            s.created_info,
                            if s.exited { "[EXITED]" } else { "" }
                        );
                    }
                }
                Ok(())
            }
        },
        Commands::ImportCert { cert, config } => {
            let (cfg_path, user_cert) = RelayConfig::import_user_cert(config.as_deref(), &cert)?;
            println!(
                "Imported operator-signed certificate into {}",
                cfg_path.display()
            );
            println!("  User ID:         {}", user_cert.user_id);
            println!(
                "  Operator Pubkey: sc_op_pub_{}",
                hex::encode(&user_cert.operator_pubkey)
            );
            Ok(())
        }
    }
}
