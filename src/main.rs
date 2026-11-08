use anyhow::Result;
use clap::{Parser, Subcommand};
use sockcast_relay::config::RelayConfig;
use sockcast_relay::init::{run_init, InitOptions};
use sockcast_relay::listener::run_daemon;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sockcast-relay",
    version,
    about = "Sockcast Roaming SSH Agent Target Host Relay"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Enroll this Linux host using a Base64 enrollment bundle from `sockcast-client grant-relay`
    Init {
        /// Compact enrollment bundle token (`sc1_<base64>`)
        #[arg(long)]
        bundle: String,

        /// Optional custom path for `relay.toml` (defaults to `~/.config/sockcast/relay.toml`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Skip running `systemctl --user enable --now sockcast-relay.socket`
        #[arg(long, default_value_t = false)]
        no_systemctl: bool,
    },
    /// Run the SSH agent relay daemon (invoked via `systemd --user` socket activation or standalone)
    Run {
        /// Optional custom path for `relay.toml` (defaults to `~/.config/sockcast/relay.toml`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Optional override for Unix socket path
        #[arg(long)]
        socket: Option<PathBuf>,

        /// Optional override for idle auto-exit timeout in seconds (0 = never exit)
        #[arg(long)]
        idle_timeout_secs: Option<u64>,
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

    match cli.command.unwrap_or(Commands::Run {
        config: None,
        socket: None,
        idle_timeout_secs: None,
    }) {
        Commands::Init {
            bundle,
            config,
            no_systemctl,
        } => {
            let opts = InitOptions {
                bundle_token: bundle,
                config_path: config,
                skip_systemctl: no_systemctl,
                ..Default::default()
            };
            let outcome = run_init(&opts)?;
            println!(
                "Enrolled sockcast-relay node '{}' for user '{}'",
                outcome.node_id, outcome.user_id
            );
            println!("  Config written to: {}", outcome.config_path.display());
            println!("  Coordinators:      {}", outcome.servers.join(", "));
            if outcome.installed_local_units {
                if let Some(sock) = &outcome.socket_unit_path {
                    println!("  User socket unit:  {}", sock.display());
                }
            } else {
                println!("  Using global RPM systemd user units in /usr/lib/systemd/user/");
            }
            println!(
                "\nEnsure your shell profile exports:\n  export SSH_AUTH_SOCK=\"/run/user/$(id -u)/sockcast.sock\""
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
    }
}
