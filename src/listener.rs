use anyhow::{Context, Result};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio::sync::{watch, Mutex};

use crate::agent::handle_agent_session;
use crate::client::CoordinatorClient;
use crate::config::{current_euid, RelayConfig};
use crate::proc_inspector::{inspect_process_context, verify_peer_cred};

pub const SD_LISTEN_FDS_START: i32 = 3;

/// Checks `systemd` socket activation environment variables (`LISTEN_PID` and `LISTEN_FDS`).
/// If a socket was passed on FD 3 (`SD_LISTEN_FDS_START`), converts it into a non-blocking `tokio::net::UnixListener`.
pub fn take_systemd_socket() -> Result<Option<UnixListener>> {
    let listen_pid_str = match std::env::var("LISTEN_PID") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return Ok(None),
    };
    let listen_fds_str = match std::env::var("LISTEN_FDS") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return Ok(None),
    };

    let listen_pid: u32 = listen_pid_str
        .trim()
        .parse()
        .context("invalid LISTEN_PID")?;
    let my_pid = std::process::id();
    if listen_pid != my_pid {
        return Ok(None);
    }

    let listen_fds: i32 = listen_fds_str
        .trim()
        .parse()
        .context("invalid LISTEN_FDS")?;
    if listen_fds < 1 {
        return Ok(None);
    }

    // Clear environment variables so any child processes don't inherit stale LISTEN_FDS
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    let fd = SD_LISTEN_FDS_START;
    unsafe {
        // Ensure FD_CLOEXEC is set on the inherited socket FD
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
        let std_listener = std::os::unix::net::UnixListener::from_raw_fd(fd);
        std_listener
            .set_nonblocking(true)
            .context("failed to set nonblocking on systemd socket FD 3")?;
        let tokio_listener = UnixListener::from_std(std_listener)
            .context("failed to wrap systemd UnixListener in tokio")?;
        Ok(Some(tokio_listener))
    }
}

/// Binds a standalone `UnixListener` at `socket_path` with `0600` permissions.
/// Refuses to unlink an active Unix socket or non-socket filesystem entry.
pub fn bind_standalone_socket(socket_path: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create parent directory {}", parent.display())
        })?;
    }
    match std::fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                anyhow::bail!(
                    "refusing to remove non-socket file at {}",
                    socket_path.display()
                );
            }
            match std::os::unix::net::UnixStream::connect(socket_path) {
                Ok(_) => {
                    anyhow::bail!(
                        "Unix socket {} is already active (likely managed by sshcast-relay.socket or another sshcast-relay instance)",
                        socket_path.display()
                    );
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    if let Err(rm_err) = std::fs::remove_file(socket_path) {
                        if rm_err.kind() != std::io::ErrorKind::NotFound {
                            return Err(rm_err).with_context(|| {
                                format!("failed to remove stale socket {}", socket_path.display())
                            });
                        }
                    }
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "refusing to remove Unix socket {} after failed liveness probe",
                            socket_path.display()
                        )
                    });
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| {
                format!("failed to inspect existing path {}", socket_path.display())
            });
        }
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind Unix socket {}", socket_path.display()))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set 0600 permissions on {}", socket_path.display()))?;
    Ok(listener)
}

/// Runs the relay accept loop with `SO_PEERCRED` verification, `/proc` ancestry inspection,
/// and an automatic idle timeout when `idle_timeout` > 0.
pub async fn serve_with_listener(
    listener: UnixListener,
    cfg: RelayConfig,
    idle_timeout: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let expected_uid = current_euid();
    let hostname = cfg.grant.node_id.clone();
    let effective_idle_timeout = if cfg.zellij_enabled {
        Duration::ZERO
    } else {
        idle_timeout
    };
    if cfg.zellij_enabled {
        let zellij_cfg = cfg.clone();
        let zellij_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            crate::zellij::run_zellij_relay_worker(zellij_cfg, zellij_shutdown).await;
        });
    }
    let coord = Arc::new(CoordinatorClient::new(cfg));

    let active_conns = Arc::new(AtomicUsize::new(0));
    let last_activity = Arc::new(Mutex::new(Instant::now()));

    let check_interval = if effective_idle_timeout.is_zero() {
        Duration::from_secs(3600)
    } else {
        (effective_idle_timeout / 4).clamp(Duration::from_millis(20), Duration::from_secs(5))
    };

    let mut ticker = tokio::time::interval(check_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::info!("Shutdown signal received; stopping sshcast-relay listener");
                    return Ok(());
                }
            }
            _ = ticker.tick(), if !effective_idle_timeout.is_zero() => {
                if active_conns.load(Ordering::Acquire) == 0 {
                    let elapsed = last_activity.lock().await.elapsed();
                    if elapsed >= effective_idle_timeout {
                        tracing::info!(
                            "Idle timeout ({:?}) reached with 0 active connections; exiting cleanly to 0 MB RSS",
                            effective_idle_timeout
                        );
                        return Ok(());
                    }
                }
            }
            accept_res = listener.accept() => {
                let (stream, _addr) = match accept_res {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!("UnixListener accept error: {}", e);
                        continue;
                    }
                };

                let peer = match verify_peer_cred(&stream, expected_uid) {
                    Ok(p) => p,
                    Err(reason) => {
                        tracing::warn!("Rejected Unix socket connection: {}", reason);
                        continue;
                    }
                };

                active_conns.fetch_add(1, Ordering::AcqRel);
                *last_activity.lock().await = Instant::now();

                let t_proc = Instant::now();
                let proc_ctx = inspect_process_context(&hostname, peer.uid, peer.pid);
                tracing::info!(
                    "Accepted agent connection (pid={}, comm={}, ancestors={}, proc_inspect_ms={})",
                    proc_ctx.pid,
                    proc_ctx.comm,
                    proc_ctx.ancestors.len(),
                    t_proc.elapsed().as_millis()
                );
                let coord_clone = Arc::clone(&coord);
                let active_clone = Arc::clone(&active_conns);
                let last_act_clone = Arc::clone(&last_activity);

                tokio::spawn(async move {
                    if let Err(e) = handle_agent_session(stream, coord_clone, proc_ctx).await {
                        tracing::debug!("Agent session ended with error: {}", e);
                    }
                    *last_act_clone.lock().await = Instant::now();
                    active_clone.fetch_sub(1, Ordering::AcqRel);
                });
            }
        }
    }
}

/// Top-level entry point for `sshcast-relay run`: uses `systemd` socket activation if available,
/// or binds `cfg.socket_path` directly.
pub async fn run_daemon(cfg: RelayConfig) -> Result<()> {
    let (listener, is_socket_activated) = match take_systemd_socket()? {
        Some(l) => {
            tracing::info!(
                "Started sshcast-relay via systemd socket activation (node_id={}, idle_timeout={}s)",
                cfg.grant.node_id,
                cfg.idle_timeout_secs
            );
            (l, true)
        }
        None => {
            let l = bind_standalone_socket(&cfg.socket_path)?;
            tracing::info!(
                "Started sshcast-relay listening on {} (node_id={}, idle_timeout={}s)",
                cfg.socket_path.display(),
                cfg.grant.node_id,
                cfg.idle_timeout_secs
            );
            (l, false)
        }
    };

    let socket_path = cfg.socket_path.clone();
    let idle_timeout = Duration::from_secs(cfg.idle_timeout_secs);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(ref mut s) = sigterm {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
        let _ = shutdown_tx.send(true);
    });

    let res = serve_with_listener(listener, cfg, idle_timeout, shutdown_rx).await;

    // Only unlink the socket file on exit if we bound it standalone (not managed by systemd.socket)
    if !is_socket_activated {
        let _ = std::fs::remove_file(&socket_path);
    }

    res
}
