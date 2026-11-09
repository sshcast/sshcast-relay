# Upstream Zellij PR Notes

This document records two upstream Zellij issues discovered while integrating `zellij web` with `sockcast-relay`, along with exact file/line locations and proposed fixes for submitting upstream pull requests.

---

## 1. Isolate `zellij --server` Sessions in Their Own `systemd --user` Scope

### Problem
When a Zellij client (`zellij` CLI or `zellij web`) creates or resurrects a session, it spawns `zellij --server <socket_path>` via `zellij-client/src/server_launch.rs`. Inside `zellij-server/src/lib.rs` (`start_server`), the server calls `daemonize::Daemonize::new().start()` (classic Unix double-`fork()` + `setsid()`).

While double-`fork()` + `setsid()` detaches the server from its parent PID and controlling terminal, **it does not move the process out of the parent's cgroup under modern Linux `systemd` (cgroupv2)**:
1. **When `zellij --server` is spawned by `zellij web` running inside a systemd service** (with default `KillMode=control-group`), restarting or stopping that service sends `SIGTERM`/`SIGKILL` to the entire service cgroup — killing every `zellij --server` session created through the web UI and all shell panes inside them.
2. **When `zellij --server` is spawned from an SSH login session (`session-N.scope`)**, the server remains inside `session-N.scope` rather than under the user's persistent `user@<uid>.service` manager (`app.slice`), making it vulnerable to scope teardown on SSH logout if `KillUserProcesses=yes` is configured.
3. Because `zellij --server <socket_path>` requires the spawning client to connect over `<socket_path>` immediately after launch and send `ClientToServerMsg::FirstClientConnected { cli_assets, is_web_client }` (carrying layout, config, palette, and initial size), a static `zellij-session@%i.service` unit cannot trivially boot `--server` without a client handshake.

### Upstream Code Locations
- **`zellij-client/src/server_launch.rs`** (`ServerLaunch::command`, lines 53–68, and `spawn_server_with`, lines 76–97)
- **`zellij-server/src/lib.rs`** (`start_server`, lines 3277–3308)

### Proposed Upstream Fix
In `zellij-client/src/server_launch.rs`, when running on Linux under a `systemd` user manager (`std::env::var_os("XDG_RUNTIME_DIR")` has `<runtime_dir>/systemd/private`), launch `zellij --server <socket_path>` inside a transient `systemd --user --scope` unit (or fall back to direct `Command::new(&self.program)` if `systemd-run` is unavailable or fails):

```rust
// In zellij-client/src/server_launch.rs:
fn systemd_scope_command(&self) -> Option<Command> {
    #[cfg(target_os = "linux")]
    {
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")?;
        if ! std::path::Path::new(&runtime_dir).join("systemd/private").exists() {
            return None;
        }
        let session_id = self
            .socket_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("session");
        // Sanitize unit name component
        let sanitized: String = session_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let unit_name = format!("zellij-session-{}-{}", sanitized, std::process::id());

        let mut cmd = Command::new("systemd-run");
        cmd.args([
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            &format!("--unit={unit_name}"),
            "--",
        ]);
        cmd.arg(&self.program);
        cmd.args(self.args());
        cmd.envs(&self.env);
        if let Some(cwd) = &self.cwd {
            cmd.current_dir(cwd);
        }
        return Some(cmd);
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
```

Why `--scope` works seamlessly with `LaunchStyle::WaitForDaemon`:
- `systemd-run --user --scope` moves the child process into a fresh transient scope unit (`app.slice/zellij-session-<id>.scope`) managed by `systemd --user` **while still executing as a direct child of the caller**, preserving environment variables, working directory, and the `WaitForDaemon` exit-code contract when `Daemonize::new().start()` forks.
- Each Zellij session lives in its own isolated `.scope` cgroup (`systemctl --user status zellij-session-*`), completely decoupled from both `zellij web` service restarts and SSH `session-N.scope` teardown.

---

## 2. Web Client Recreates Exited Sessions on Normal Exit (`CloseFrame` Code `1000` vs `4001`)

### Problem
When a user exits the last pane in a session attached via `zellij web` (`ExitReason::Normal`), or when a session rejects web attachment (`ExitReason::WebClientsForbidden`), `handle_exit_reason` in `zellij-client/src/web_client/server_listener.rs` calls `client_connection_bus.close_connection()` (instead of `close_connection_kicked()`).

In `zellij-client/src/web_client/message_handlers.rs` (`render_to_client`, lines 164–174):
- `close_connection()` leaves `should_not_reconnect == false`, which sends WebSocket `CloseFrame { code: 1000 (NORMAL), reason: "Connection closed" }`.
- Only `close_connection_kicked()` sets `should_not_reconnect = true`, which sends WebSocket close code `4001`.

In `zellij-client/assets/app.js` (lines 3225–3231) and `zellij-client/assets/connection.js` (lines 59–99):
```javascript
wsTerminal.onclose = function (event) {
    if (event.code === 4001) {
        handleDisconnected();
    } else {
        handleReconnection();
    }
};
```
Because `handleReconnection()` checks `/info/version` and calls `window.location.reload()` on `/<session_name>`, closing a session in the web UI (or failing to attach due to `WebClientsForbidden`) causes the browser to treat the intentional session exit as a network drop, reload `/<session_name>`, and **immediately respawn/recreate the session that just exited**.

### Upstream Code Locations
- **`zellij-client/src/web_client/server_listener.rs`** (`handle_exit_reason`, lines 355–398)
- **`zellij-client/src/web_client/connection_manager.rs`** (`ClientConnectionBus::close_connection` vs `close_connection_kicked`, lines 163–210)
- **`zellij-client/src/web_client/message_handlers.rs`** (`render_to_client`, lines 164–174)
- **`zellij-client/assets/app.js`** (`wsTerminal.onclose`, lines 3225–3231)

### Proposed Upstream Fix
In `zellij-client/src/web_client/server_listener.rs` (`handle_exit_reason`), any terminal `ExitReason` from the server (`ExitReason::Normal`, `ExitReason::NormalDetached`, `ExitReason::ForceDetached`, `ExitReason::WebClientsForbidden`, `ExitReason::Error(_)`, `ExitReason::KickedByHost`) should set `should_not_reconnect` (or use a dedicated close code such as `4000` for normal session exit vs `4001` for kicked by host) so the browser does not auto-reload `/<session_name>` and resurrect/recreate an intentionally exited session.

---

## 3. `env { ... }` in `config.kdl` Ignored by `zellij web` in Zellij 0.45.1

### Problem
In Zellij 0.45.1:
- `config.env.set_vars()` (which applies `env { ... }` from `config.kdl` to the process environment via `std::env::set_var`) is only called in `zellij-client/src/lib.rs:992` (`start_client`) and `zellij-client/src/lib.rs:1646` (`start_server_detached`).
- `start_web_client` in `zellij-client/src/web_client/mod.rs` never calls `config.env.set_vars()`, and `zellij-server` in 0.45.1 simply inherits the spawning process's environment in `handle_openpty` (`zellij-server/src/os_input_output_unix.rs:228–259`).
- As a result, in Zellij 0.45.1, any session spawned from the `zellij web` launcher ignores the `env { ... }` block in `config.kdl`. (Combined with `systemd --user` services not setting `TERM` by default, panes in web-created sessions end up with an empty `TERM` unless `Environment=TERM=xterm-256color` is set on the service unit.)

### Upstream Status
Fixed on upstream `main` (post-0.45.1, commit `201c1593d`, PR `#5685`) by introducing `AppliedEnv::at_startup(config.env.inner())` in `zellij-server/src/lib.rs:5509` and passing `pane_env` directly into `handle_openpty` (`zellij-server/src/os_input_output_unix.rs:241–246`).
