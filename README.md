# `sockcast-relay`

Ultra-low-footprint Linux Target Host Relay daemon for the **Sockcast** Roaming SSH Agent architecture.

## Key Features
- **`systemd --user` Socket Activation & 15-Minute Idle Auto-Exit:**
  - Listens on `/run/user/$UID/sockcast.sock` (`%t/sockcast.sock`).
  - Stays warm for 15 minutes (`idle_timeout_secs = 900`) after socket activity to reuse HTTP/2 gRPC channels and in-memory key caches across back-to-back `scp` / `rsync` / `git` commands, then exits cleanly to **0 MB RSS**.
- **Deep Caller Process Ancestry (`SO_PEERCRED` + `/proc`):**
  - Verifies caller UID matches the relay UID and walks `/proc/<pid>/{stat,comm,cmdline,cwd}` up to **6 parent levels** (e.g., `zellij-server -> zsh -> scp pkg.rpm server-y:/tmp -> ssh`).
- **RFC 4252 SSH Payload Inspection & End-to-End Signing:**
  - Extracts `target_username` and `pubkey_algorithm` from `SSH_MSG_USERAUTH_REQUEST` packets and signs every `SignRequest` with the relay's Ed25519 private key.
- **One-Step Host Enrollment:**
  ```bash
  sockcast-relay init --bundle sc1_...
  ```
  Writes `~/.config/sockcast/relay.toml` (`0600`), installs `~/.config/systemd/user/sockcast-relay.{socket,service}` if global RPM units are absent, and enables `sockcast-relay.socket`.

## Building & Fedora RPM Packaging (`tito`)

```bash
# Run tests
cargo test --offline

# Build Fedora RPM via tito
tito build --test --rpm
```
