# `sshcast-relay`

Ultra-low-footprint Linux Target Host Relay daemon for the **Sshcast** Roaming SSH Agent architecture.

## Key Features
- **`systemd --user` Socket Activation & 15-Minute Idle Auto-Exit:**
  - Listens on `/run/user/$UID/sshcast.sock` (`%t/sshcast.sock`).
  - Stays warm for 15 minutes (`idle_timeout_secs = 900`) after socket activity to reuse HTTP/2 gRPC channels and in-memory key caches across back-to-back `scp` / `rsync` / `git` commands, then exits cleanly to **0 MB RSS**.
- **Deep Caller Process Ancestry (`SO_PEERCRED` + `/proc`):**
  - Verifies caller UID matches the relay UID and walks `/proc/<pid>/{stat,comm,cmdline,cwd}` up to **6 parent levels** (e.g., `zellij-server -> zsh -> scp pkg.rpm server-y:/tmp -> ssh`).
- **RFC 4252 SSH Payload Inspection & End-to-End Signing:**
  - Extracts `target_username` and `pubkey_algorithm` from `SSH_MSG_USERAUTH_REQUEST` packets and signs every `SignRequest` with the relay's Ed25519 private key.
- **One-Step Host Enrollment:**
  ```bash
  sshcast-relay init --bundle sc1_...
  ```
  Writes `~/.config/sshcast/relay.toml` (`0600`), prompts before overwriting an existing config (`--force` to skip), installs `~/.config/systemd/user/sshcast-relay.{socket,service}` if global RPM units are absent, enables `sshcast-relay.socket`, and restarts `sshcast-relay.service` if already running.

## Building & Fedora RPM Packaging (`tito`)

```bash
# Run tests
cargo test --offline

# Build Fedora RPM via tito
tito build --test --rpm
```

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting (`security@sshcast.net` / [GitHub Security Advisories](https://github.com/sshcast/sshcast-relay/security/advisories/new)), the relay cryptographic model, and release provenance verification.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option. Source repository: [https://github.com/sshcast/sshcast-relay](https://github.com/sshcast/sshcast-relay).
