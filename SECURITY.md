# Security Policy

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues, pull requests, or discussions.

Instead, please report them privately through one of the following channels:

- **GitHub Security Advisories:** [https://github.com/sshcast/sshcast-relay/security/advisories/new](https://github.com/sshcast/sshcast-relay/security/advisories/new)
- **Email:** `security@sshcast.net`

When reporting a vulnerability, please include:
- A description of the issue and affected component(s) or version/commit.
- Reproduction steps, logs, or a minimal proof of concept.
- Potential security impact and any suggested remediation if known.

We aim to acknowledge reports promptly, keep reporters updated during triage and remediation, and coordinate public disclosure once a fix is available.

---

## Relay Security & Cryptographic Model

`sshcast-relay` is designed around a zero-trust coordinator boundary in which neither `sshcast-server` nor upstream TLS-terminating proxies (such as Nginx or Cloudflare) are trusted with private SSH keys or authorized to forge signing requests.

### 1. Local Socket Access Control (`SO_PEERCRED`)

- **Socket Permissions:** `sshcast-relay` listens on a per-user Unix domain socket (`%t/sshcast.sock`, defaulting to `/run/user/$UID/sshcast.sock`) created with mode `0600` inside a `0700` runtime directory. In standalone mode, it refuses to unlink non-socket files or overwrite an actively listening socket.
- **Kernel UID Verification:** On every accepted Unix socket connection, `verify_peer_cred` reads `SO_PEERCRED` (`uid`, `gid`, `pid`) from the kernel and rejects any caller whose UID does not match the relay's effective UID (`geteuid()`).
- **Read-Only Agent Surface:** Mutating SSH agent operations (`SSH2_AGENTC_ADD_IDENTITY`, `SSH2_AGENTC_REMOVE_IDENTITY`, `SSH2_AGENTC_REMOVE_ALL_IDENTITIES`, `SSH_AGENTC_LOCK`, `SSH_AGENTC_UNLOCK`, smartcard operations, and extensions) are unconditionally rejected with `SSH_AGENT_FAILURE`.

### 2. Caller Process Ancestry Inspection (`/proc`)

- Using the kernel-verified caller `pid` from `SO_PEERCRED`, `inspect_process_context` reads `/proc/<pid>/{stat,comm,cmdline,cwd}` and traverses up to 6 parent process levels (stopping at `pid <= 1`) to populate `ProcessContext`.
- For `SSH2_AGENTC_SIGN_REQUEST`, `parse_ssh_auth_context` inspects the signed payload for RFC 4252 `SSH_MSG_USERAUTH_REQUEST` (message type `50`) to extract `target_username`, `service_name`, `pubkey_algorithm`, and `session_id`.
- **Trust Boundary Note:** Same-UID processes on the relay host share user privileges and can influence their own `argv`/working directory before connecting to `SSH_AUTH_SOCK`. Accordingly, `ProcessContext` serves as rich audit and workstation approval context, while `SO_PEERCRED` establishes the calling UID/PID and end-to-end Ed25519 signatures bind the relay identity (`NodeGrant.node_id`) and exact challenge bytes.

### 3. End-to-End Ed25519 Signing Model

- **Relay Identity & Configuration (`0600`):** Enrollment (`sshcast-relay init --bundle sc1_...`) stores the relay's 32-byte Ed25519 private seed and user-signed `NodeGrant` (`NODE_ROLE_RELAY`, domain `sshcast-node-grant-v1`, optionally accompanied by an operator-signed `UserCert` under `sshcast-user-cert-v1`) in `~/.config/sshcast/relay.toml` with `0600` permissions.
- **Per-RPC Authentication (`NodeAuth`):** Outbound `GetIdentities` and `Sign` calls authenticate to `sshcast-server` with a `NodeAuth` token signed by the relay's Ed25519 key (`sshcast-rpc-auth-v1` over the grant signature, millisecond timestamp, and a 16-byte random nonce).
- **End-to-End `SignRequest` Signature:** Every `SignRequest` is signed end-to-end by the relay's Ed25519 key (`sshcast-sign-request-v1`) across `request_id`, `timestamp_unix_ms`, `key_blob`, `data`, `flags`, `process_context`, `ssh_auth_context`, and the relay grant's `user_signature`.
- **Verification on `sshcast-client`:** Before displaying an approval prompt or accessing the local OS SSH agent, the workstation client independently verifies the relay `NodeGrant` against the user's root public key, verifies `process_context.hostname == relay_grant.node_id`, and verifies `relay_signature`. A compromised coordinator or reverse proxy cannot tamper with challenge data or spoof the originating host.
- **Optional Zellij Web P2P Tunneling:** When explicitly enabled (`zellij_enabled = true`), P2P tunnel offers and answers are mutually signed (`sshcast-zellij-frame-v1`) by the enrolled client and relay Ed25519 keys, and tunnel payloads are encrypted using session keys derived from the signed handshake.
- **Transport Security:** Coordinator endpoints using `https://` enable TLS verification against system root certificates (`tonic`/`rustls`); cleartext `http://` (`h2c`) should only be used on loopback or trusted local transports.

---

## Release & Build Provenance Verification

Official `sshcast-relay` release artifacts and Fedora RPMs published via GitHub Releases ([https://github.com/sshcast/sshcast-relay/releases](https://github.com/sshcast/sshcast-relay/releases)) can be verified before installation:

1. **SHA256 Checksum Verification:**
   Download the release artifact alongside `SHA256SUMS` from the release page and verify:
   ```bash
   sha256sum -c SHA256SUMS --ignore-missing
   ```

2. **GitHub Build Provenance Attestation:**
   Verify SLSA/GitHub Actions build provenance using the [GitHub CLI](https://cli.github.com/):
   ```bash
   gh attestation verify <artifact-file> --repo sshcast/sshcast-relay
   ```

3. **Reproducible Local Verification:**
   You can also build and test directly from a verified git tag or source tarball using locked dependencies:
   ```bash
   cargo test --offline
   cargo build --release --locked
   ```
