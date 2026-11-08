# Sockcast (`sockcast`) — Roaming SSH Agent Architecture & Specification

## 1. Problem Statement & Motivation
When working across remote Linux servers (`Server X`, `Server Y`) inside persistent terminal multiplexers like **Zellij** or **tmux** (both via CLI SSH and the **Zellij HTTPS Web Terminal**), traditional SSH agent forwarding (`ssh -A`) breaks down:
1. **Stale `SSH_AUTH_SOCK` paths:** Reconnecting via SSH creates a new ephemeral socket in `/tmp/ssh-XXXX/agent.YYYY`, leaving existing shells inside Zellij pointing to dead sockets.
2. **HTTPS / Web Terminals:** Connecting to Zellij via its built-in HTTPS web server provides no SSH transport at all, meaning no local agent can be forwarded via standard SSH channels.
3. **Server-to-Server Transfers:** Workflows like building an RPM on `Server X` and running `scp` or `rsync` directly to `Server Y` fail without an active, reachable SSH agent on `Server X`.
4. **Security of `ssh -A`:** Standard agent forwarding exposes the socket to silent misuse without telling the user *which* host, process tree, or target SSH user triggered a signature request.

### Solution Overview
Decouple `SSH_AUTH_SOCK` from the SSH connection lifecycle by building **Sockcast**, a 3-tier out-of-band SSH Agent Router designed to traverse restrictive firewalls, Nginx reverse proxies, and Cloudflare edges over standard HTTPS/HTTP2 (port 443):

1. **Target Host Relay (`sockcast-relay` — Rust):** Ultra-low-footprint user-session daemon listening on a static Unix socket (`/run/user/$UID/sockcast.sock`), socket-activated via `systemd --user` with a 15-minute warm idle timeout. Extracts deep caller process ancestry (`/proc/$PID`), parses the SSH signing payload (RFC 4252), cryptographically signs the request with its node Ed25519 key, and forwards it over gRPC to `sockcast-server`.
2. **Stateless Coordinator Server (`sockcast-server` — Go):** Distributed, zero-database active-active gRPC relay servers that can run behind Cloudflare or Nginx (`h2c` HTTP/2 backend listener or direct TLS). Multi-user partitioned from day 1 (`user_id`), maintaining persistent bidirectional gRPC streams to each user's workstations and routing requests with a fast 1.5s `SignAck` failover mechanism.
3. **Workstation GUI & CLI Client (`sockcast-client` — Rust + `egui`/`tray-icon`):** Single-binary cross-platform desktop app (macOS, Windows, Linux) that tracks user activity, verifies end-to-end relay signatures, filters exported local SSH keys, pops a native `egui` approval window (showing verified hostname, target SSH username, and up to 6 levels of process ancestry), and bridges approved requests to the local OS SSH agent.

---

## 2. System Architecture

```
+-------------------------------------------------------------------------+
| Target Server X (Linux User Session)                                    |
|                                                                         |
|  [Zellij Pane: scp pkg.rpm server-y:/tmp]                               |
|         |                                                               |
|         | (Unix Socket: /run/user/1000/sockcast.sock)                   |
|         v                                                               |
|  [sockcast-relay (Rust)]                                                |
|    - systemd --user socket-activated (stays warm 15m, then exits to 0B) |
|    - Walks /proc/<pid> ancestry (up to 6 levels) via SO_PEERCRED        |
|    - Parses RFC 4252 SSH_MSG_USERAUTH_REQUEST (target SSH user)         |
|    - Signs SignRequest end-to-end with Relay Ed25519 Private Key        |
+---------+---------------------------------------------------------------+
          |
          | Outbound gRPC over HTTPS (Port 443)
          | Traverses Firewalls / Cloudflare / Nginx (grpc_pass -> h2c)
          | Happy-Eyeballs / Failover across configured sockcast-servers
          v
+-------------------------------------------------------------------------+
| Coordinator Tier: sockcast-server (Go - Active-Active, Stateless)       |
|   - Partitioned by user_id (Multi-user ready)                           |
|   - Listens on h2c (behind Nginx/Cloudflare) or native TLS              |
|   - Verifies Ed25519 NodeGrants (no reliance on edge TLS client certs)  |
|                                                                         |
|   +-------------------+   +-------------------+   +-------------------+ |
|   | sockcast-server-1 |   | sockcast-server-2 |   | sockcast-server-3 | |
|   +---------+---------+   +---------+---------+   +---------+---------+ |
+-------------|-----------------------|-----------------------|-----------+
              ^                       ^                       ^
              |                       |                       |
              +-----------------------+-----------------------+
              | Persistent Outbound Bidirectional gRPC Streams (All servers)
              | 25s application heartbeats keep Cloudflare/Nginx streams warm
              | Fast 1.5s SignAck receipt + automatic workstation failover
              |
+-------------+-----------------------------------------------------------+
| Workstation (macOS / Windows / Linux Desktop)                           |
|                                                                         |
|  [sockcast-client (Rust: eframe/egui + tray-icon)]                      |
|    1. Verifies Relay NodeGrant + end-to-end SignRequest signature       |
|    2. Evaluates session trust rules or pops native egui Approval UI:    |
|       - [Approve Once]                                                  |
|       - [Approve <tool> on <host> for 15m]                              |
|       - [Approve all on <host> for 15m]                                 |
|       - [Deny]                                                          |
|    3. Bridges to Local OS SSH Agent (with optional key filtering):      |
|       - macOS / Linux: Unix Socket ($SSH_AUTH_SOCK / 1Password / GPG)   |
|       - Windows: Named Pipe (\\.\pipe\openssh-ssh-agent)                |
+-------------------------------------------------------------------------+
```

---

## 3. Component Specifications

### Tier 1: Target Host Relay (`sockcast-relay` — Rust)
Designed for minimal memory (~2 MB RSS when active, **0 MB RSS** when idle) and zero maintenance across Linux servers.

* **Key Crates:**
  * `ssh-agent-lib`: Async implementation of the SSH Agent protocol (`Session` trait).
  * `tokio`: Async runtime (`net`, `io-util`, `sync`, `time`, `signal`).
  * `listenfd`: Supports `systemd --user` socket activation.
  * `tonic` + `prost` + `rustls`: gRPC HTTP/2 client over TLS (compatible with Cloudflare/Nginx TLS termination) and cleartext `h2c` for local testing.
  * `ed25519-dalek`: Ed25519 request signing and enrollment bundle parsing.
* **Core Responsibilities:**
  1. **Socket Activation & 15-Minute Idle Timeout:**
     * Listens on `/run/user/$UID/sockcast.sock` (`%t/sockcast.sock` in systemd).
     * Shell profiles (`~/.bashrc`, `~/.zshrc`, `~/.config/fish/config.fish`) set `export SSH_AUTH_SOCK="/run/user/$(id -u)/sockcast.sock"`.
     * When woken by `systemd --user` on socket traffic, `sockcast-relay` stays warm for a configurable idle period (default `15m`) to reuse open HTTP/2 gRPC connections and in-memory key caches across back-to-back `scp`/`rsync`/`git` commands. After 15 minutes of inactivity, it exits cleanly with code `0`, dropping memory usage to zero until the next command arrives.
  2. **Deep Process Ancestry Extraction (`SO_PEERCRED` + `/proc`):**
     * On `UnixListener::accept()`, calls `stream.peer_cred()` to obtain `uid`, `gid`, and `pid`.
     * Verifies `uid` matches the relay's own UID.
     * Walks `/proc/<pid>/stat`, `/proc/<pid>/comm`, `/proc/<pid>/cmdline`, and `/proc/<pid>/cwd` up to **6 parent levels** (stopping at `pid <= 1` or session root) to capture the full process tree (e.g., `zellij-server` $\rightarrow$ `zsh` $\rightarrow$ `scp pkg.rpm server-y:/tmp` $\rightarrow$ `ssh server-y scp -t /tmp`).
  3. **RFC 4252 SSH Payload Parsing:**
     * Parses the `data` buffer inside `SSH2_AGENTC_SIGN_REQUEST`. When packet type `50` (`SSH_MSG_USERAUTH_REQUEST`) is detected, extracts:
       * `session_id`
       * `target_username` (the remote Linux user being authenticated as, e.g., `pavel` or `root`)
       * `service_name` (e.g., `ssh-connection`)
       * `pubkey_algorithm` (e.g., `ssh-ed25519`, `rsa-sha2-512`)
  4. **Public Key Caching (`SSH2_AGENTC_REQUEST_IDENTITIES`):**
     * Caches the user's filtered public keys in memory (with a configurable TTL, e.g., 60s) and persists a fallback cache at `~/.cache/sockcast/pubkeys.json` so `ssh-add -L` and initial SSH key negotiation succeed instantaneously.
  5. **End-to-End Signed `SignRequest`:**
     * Packages the key blob, challenge data, signing flags, extracted `ProcessContext`, parsed `SshAuthContext`, timestamp, and request ID, and signs the canonical request payload with the relay's Ed25519 private key.
     * Dispatches to configured `sockcast-server` endpoints with automatic failover.
  6. **Hardening, RPM Packaging & One-Step Enrollment (`sockcast-relay init`):**
     * Rejects mutating agent operations (`AddIdentity`, `RemoveIdentity`, `RemoveAllIdentities`, `Lock`, `Unlock`) with `SSH_AGENT_FAILURE`.
     * Packaged as a Fedora RPM (buildable via `tito`) installing `/usr/bin/sockcast-relay`, `/usr/lib/systemd/user/sockcast-relay.{socket,service}`, and `/etc/profile.d/sockcast-relay.sh`.
     * Provides `sockcast-relay init --bundle <base64_bundle>` to write `~/.config/sockcast/relay.toml` (`0600`), install `~/.config/systemd/user/sockcast-relay.{socket,service}` only if the global `/usr/lib/systemd/user/` RPM units are absent, enable the socket (`systemctl --user enable --now sockcast-relay.socket`), and check `loginctl enable-linger`.

---

### Tier 2: Stateless Coordinator Cluster (`sockcast-server` — Go)
Designed to run behind Nginx (`grpc_pass`) and Cloudflare on tiny VMs or containers with zero database dependencies and instant restartability.

* **Why Stateless Active-Active + `h2c`:**
  * Running behind Nginx or Cloudflare on port 443 allows `sockcast-relay` to work from restricted networks where arbitrary outbound ports are blocked.
  * `sockcast-server` listens on cleartext HTTP/2 (`golang.org/x/net/http2/h2c`) when behind a reverse proxy, or native TLS when exposed directly.
  * Each workstation (`sockcast-client`) maintains lightweight bidirectional gRPC streams to **all** coordinator servers simultaneously, sending a `WorkstationStatus` heartbeat every **25 seconds** (preventing Cloudflare's 100-second HTTP/2 idle timeout from dropping the stream).
* **Multi-User Partitioning:**
  * All in-memory routing state is partitioned by `user_id` (`map[string]*UserHub`).
  * In Milestone 1, allowed `user_pubkey` roots are loaded from `server.toml` (or CLI flags). Milestone 2/3 can add dynamic user registration without changing any wire protocols or routing logic.
* **Routing & Fast 1.5s `SignAck` Failover Logic:**
  1. **Workstation Selection:**
     * When a `SignRequest` arrives for `user_id`, `sockcast-server` orders the user's connected workstations by `force_active == true` first, then by highest `last_input_epoch_ms`.
  2. **Two-Phase Delivery (`SignAck` + `SignResponse`):**
     * `sockcast-server` pushes `SignRequest` down the primary workstation's stream and starts a **1.5-second `SignAck` timer**.
     * As soon as `sockcast-client` receives the frame (before the human clicks anything), it automatically replies with `SignAck { request_id }`.
     * **Fast Failover:** If `SignAck` does not arrive within 1.5s (e.g., laptop lid was just closed and TCP keepalive hasn't expired yet), `sockcast-server` immediately fails over and dispatches `SignRequest` to the next active workstation.
     * **Human Approval Wait:** Once `SignAck` is received, `sockcast-server` waits up to **60 seconds** for `SignResponse` (human approval or policy auto-approval). If another workstation reports newer user input activity while a prompt is still awaiting human action, `sockcast-server` can also forward the prompt there and cancel whichever prompt isn't answered first.
  3. **Per-User Public Key Cache:**
     * Each coordinator caches the latest `repeated PublicKey` pushed by a user's workstation in memory so `GetIdentities` from newly woken relays succeeds immediately even if all workstations are temporarily offline/asleep.
  4. **Fedora RPM & Systemd Deployment:**
     * Packaged as a Fedora RPM (buildable via `tito`) installing `/usr/bin/sockcast-server`, `/usr/lib/systemd/system/sockcast-server.service` (hardened with `DynamicUser=yes`), and `%config(noreplace) /etc/sockcast/server.toml`.

---

### Tier 3: Workstation GUI & CLI Client (`sockcast-client` — Rust)
Single-binary cross-platform system tray application (`eframe`/`egui` + `tray-icon`) and enrollment CLI for **macOS**, **Windows**, and **Linux**.

* **Key Crates:**
  * `eframe` / `egui`: Pure Rust native GPU/software-rendered GUI for the approval popup modal and settings/key-filter window (zero Node.js/WebView runtime bloat).
  * `tray-icon` + `muda`: Cross-platform system tray / macOS menu bar icon and context menu.
  * `tonic` + `prost` + `rustls`: Multi-coordinator gRPC bidirectional streaming client with exponential backoff and 25s heartbeats.
  * `ed25519-dalek`: Root key management, `NodeGrant` signing, and end-to-end verification of incoming `SignRequest`s.
* **OS Local SSH Agent Integration & Key Filtering:**
  * **macOS & Linux:** Connects via `tokio::net::UnixStream` to `$SSH_AUTH_SOCK` (or a configured socket path such as 1Password `~/.1password/agent.sock`, GPG agent, or Secretive).
  * **Windows:** Connects via Windows Named Pipe `\\.\pipe\openssh-ssh-agent` (`tokio::net::windows::named_pipe::ClientOptions`), compatible with Windows OpenSSH Agent, 1Password for Windows, and Pageant/WinCrypt bridges.
  * **Key Filtering:** Allows the user (via `client.toml` or the tray Settings UI) to select or filter which local SSH keys (by fingerprint or comment substring) are exported to remote `sockcast-relay` instances—preventing OpenSSH `Too many authentication failures` (`MaxAuthTries`) when the local agent holds many unrelated keys.
* **Presence Detection:**
  * Queries OS idle time (`CGEventSourceSecondsSinceLastEventType` on macOS, `GetLastInputInfo` on Windows, X11/Wayland/manual fallback on Linux) plus a tray menu override (`Force Active Here`) and pushes `WorkstationStatus` heartbeats every 25s (and immediately upon waking from idle).
* **Approval Policy & Native `egui` Prompt:**
  * Before showing any UI, `sockcast-client` cryptographically verifies:
    1. The relay's `NodeGrant` signature against the user's `user_pubkey` (`role == "relay"`).
    2. That `ProcessContext.hostname` matches the `NodeGrant.node_id`.
    3. The `SignRequest` signature against the relay's `node_pubkey`.
  * **Interactive Approval Modal Displays:**
    * **Verified Source Host:** `server-x.infra.local` (cryptographically bound to relay key)
    * **Target SSH User:** `pavel` (parsed from RFC 4252 `SSH_MSG_USERAUTH_REQUEST`)
    * **Primary Tool & Command:** `scp pkg.rpm server-y:/tmp`
    * **Process Ancestry Tree:** `zellij` (`1402`) $\rightarrow$ `zsh` (`1890`) $\rightarrow$ `scp` (`41890`) $\rightarrow$ `ssh` (`41892`)
    * **Working Directory:** `/home/pavel/rpmbuild/RPMS/x86_64`
    * **SSH Key:** `SHA256:xxxx... (ed25519 - pavel@workstation)`
  * **Approval Actions:**
    1. **`[Approve Once]`**: Signs this single request.
    2. **`[Approve <tool> on <host> for 15m]`**: Caches an in-memory approval rule matching `(verified_source_host, caller_tool_binary, key_blob, target_ssh_user)` for 15 minutes (e.g., allows subsequent `scp` commands on `server-x` for 15m without prompting, while still prompting if `git` or `ssh` is invoked directly).
    3. **`[Approve all on <host> for 15m]`**: Approves any signing request for this key from `verified_source_host` for 15 minutes.
    4. **`[Deny]`**: Immediately returns `approved = false`, causing `sockcast-relay` to return `SSH_AGENT_FAILURE`.

---

## 4. Security & Cryptographic Model (Zero-Trust Edge)

Because `sockcast-server` can run behind TLS-terminating reverse proxies like **Cloudflare** and **Nginx** (which strip transport-layer X.509 client certificates before forwarding `h2c` to the Go backend), authentication and integrity are enforced at the **application layer using Ed25519**:

1. **User Root Keypair (`user_privkey` / `user_pubkey`):**
   * Generated once on the user's primary workstation via `sockcast-client keygen`.
   * `user_pubkey` (32 bytes, encoded as `sc_user_<base58/base64>`) uniquely identifies the user tenant on `sockcast-server`.
   * `sockcast-server` only needs `user_pubkey` (no private keys are ever stored on `sockcast-server`).
2. **Signed `NodeGrant` Certificates:**
   * To enroll a remote Linux server (`sockcast-relay`) or workstation (`sockcast-client`), the user runs:
     ```bash
     sockcast-client grant-relay --node server-x.infra.local --server https://sockcast.example.com
     ```
   * This generates a fresh Ed25519 keypair (`node_privkey`, `node_pubkey`) for that node and signs a `NodeGrant` structure using `user_privkey`:
     * `user_id` / `user_pubkey`
     * `node_id` (e.g., `"server-x.infra.local"` or `"macbook-pro"`)
     * `role` (`NODE_ROLE_RELAY` or `NODE_ROLE_CLIENT`)
     * `node_pubkey` (32-byte Ed25519 public key)
     * `issued_at_unix_sec`, `expires_at_unix_sec`
     * `user_signature` (64-byte Ed25519 signature over the canonical grant fields)
3. **Request-Level & End-to-End Verification:**
   * **RPC Authentication:** Every gRPC call (`GetIdentities`, `Sign`, `ConnectWorkstation`) carries the caller's `NodeGrant` plus a timestamped authentication signature signed by `node_privkey`. `sockcast-server` verifies both the `user_signature` on the `NodeGrant` and the `node_signature` on the RPC.
   * **End-to-End Relay-to-Workstation Verification:** Every `SignRequest` includes the relay's `NodeGrant` and an Ed25519 `relay_signature` over `(request_id, timestamp, key_blob, data, flags, process_context)`.
   * Even if `sockcast-server`, Nginx, or Cloudflare were completely compromised, an attacker **cannot** forge a `SignRequest`, alter the `data` challenge being signed, or spoof `ProcessContext.hostname` because `sockcast-client` independently verifies the relay's `NodeGrant` and `relay_signature` against `user_pubkey` before displaying the prompt or accessing the local SSH agent.

---

## 5. Wire Protocol Specification (`sockcast-proto/proto/sockcast/v1/sockcast.proto`)

```protobuf
syntax = "proto3";
package sockcast.v1;

option go_package = "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1;sockcastv1";

enum NodeRole {
  NODE_ROLE_UNSPECIFIED = 0;
  NODE_ROLE_RELAY = 1;
  NODE_ROLE_CLIENT = 2;
}

// Signed by the User's Root Ed25519 private key.
message NodeGrant {
  string user_id = 1;               // Derived from or paired with user_pubkey
  bytes user_pubkey = 2;            // 32-byte Ed25519 user root public key
  string node_id = 3;               // e.g. "server-x.infra.local" or "macbook-pro"
  NodeRole role = 4;                // RELAY or CLIENT
  bytes node_pubkey = 5;            // 32-byte Ed25519 node public key
  uint64 issued_at_unix_sec = 6;
  uint64 expires_at_unix_sec = 7;   // 0 = no expiration
  bytes user_signature = 8;         // 64-byte Ed25519 signature by user_privkey
}

// Attached to RPC calls to prove possession of node_privkey.
message NodeAuth {
  NodeGrant grant = 1;
  uint64 timestamp_unix_ms = 2;
  bytes nonce = 3;
  bytes node_signature = 4;         // Signs ("sockcast-rpc-auth-v1" || timestamp || nonce)
}

message PublicKey {
  bytes key_blob = 1;
  string comment = 2;
  string fingerprint_sha256 = 3;
  string key_type = 4;              // e.g. "ssh-ed25519"
}

message ProcessAncestor {
  uint32 pid = 1;
  string comm = 2;                  // e.g. "scp", "zsh", "zellij"
  string cmdline = 3;               // e.g. "scp pkg.rpm server-y:/tmp"
}

message ProcessContext {
  string hostname = 1;              // Must match NodeGrant.node_id
  uint32 uid = 2;
  uint32 pid = 3;
  string comm = 4;                  // Direct caller binary, e.g. "ssh"
  string cmdline = 5;               // Direct caller cmdline
  string cwd = 6;                   // Working directory from /proc/<pid>/cwd
  repeated ProcessAncestor ancestors = 7; // Up to 6 parent levels
}

// Extracted from RFC 4252 SSH_MSG_USERAUTH_REQUEST (packet type 50) if present.
message SshAuthContext {
  bool is_userauth_request = 1;
  string target_username = 2;       // e.g. "pavel" or "root"
  string service_name = 3;          // e.g. "ssh-connection"
  string pubkey_algorithm = 4;      // e.g. "ssh-ed25519"
  bytes session_id = 5;
}

// 1. Relay -> Server: Fetch cached public keys for this user
message GetIdentitiesRequest {
  NodeAuth auth = 1;
}

message GetIdentitiesResponse {
  repeated PublicKey keys = 1;
}

// 2. Relay -> Server -> Client: Request cryptographic signature
message SignRequest {
  string request_id = 1;
  uint64 timestamp_unix_ms = 2;
  bytes key_blob = 3;
  bytes data = 4;                   // Raw SSH challenge payload to sign
  uint32 flags = 5;                 // SSH_AGENT_RSA_SHA2_256 (2), SSH_AGENT_RSA_SHA2_512 (4)
  ProcessContext process_context = 6;
  SshAuthContext ssh_auth_context = 7;
  NodeGrant relay_grant = 8;        // Verified end-to-end by sockcast-client
  bytes relay_signature = 9;        // Ed25519 signature by relay's node_privkey over fields 1..7
}

message SignResponse {
  string request_id = 1;
  bool approved = 2;
  bytes signature_blob = 3;         // Raw SSH wire format signature
  string error_message = 4;
  string handled_by_node_id = 5;
}

// 3. Bidirectional Stream: Client <-> Server
message WorkstationStatus {
  uint64 last_input_epoch_ms = 1;
  bool force_active = 2;
  string os = 3;                    // "macos", "windows", "linux"
  repeated PublicKey keys = 4;      // Filtered local public keys
}

// Immediate automated receipt sent by sockcast-client within <1.5s of receiving SignRequest
message SignAck {
  string request_id = 1;
}

message CancelSignRequest {
  string request_id = 1;
  string reason = 2;                // e.g. "Handled by another workstation" or "Relay timed out"
}

message ClientStreamMessage {
  oneof payload {
    NodeAuth auth_handshake = 1;    // Sent as first message on stream open
    WorkstationStatus status = 2;   // Sent every 25s and on activity/key changes
    SignAck sign_ack = 3;           // Sent immediately when SignRequest arrives
    SignResponse sign_response = 4; // Sent after policy auto-approve or user UI decision
  }
}

message ServerStreamMessage {
  oneof payload {
    SignRequest sign_request = 1;
    CancelSignRequest cancel_sign_request = 2;
    uint64 server_heartbeat_epoch_ms = 3;
  }
}

service SockcastService {
  // Called by sockcast-relay
  rpc GetIdentities(GetIdentitiesRequest) returns (GetIdentitiesResponse);
  rpc Sign(SignRequest) returns (SignResponse);

  // Persistent bidirectional stream maintained by sockcast-client
  rpc ConnectWorkstation(stream ClientStreamMessage) returns (stream ServerStreamMessage);
}
```

---

## 6. Multi-Repository Layout & Implementation Roadmap

Each component lives in its own independent repository under `/home/stingray/m/`:

```
/home/stingray/m/
├── sockcast-proto/                 # Repo 1: Shared Protobuf + Dual Rust Crate & Go Module
│   ├── Cargo.toml                  # Rust crate exported to sockcast-relay & sockcast-client
│   ├── build.rs                    # tonic-build codegen for Rust
│   ├── src/                        # Rust Ed25519 NodeGrant crypto, RFC 4252 parser, Enrollment bundle codec
│   ├── go.mod                      # Go module exported to sockcast-server
│   ├── proto/
│   │   └── sockcast/v1/sockcast.proto
│   ├── gen/go/sockcast/v1/         # Generated Go protobuf & gRPC definitions
│   └── pkg/auth/                   # Shared Go Ed25519 NodeGrant & NodeAuth verification
│
├── sockcast-server/                # Repo 2: Stateless Active-Active Coordinator (Go)
│   ├── .tito/                      # tito release & build configuration
│   ├── sockcast-server.spec        # Fedora RPM spec file
│   ├── systemd/                    # sockcast-server.service & default server.toml
│   ├── go.mod                      # Depends on sockcast-proto
│   ├── cmd/sockcast-server/        # Coordinator binary (h2c + TLS listeners)
│   └── internal/
│       └── hub/                    # Multi-user workstation registry, 1.5s SignAck failover, pubkey cache
│
├── sockcast-relay/                 # Repo 3: Target Linux Host Daemon (Rust)
│   ├── .tito/                      # tito release & build configuration
│   ├── sockcast-relay.spec         # Fedora RPM spec file
│   ├── systemd/                    # /usr/lib/systemd/user/sockcast-relay.{socket,service} & profile.d
│   ├── Cargo.toml                  # Depends on sockcast-proto
│   ├── src/                        # /proc inspector, systemd socket activation, 15m idle timer, SSH agent session
│   └── doc/
│       └── roaming_ssh_agent_architecture_spec.md
│
└── sockcast-client/                # Repo 4: Workstation GUI & Enrollment CLI (Rust)
    ├── Cargo.toml                  # Depends on sockcast-proto
    └── src/                        # eframe/egui + tray-icon UI, local OS agent bridge, CLI (keygen, grant-*)
```

### Phase 1: Shared Protocol, Crypto & Enrollment (`sockcast-proto`)
- [x] Initialize `/home/stingray/m/sockcast-proto` with `proto/sockcast/v1/sockcast.proto`, `Cargo.toml`, and `go.mod`.
- [x] Pre-generate and commit Rust (`prost`/`tonic`) and Go (`protoc`) protobuf bindings inside `sockcast-proto` so downstream RPM builds don't require matching `protoc` versions during `%build`.
- [x] Implement `NodeGrant`, `NodeAuth`, and `SignRequest` canonical Ed25519 signing/verification in both Rust (`sockcast-proto/src`) and Go (`sockcast-proto/pkg/auth`).
- [x] Implement RFC 4252 `SSH_MSG_USERAUTH_REQUEST` payload parser in `sockcast-proto` (with unit tests).
- [x] Define the compact Base64 enrollment bundle format used by `grant-relay` and `sockcast-relay init`.

### Phase 2: Stateless Coordinator Server (`sockcast-server` in Go)
- [x] Initialize `/home/stingray/m/sockcast-server` referencing `sockcast-proto`.
- [x] Implement HTTP/2 cleartext (`h2c`) and optional TLS gRPC listener compatible with Nginx `grpc_pass` and Cloudflare (`cmd/sockcast-server/main.go`).
- [x] Implement multi-user `UserHub` registry partitioned by `user_id` (`user_pubkey`) (`internal/hub/hub.go`).
- [x] Implement `ConnectWorkstation` stream handler, per-user public key cache, and `GetIdentities` RPC (`internal/server/grpc.go`).
- [x] Implement `Sign` RPC routing with the **1.5s `SignAck` timer**, automatic secondary workstation failover, and `CancelSignRequest` cleanup (`internal/hub/hub.go` & `internal/server/grpc_test.go`).

### Phase 3: Linux Target Host Relay (`sockcast-relay` in Rust)
- [x] Initialize `/home/stingray/m/sockcast-relay` referencing `sockcast-proto`.
- [x] Implement `sockcast-relay init --bundle <...>` to write `~/.config/sockcast/relay.toml` and enable `sockcast-relay.socket` (using `/usr/lib/systemd/user/` when installed via RPM, or writing `~/.config/systemd/user/` when running standalone).
- [x] Implement `UnixListener` with systemd socket activation and configurable 15-minute idle auto-exit timer.
- [x] Implement `SO_PEERCRED` caller inspection and 6-level `/proc/<pid>` ancestor chain extraction.
- [x] Implement SSH agent protocol session forwarding `request_identities` (with local memory + disk cache) and end-to-end signed `sign` requests with multi-server failover.

### Phase 4: Workstation Client & Native GUI (`sockcast-client` in Rust)
- [ ] Initialize `/home/stingray/m/sockcast-client` referencing `sockcast-proto`.
- [ ] Implement CLI subcommands: `keygen`, `grant-relay`, `grant-client`, and `run`.
- [ ] Implement local OS SSH agent connector (`$SSH_AUTH_SOCK` Unix socket on macOS/Linux, `\\.\pipe\openssh-ssh-agent` Named Pipe on Windows) with configurable key filtering.
- [ ] Implement multi-server persistent `ConnectWorkstation` gRPC stream manager with 25s heartbeats, OS idle detection, and immediate `SignAck` reply.
- [ ] Implement end-to-end `SignRequest` signature verifier, 15-minute session rule engine (`[Approve <tool> on <host> for 15m]`, `[Approve all on <host> for 15m]`), system tray icon, and native `egui` approval popup window.

### Phase 5: Fedora RPM & `tito` Packaging (`sockcast-server` & `sockcast-relay`)
- [ ] Configure `tito` (`tito init`) and dependency vendoring (`go mod vendor` / `cargo vendor` or self-contained source archives) so `tito build --test --rpm` and `mock` / COPR offline builds succeed cleanly without external path dependencies.
- [ ] Author `sockcast-server.spec` and systemd unit files (`/usr/lib/systemd/system/sockcast-server.service`, `/etc/sockcast/server.toml`) with standard Fedora `%systemd_post` / `%systemd_preun` macros.
- [ ] Author `sockcast-relay.spec` and user systemd unit files (`/usr/lib/systemd/user/sockcast-relay.socket`, `/usr/lib/systemd/user/sockcast-relay.service`, `/etc/profile.d/sockcast-relay.sh`) with `%systemd_user_post` / `%systemd_user_preun` macros.
- [ ] Verify end-to-end `tito build --test --rpm` for both `sockcast-server` and `sockcast-relay`.
