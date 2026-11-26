use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::SigningKey;
use prost::Message as _;
use sshcast_proto::bundle::{encode_user_cert_token, EnrollmentBundle};
use sshcast_proto::crypto::{
    derive_user_id, sign_node_grant, sign_user_cert, verify_node_auth, verify_sign_request,
    DEFAULT_MAX_CLOCK_SKEW_MS,
};
use sshcast_proto::v1::sshcast_service_server::{SshcastService, SshcastServiceServer};
use sshcast_proto::v1::{
    ClientStreamMessage, GetIdentitiesRequest, GetIdentitiesResponse, NodeAuth, NodeGrant,
    NodeRole, ProcessContext, PublicKey, RelayStreamMessage, ServerStreamMessage,
    ServerToRelayMessage, SignRequest, SignResponse, UserCert,
};
use sshcast_relay::agent::{
    read_agent_frame, write_agent_frame, SSH2_AGENTC_ADD_IDENTITY, SSH2_AGENTC_REMOVE_ALL_IDENTITIES,
    SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST, SSH2_AGENT_IDENTITIES_ANSWER,
    SSH2_AGENT_SIGN_RESPONSE, SSH_AGENTC_LOCK, SSH_AGENT_FAILURE,
};
use sshcast_relay::client::CoordinatorClient;
use sshcast_relay::config::{RelayConfig, RelayConfigFile};
use sshcast_relay::init::{run_init, InitOptions};
use sshcast_relay::listener::{bind_standalone_socket, serve_with_listener};
use sshcast_relay::proc_inspector::{
    format_cmdline, inspect_process_context_in_proc, parse_proc_stat,
};
use sshcast_relay::renew::cert_needs_renewal;
use sshcast_relay::zellij::{
    ensure_zellij_web_sharing_in_file, inject_set_cookie_into_http_response,
    parse_zellij_create_token_output, parse_zellij_list_sessions_output,
    rewrite_http_request_for_zellij_web, rewrite_websocket_normal_close_to_4001,
    try_build_sshcast_asset_http_response,
};
use std::os::unix::fs::PermissionsExt;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tonic::{Request, Response, Status, Streaming};

fn write_ssh_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

#[test]
fn test_proc_inspector_6_level_ancestry_and_stat_parsing() {
    // 1. Verify stat parsing with spaces and parentheses inside comm
    let (comm, ppid) = parse_proc_stat("4210 (zellij (server)) S 1099 4210 4210 0 -1").unwrap();
    assert_eq!(comm, "zellij (server)");
    assert_eq!(ppid, 1099);

    // 2. Verify cmdline NUL-byte formatting
    assert_eq!(
        format_cmdline(b"scp\0pkg.rpm\0server-y:/tmp\0\0"),
        "scp pkg.rpm server-y:/tmp"
    );

    // 3. Create a synthetic /proc hierarchy with 7 parent levels to verify 6-level cap
    let tmp = TempDir::new().unwrap();
    let proc_root = tmp.path();

    // Chain: 5000 (ssh) -> 4000 (scp) -> 3000 (bash) -> 2500 (zsh) -> 2000 (zellij-server) -> 1500 (systemd) -> 1200 (extra-root) -> 1100 (ignored-7th) -> 1 (init)
    let chain = [
        (5000u32, 4000u32, "ssh", "ssh\0server-y\0scp\0-t\0/tmp\0"),
        (4000, 3000, "scp", "scp\0pkg.rpm\0server-y:/tmp\0"),
        (3000, 2500, "bash", "bash\0./deploy.sh\0"),
        (2500, 2000, "zsh", "-zsh\0"),
        (2000, 1500, "zellij-server", "zellij\0--server\0"),
        (1500, 1200, "systemd", "/usr/lib/systemd/systemd\0--user\0"),
        (1200, 1100, "extra-root", "extra-root-daemon\0"),
        (1100, 1, "ignored-7th", "ignored-7th\0"),
    ];

    for (pid, ppid, comm, cmdline) in chain {
        let dir = proc_root.join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("stat"),
            format!("{pid} ({comm}) S {ppid} {pid} {pid} 0 -1\n"),
        )
        .unwrap();
        std::fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
        std::fs::write(dir.join("cmdline"), cmdline.as_bytes()).unwrap();
    }

    let workdir = tmp.path().join("rpmbuild");
    std::fs::create_dir_all(&workdir).unwrap();
    std::os::unix::fs::symlink(&workdir, proc_root.join("5000").join("cwd")).unwrap();

    let ctx = inspect_process_context_in_proc(proc_root, "server-x.infra.local", 1000, 5000);
    assert_eq!(ctx.hostname, "server-x.infra.local");
    assert_eq!(ctx.uid, 1000);
    assert_eq!(ctx.pid, 5000);
    assert_eq!(ctx.comm, "ssh");
    assert_eq!(ctx.cmdline, "ssh server-y scp -t /tmp");
    assert_eq!(ctx.cwd, workdir.to_string_lossy());

    // Must cap at exactly 6 ancestors (4000, 3000, 2500, 2000, 1500, 1200) and exclude 1100
    assert_eq!(ctx.ancestors.len(), 6);
    assert_eq!(ctx.ancestors[0].pid, 4000);
    assert_eq!(ctx.ancestors[0].comm, "scp");
    assert_eq!(ctx.ancestors[0].cmdline, "scp pkg.rpm server-y:/tmp");
    assert_eq!(ctx.ancestors[3].comm, "zellij-server");
    assert_eq!(ctx.ancestors[4].comm, "systemd");
    assert_eq!(ctx.ancestors[5].pid, 1200);
    assert_eq!(ctx.ancestors[5].comm, "extra-root");
}

#[test]
fn test_init_bundle_writes_config_and_conditional_systemd_units() {
    let tmp = TempDir::new().unwrap();
    let user_sk = SigningKey::from_bytes(&[0x11; 32]);
    let relay_sk = SigningKey::from_bytes(&[0x22; 32]);

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "server-x.infra.local".to_string(),
        role: NodeRole::Relay as i32,
        node_pubkey: relay_sk.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
        user_cert: None,
    };
    sign_node_grant(&mut grant, &user_sk);

    let bundle = EnrollmentBundle::new(
        vec!["https://coord1.example.com".to_string()],
        relay_sk.clone(),
        grant.clone(),
    );
    let token = bundle.encode().unwrap();

    // Case 1: Global RPM units do NOT exist -> installs ~/.config/systemd/user units
    let cfg_path_1 = tmp.path().join("cfg1").join("relay.toml");
    let user_systemd_1 = tmp.path().join("systemd-user-1");
    let fake_global_empty = tmp.path().join("global-empty");

    let out1 = run_init(&InitOptions {
        bundle_token: token.clone(),
        config_path: Some(cfg_path_1.clone()),
        systemd_user_dir: Some(user_systemd_1.clone()),
        global_systemd_user_dir: fake_global_empty,
        skip_systemctl: true,
        enable_zellij: false,
    })
    .unwrap();

    assert!(out1.installed_local_units);
    assert!(user_systemd_1.join("sshcast-relay.socket").exists());
    assert!(user_systemd_1.join("sshcast-relay.service").exists());
    assert!(user_systemd_1.join("sshcast-zellij-web.service").exists());

    let relay_svc_unit =
        std::fs::read_to_string(user_systemd_1.join("sshcast-relay.service")).unwrap();
    assert!(!relay_svc_unit.contains("PrivateTmp=yes"));
    assert!(relay_svc_unit.contains("KillMode=process"));

    let zellij_svc_unit =
        std::fs::read_to_string(user_systemd_1.join("sshcast-zellij-web.service")).unwrap();
    assert!(zellij_svc_unit.contains("KillMode=process"));

    let mode = std::fs::metadata(&cfg_path_1).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let loaded_cfg = RelayConfig::load(Some(&cfg_path_1)).unwrap();
    assert_eq!(loaded_cfg.grant.node_id, "server-x.infra.local");
    assert_eq!(loaded_cfg.node_signing_key.to_bytes(), relay_sk.to_bytes());
    assert!(!loaded_cfg.zellij_enabled);

    RelayConfig::set_zellij_config(Some(&cfg_path_1), true, Some(18082)).unwrap();
    let updated_cfg = RelayConfig::load(Some(&cfg_path_1)).unwrap();
    assert!(updated_cfg.zellij_enabled);
    assert_eq!(updated_cfg.zellij_web_port, 18082);

    // Case 2: Global RPM units DO exist in /usr/lib/systemd/user -> does NOT write ~/.config/systemd/user units
    let fake_global_rpm = tmp.path().join("global-rpm");
    std::fs::create_dir_all(&fake_global_rpm).unwrap();
    std::fs::write(fake_global_rpm.join("sshcast-relay.socket"), "[Socket]\n").unwrap();
    std::fs::write(fake_global_rpm.join("sshcast-relay.service"), "[Service]\n").unwrap();

    let cfg_path_2 = tmp.path().join("cfg2").join("relay.toml");
    let user_systemd_2 = tmp.path().join("systemd-user-2");

    let out2 = run_init(&InitOptions {
        bundle_token: token,
        config_path: Some(cfg_path_2),
        systemd_user_dir: Some(user_systemd_2.clone()),
        global_systemd_user_dir: fake_global_rpm,
        skip_systemctl: true,
        enable_zellij: true,
    })
    .unwrap();

    assert!(!out2.installed_local_units);
    assert!(!user_systemd_2.exists());
}

struct MockCoordinator {
    keys: Vec<PublicKey>,
    captured_sign_requests: Arc<Mutex<Vec<SignRequest>>>,
}

#[tonic::async_trait]
impl SshcastService for MockCoordinator {
    async fn get_identities(
        &self,
        request: Request<GetIdentitiesRequest>,
    ) -> Result<Response<GetIdentitiesResponse>, Status> {
        let auth = request
            .into_inner()
            .auth
            .ok_or_else(|| Status::unauthenticated("missing auth"))?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        verify_node_auth(&auth, Some(NodeRole::Relay), now_ms, DEFAULT_MAX_CLOCK_SKEW_MS)
            .map_err(|e| Status::unauthenticated(e.to_string()))?;

        Ok(Response::new(GetIdentitiesResponse {
            keys: self.keys.clone(),
        }))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        verify_sign_request(&req, now_sec)
            .map_err(|e| Status::permission_denied(format!("verify_sign_request failed: {e}")))?;

        self.captured_sign_requests.lock().unwrap().push(req.clone());

        Ok(Response::new(SignResponse {
            request_id: req.request_id,
            approved: true,
            signature_blob: b"mock-ssh-ed25519-sig-blob".to_vec(),
            error_message: String::new(),
            handled_by_node_id: "test-workstation".to_string(),
        }))
    }

    type ConnectWorkstationStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ServerStreamMessage, Status>> + Send>>;

    async fn connect_workstation(
        &self,
        _request: Request<Streaming<ClientStreamMessage>>,
    ) -> Result<Response<Self::ConnectWorkstationStream>, Status> {
        Err(Status::unimplemented("not used in relay test"))
    }

    type ConnectRelayStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ServerToRelayMessage, Status>> + Send>>;

    async fn connect_relay(
        &self,
        _request: Request<Streaming<RelayStreamMessage>>,
    ) -> Result<Response<Self::ConnectRelayStream>, Status> {
        Err(Status::unimplemented("not used in agent test"))
    }
}

#[tokio::test]
async fn test_end_to_end_agent_session_failover_and_idle_timeout() {
    let tmp = TempDir::new().unwrap();
    let user_sk = SigningKey::from_bytes(&[0x44; 32]);
    let relay_sk = SigningKey::from_bytes(&[0x55; 32]);

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "server-x.infra.local".to_string(),
        role: NodeRole::Relay as i32,
        node_pubkey: relay_sk.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
        user_cert: None,
    };
    sign_node_grant(&mut grant, &user_sk);

    let captured = Arc::new(Mutex::new(Vec::new()));
    let mock_svc = MockCoordinator {
        keys: vec![PublicKey {
            key_blob: b"ssh-ed25519-test-blob".to_vec(),
            comment: "pavel@workstation".to_string(),
            fingerprint_sha256: "SHA256:testfp".to_string(),
            key_type: "ssh-ed25519".to_string(),
        }],
        captured_sign_requests: Arc::clone(&captured),
    };

    // Start mock gRPC coordinator server on an ephemeral port
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(tcp_listener);
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(SshcastServiceServer::new(mock_svc))
            .serve_with_incoming(incoming)
            .await;
    });

    let sock_path = tmp.path().join("sshcast.sock");
    let pubkey_cache_path = tmp.path().join("pubkeys.json");

    // Configure relay with a dead first coordinator URL (to verify automatic failover to server 2)
    let cfg = RelayConfig {
        servers: vec![
            "http://127.0.0.1:1".to_string(), // Closed port -> triggers failover
            format!("http://{}", server_addr),
        ],
        node_signing_key: relay_sk,
        grant,
        socket_path: sock_path.clone(),
        idle_timeout_secs: 1,
        key_cache_ttl_secs: 60,
        pubkey_cache_path: pubkey_cache_path.clone(),
        connect_timeout_ms: 250,
        sign_timeout_secs: 5,
        zellij_enabled: false,
        zellij_web_port: 8082,
        stun_servers: Vec::new(),
        operator_url: None,
        config_path: None,
    };

    let unix_listener: UnixListener = bind_standalone_socket(&sock_path).unwrap();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let daemon_handle = tokio::spawn(async move {
        serve_with_listener(
            unix_listener,
            cfg,
            Duration::from_millis(180),
            shutdown_rx,
        )
        .await
    });

    // Connect as an SSH client to the Unix socket
    let mut client_stream = UnixStream::connect(&sock_path).await.unwrap();

    // 1. Request identities (SSH2_AGENTC_REQUEST_IDENTITIES = 11)
    write_agent_frame(&mut client_stream, &[SSH2_AGENTC_REQUEST_IDENTITIES])
        .await
        .unwrap();
    let id_reply = read_agent_frame(&mut client_stream).await.unwrap().unwrap();
    assert_eq!(id_reply[0], SSH2_AGENT_IDENTITIES_ANSWER);
    let num_keys = u32::from_be_bytes([id_reply[1], id_reply[2], id_reply[3], id_reply[4]]);
    assert_eq!(num_keys, 1);

    // Verify disk cache was written
    assert!(pubkey_cache_path.exists());

    // 2. Verify mutating agent operations are rejected with SSH_AGENT_FAILURE (5)
    for forbidden_op in [
        SSH2_AGENTC_ADD_IDENTITY,
        SSH2_AGENTC_REMOVE_ALL_IDENTITIES,
        SSH_AGENTC_LOCK,
    ] {
        write_agent_frame(&mut client_stream, &[forbidden_op])
            .await
            .unwrap();
        let resp = read_agent_frame(&mut client_stream).await.unwrap().unwrap();
        assert_eq!(resp, vec![SSH_AGENT_FAILURE]);
    }

    // 3. Send a SignRequest containing an RFC 4252 SSH_MSG_USERAUTH_REQUEST payload
    let mut rfc4252_data = Vec::new();
    write_ssh_bytes(&mut rfc4252_data, &[0xaa, 0xbb, 0xcc, 0xdd]); // session_id
    rfc4252_data.push(50); // SSH_MSG_USERAUTH_REQUEST
    write_ssh_bytes(&mut rfc4252_data, b"pavel");
    write_ssh_bytes(&mut rfc4252_data, b"ssh-connection");
    write_ssh_bytes(&mut rfc4252_data, b"publickey");
    rfc4252_data.push(1);
    write_ssh_bytes(&mut rfc4252_data, b"ssh-ed25519");
    write_ssh_bytes(&mut rfc4252_data, b"ssh-ed25519-test-blob");

    let mut sign_frame = vec![SSH2_AGENTC_SIGN_REQUEST];
    write_ssh_bytes(&mut sign_frame, b"ssh-ed25519-test-blob");
    write_ssh_bytes(&mut sign_frame, &rfc4252_data);
    sign_frame.extend_from_slice(&0u32.to_be_bytes()); // flags = 0

    write_agent_frame(&mut client_stream, &sign_frame)
        .await
        .unwrap();
    let sign_reply = read_agent_frame(&mut client_stream).await.unwrap().unwrap();
    assert_eq!(sign_reply[0], SSH2_AGENT_SIGN_RESPONSE);

    let mut expected_sig_reply = vec![SSH2_AGENT_SIGN_RESPONSE];
    write_ssh_bytes(&mut expected_sig_reply, b"mock-ssh-ed25519-sig-blob");
    assert_eq!(sign_reply, expected_sig_reply);

    // Inspect captured SignRequest on the coordinator
    {
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let sr = &reqs[0];
        let pc = sr.process_context.as_ref().unwrap();
        assert_eq!(pc.hostname, "server-x.infra.local");
        assert_eq!(pc.pid, std::process::id());
        let sc = sr.ssh_auth_context.as_ref().unwrap();
        assert!(sc.is_userauth_request);
        assert_eq!(sc.target_username, "pavel");
        assert_eq!(sc.pubkey_algorithm, "ssh-ed25519");
    }

    // Close client connection and verify daemon automatically exits after the 180ms idle timeout
    drop(client_stream);
    let daemon_res = tokio::time::timeout(Duration::from_secs(2), daemon_handle)
        .await
        .expect("daemon should auto-exit on idle timeout")
        .unwrap();
    assert!(daemon_res.is_ok());
}

#[test]
fn test_zellij_session_parsing_token_and_header_rewriter() {
    let raw_sessions = "\
work-main [Created 2h 15m ago]
build-rpm [Created 1d ago] (EXITED - attach to resurrect)
";
    let sessions = parse_zellij_list_sessions_output(raw_sessions);
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].name, "work-main");
    assert!(!sessions[0].exited);
    assert_eq!(sessions[1].name, "build-rpm");
    assert!(sessions[1].exited);

    let token_out = "Created token successfully\n\ntoken_1: 18fcbf46-3526-4d04-8364-e015403284eb\n";
    assert_eq!(
        parse_zellij_create_token_output(token_out).as_deref(),
        Some("18fcbf46-3526-4d04-8364-e015403284eb")
    );

    let req = b"GET /ws/terminal/work-main HTTP/1.1\r\nHost: sunduk.localhost:18080\r\nOrigin: http://sunduk.localhost:18080\r\nUpgrade: websocket\r\n\r\npayload";
    let rewritten = rewrite_http_request_for_zellij_web(req, 8082, Some("session_token=abc123"));
    let rewritten_str = String::from_utf8(rewritten).unwrap();
    assert!(rewritten_str.contains("Host: 127.0.0.1:8082\r\n"));
    assert!(rewritten_str.contains("Origin: http://127.0.0.1:8082\r\n"));
    assert!(rewritten_str.contains("Cookie: session_token=abc123\r\n"));
    assert!(rewritten_str.ends_with("\r\n\r\npayload"));

    let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>";
    let resp_injected = inject_set_cookie_into_http_response(resp, Some("session_token=abc123"));
    let resp_str = String::from_utf8(resp_injected).unwrap();
    assert!(resp_str.contains("Set-Cookie: session_token=abc123; Path=/; SameSite=Lax\r\n"));
    assert!(resp_str.ends_with("\r\n\r\n<html></html>"));

    let index_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 88\r\n\r\n<html><body><script type=\"module\" src=\"assets/app.js\"></script></body></html>";
    let index_injected = inject_set_cookie_into_http_response(index_resp, None);
    let index_str = String::from_utf8(index_injected).unwrap();
    assert!(index_str.contains("/__sshcast/sshcast-fonts.css"));
    assert!(index_str.contains("/__sshcast/sshcast-zellij.js"));

    let css_req = b"GET /__sshcast/sshcast-fonts.css HTTP/1.1\r\nHost: 127.0.0.1:8082\r\n\r\n";
    let css_resp = String::from_utf8(try_build_sshcast_asset_http_response(css_req).unwrap()).unwrap();
    assert!(css_resp.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/css"));
    assert!(css_resp.contains("Symbols Nerd Font Mono"));
    assert!(css_resp.contains("Iosevka Term"));

    let js_req = b"GET /__sshcast/sshcast-zellij.js HTTP/1.1\r\nHost: 127.0.0.1:8082\r\n\r\n";
    let js_resp = String::from_utf8(try_build_sshcast_asset_http_response(js_req).unwrap()).unwrap();
    assert!(js_resp.starts_with("HTTP/1.1 200 OK\r\nContent-Type: application/javascript"));
    assert!(js_resp.contains("withSshcastNerdFonts"));

    let font_gz_req = b"GET /__sshcast/SymbolsNerdFontMono-Regular.ttf HTTP/1.1\r\nHost: 127.0.0.1:8082\r\nAccept-Encoding: gzip, deflate\r\n\r\n";
    let font_gz_resp = try_build_sshcast_asset_http_response(font_gz_req).unwrap();
    let gz_hdr_end = font_gz_resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let gz_hdr_str = std::str::from_utf8(&font_gz_resp[..gz_hdr_end]).unwrap();
    assert!(gz_hdr_str.contains("Content-Type: font/ttf\r\n"));
    assert!(gz_hdr_str.contains("Content-Encoding: gzip\r\n"));
    assert_eq!(&font_gz_resp[gz_hdr_end + 4..gz_hdr_end + 6], &[0x1f, 0x8b]);

    let font_raw_req = b"GET /__sshcast/IosevkaTerm-Regular.ttf HTTP/1.1\r\nHost: 127.0.0.1:8082\r\n\r\n";
    let font_raw_resp = try_build_sshcast_asset_http_response(font_raw_req).unwrap();
    let raw_hdr_end = font_raw_resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let raw_hdr_str = std::str::from_utf8(&font_raw_resp[..raw_hdr_end]).unwrap();
    assert!(raw_hdr_str.contains("Content-Type: font/ttf\r\n"));
    assert!(!raw_hdr_str.contains("Content-Encoding: gzip"));
    // TrueType sfnt version 0x00010000
    assert_eq!(&font_raw_resp[raw_hdr_end + 4..raw_hdr_end + 8], &[0x00, 0x01, 0x00, 0x00]);

    let mut ws_close = b"\x88\x13\x03\xe8Connection closed".to_vec();
    rewrite_websocket_normal_close_to_4001(&mut ws_close);
    assert_eq!(&ws_close, b"\x88\x13\x0f\xa1Connection closed");

    let tmp = TempDir::new().unwrap();
    let kdl_path = tmp.path().join("zellij").join("config.kdl");
    assert!(ensure_zellij_web_sharing_in_file(&kdl_path).unwrap());
    assert_eq!(
        std::fs::read_to_string(&kdl_path).unwrap(),
        "web_sharing \"on\"\n"
    );
    assert!(!ensure_zellij_web_sharing_in_file(&kdl_path).unwrap());

    std::fs::write(&kdl_path, "theme \"dracula\"\nweb_sharing \"off\"\n").unwrap();
    assert!(ensure_zellij_web_sharing_in_file(&kdl_path).unwrap());
    assert_eq!(
        std::fs::read_to_string(&kdl_path).unwrap(),
        "theme \"dracula\"\nweb_sharing \"on\"\n"
    );
}

#[tokio::test]
async fn test_bind_standalone_socket_protects_active_and_non_socket_files() {
    let tmp = TempDir::new().unwrap();

    // 1. Active Unix socket must NOT be unlinked or replaced
    let active_sock = tmp.path().join("sshcast.sock");
    let original_listener = UnixListener::bind(&active_sock).unwrap();

    let err = bind_standalone_socket(&active_sock).unwrap_err();
    assert!(
        err.to_string().contains("already active"),
        "unexpected error for active socket: {err:#}"
    );
    assert!(active_sock.exists());
    assert!(UnixStream::connect(&active_sock).await.is_ok());
    drop(original_listener);

    // 2. Stale Unix socket (no listener) should be cleaned up and rebound
    let stale_sock = tmp.path().join("stale.sock");
    {
        let _stale = std::os::unix::net::UnixListener::bind(&stale_sock).unwrap();
    }
    assert!(stale_sock.exists());
    let rebound = bind_standalone_socket(&stale_sock).expect("stale socket should be rebound");
    assert!(UnixStream::connect(&stale_sock).await.is_ok());
    drop(rebound);

    // 3. Regular file must NOT be unlinked
    let reg_file = tmp.path().join("not_a_socket");
    std::fs::write(&reg_file, b"keep-me").unwrap();
    let reg_err = bind_standalone_socket(&reg_file).unwrap_err();
    assert!(
        reg_err.to_string().contains("non-socket"),
        "unexpected error for regular file: {reg_err:#}"
    );
    assert_eq!(std::fs::read(&reg_file).unwrap(), b"keep-me");
}

#[test]
fn test_cli_requires_subcommand_and_preserves_existing_socket() {
    let tmp = TempDir::new().unwrap();
    let sock_path = tmp.path().join("sshcast.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sshcast-relay"))
        .env("XDG_RUNTIME_DIR", tmp.path())
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "bare sshcast-relay should exit non-zero without a subcommand"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage:"),
        "expected usage text in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("run"),
        "expected 'run' subcommand in stderr, got: {stderr}"
    );
    assert!(sock_path.exists());
    assert!(std::os::unix::net::UnixStream::connect(&sock_path).is_ok());
    drop(listener);
}

#[derive(serde::Deserialize)]
struct MockRenewReq {
    node_auth_proto_b64: String,
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "unexpected EOF reading HTTP request headers");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };
    let header_str = std::str::from_utf8(&buf[..header_end]).unwrap().to_string();
    let content_len = header_str
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buf.len() < body_start + content_len {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "unexpected EOF reading HTTP request body");
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[body_start..body_start + content_len].to_vec();
    (header_str, body)
}

async fn spawn_mock_renew_server(
    op_sk: SigningKey,
    user_pk: Vec<u8>,
    expected_relay_pk: Vec<u8>,
    call_count: Arc<AtomicUsize>,
    issued_certs: Arc<Mutex<Vec<UserCert>>>,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let op_sk = op_sk.clone();
            let user_pk = user_pk.clone();
            let expected_relay_pk = expected_relay_pk.clone();
            let call_count = Arc::clone(&call_count);
            let issued_certs = Arc::clone(&issued_certs);
            tokio::spawn(async move {
                let (headers, body) = read_http_request(&mut stream).await;
                let first_line = headers.lines().next().unwrap_or("");
                assert!(
                    first_line.starts_with("POST /api/v1/renew "),
                    "unexpected HTTP request line: {first_line}"
                );

                let req: MockRenewReq = serde_json::from_slice(&body).unwrap();
                let raw_auth = URL_SAFE_NO_PAD
                    .decode(req.node_auth_proto_b64.trim())
                    .or_else(|_| STANDARD.decode(req.node_auth_proto_b64.trim()))
                    .unwrap();
                let auth = NodeAuth::decode(raw_auth.as_slice()).unwrap();
                let grant = auth.grant.as_ref().expect("NodeAuth must include grant");

                // Critical invariant: dormant relay must strip expired UserCert before signing NodeAuth
                assert!(
                    grant.user_cert.is_none(),
                    "incoming NodeAuth grant.user_cert MUST be None on /api/v1/renew"
                );
                assert_eq!(grant.node_pubkey, expected_relay_pk);

                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                verify_node_auth(&auth, Some(NodeRole::Relay), now_ms, DEFAULT_MAX_CLOCK_SKEW_MS)
                    .expect("NodeAuth from relay must pass verify_node_auth");

                let seq = call_count.fetch_add(1, Ordering::SeqCst) as u64 + 1;
                let now_sec = now_ms / 1000;
                let mut new_cert = UserCert {
                    user_id: derive_user_id(&user_pk),
                    user_pubkey: user_pk,
                    operator_pubkey: Vec::new(),
                    issued_at_unix_sec: now_sec.saturating_sub(5),
                    expires_at_unix_sec: now_sec + 7 * 86400 + seq,
                    operator_signature: Vec::new(),
                };
                sign_user_cert(&mut new_cert, &op_sk);
                issued_certs.lock().unwrap().push(new_cert.clone());

                let token = encode_user_cert_token(&new_cert);
                let resp_json = serde_json::json!({
                    "ok": true,
                    "cert_token": token,
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_json.len(),
                    resp_json
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[test]
fn test_cert_needs_renewal_matrix() {
    let now = 1_750_000_000u64;
    assert!(!cert_needs_renewal(None, now));

    let make = |issued: u64, expires: u64| UserCert {
        user_id: "sc_u_test".to_string(),
        user_pubkey: vec![0x11; 32],
        operator_pubkey: vec![0x22; 32],
        issued_at_unix_sec: issued,
        expires_at_unix_sec: expires,
        operator_signature: vec![0x33; 64],
    };

    assert!(!cert_needs_renewal(Some(&make(now - 500, 0)), now));
    assert!(!cert_needs_renewal(
        Some(&make(now - 100, now - 100 + 7 * 86400)),
        now
    ));
    assert!(cert_needs_renewal(
        Some(&make(now - (7 * 86400) / 2, now + (7 * 86400) / 2)),
        now
    ));
    assert!(!cert_needs_renewal(Some(&make(now - 10, now + 50)), now));
    assert!(cert_needs_renewal(Some(&make(now - 35, now + 25)), now));
    assert!(cert_needs_renewal(Some(&make(now - 100, now - 1)), now));
}

#[test]
fn test_import_user_cert_persists_atomically_and_validates_pubkey() {
    let tmp = TempDir::new().unwrap();
    let op_sk = SigningKey::from_bytes(&[0x91; 32]);
    let user_sk = SigningKey::from_bytes(&[0x11; 32]);
    let other_user_sk = SigningKey::from_bytes(&[0x12; 32]);
    let relay_sk = SigningKey::from_bytes(&[0x22; 32]);
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "relay-atomic".to_string(),
        role: NodeRole::Relay as i32,
        node_pubkey: relay_sk.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
        user_cert: None,
    };
    sign_node_grant(&mut grant, &user_sk);

    let bundle = EnrollmentBundle::new(
        vec!["https://coord.example.com".to_string()],
        relay_sk,
        grant.clone(),
    );
    let cfg_path = tmp.path().join("relay.toml");
    let file = RelayConfigFile::from_bundle(&bundle);
    std::fs::write(&cfg_path, toml::to_string_pretty(&file).unwrap()).unwrap();

    // Valid UserCert matching grant.user_pubkey
    let mut cert = UserCert {
        user_id: derive_user_id(&grant.user_pubkey),
        user_pubkey: grant.user_pubkey.clone(),
        operator_pubkey: Vec::new(),
        issued_at_unix_sec: now_sec - 10,
        expires_at_unix_sec: now_sec + 86400,
        operator_signature: Vec::new(),
    };
    sign_user_cert(&mut cert, &op_sk);
    let cert_token = encode_user_cert_token(&cert);

    let (saved_path, saved_cert) =
        RelayConfig::import_user_cert(Some(&cfg_path), &cert_token).unwrap();
    assert_eq!(saved_path, cfg_path);
    assert_eq!(saved_cert, cert);

    let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let reloaded = RelayConfig::load(Some(&cfg_path)).unwrap();
    assert_eq!(reloaded.grant.user_cert, Some(cert));

    // Mismatched UserCert user_pubkey must fail without modifying relay.toml
    let wrong_pk = other_user_sk.verifying_key().to_bytes().to_vec();
    let mut wrong_cert = UserCert {
        user_id: derive_user_id(&wrong_pk),
        user_pubkey: wrong_pk,
        operator_pubkey: Vec::new(),
        issued_at_unix_sec: now_sec - 10,
        expires_at_unix_sec: now_sec + 86400,
        operator_signature: Vec::new(),
    };
    sign_user_cert(&mut wrong_cert, &op_sk);
    let wrong_token = encode_user_cert_token(&wrong_cert);
    assert!(RelayConfig::import_user_cert(Some(&cfg_path), &wrong_token).is_err());
}

#[tokio::test]
async fn test_proactive_user_cert_renewal_and_atomic_persistence() {
    let tmp = TempDir::new().unwrap();
    let op_sk = SigningKey::from_bytes(&[0x71; 32]);
    let user_sk = SigningKey::from_bytes(&[0x72; 32]);
    let relay_sk = SigningKey::from_bytes(&[0x73; 32]);
    let user_pk = user_sk.verifying_key().to_bytes().to_vec();
    let relay_pk = relay_sk.verifying_key().to_bytes().to_vec();

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Start with an EXPIRED UserCert embedded in relay.toml
    let mut expired_cert = UserCert {
        user_id: derive_user_id(&user_pk),
        user_pubkey: user_pk.clone(),
        operator_pubkey: Vec::new(),
        issued_at_unix_sec: now_sec - 1000,
        expires_at_unix_sec: now_sec - 60,
        operator_signature: Vec::new(),
    };
    sign_user_cert(&mut expired_cert, &op_sk);

    let mut grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "relay-dormant.local".to_string(),
        role: NodeRole::Relay as i32,
        node_pubkey: relay_pk.clone(),
        issued_at_unix_sec: now_sec - 1000,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
        user_cert: Some(expired_cert),
    };
    sign_node_grant(&mut grant, &user_sk);

    // Start mock gRPC coordinator (enforces valid non-expired UserCert in NodeGrant)
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mock_svc = MockCoordinator {
        keys: vec![PublicKey {
            key_blob: b"ssh-ed25519-renew-test".to_vec(),
            comment: "renew@workstation".to_string(),
            fingerprint_sha256: "SHA256:renewfp".to_string(),
            key_type: "ssh-ed25519".to_string(),
        }],
        captured_sign_requests: Arc::clone(&captured),
    };
    let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_addr = grpc_listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(grpc_listener);
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(SshcastServiceServer::new(mock_svc))
            .serve_with_incoming(incoming)
            .await;
    });

    // Start mock HTTP /api/v1/renew operator server
    let renew_calls = Arc::new(AtomicUsize::new(0));
    let issued_certs = Arc::new(Mutex::new(Vec::new()));
    let op_addr = spawn_mock_renew_server(
        op_sk,
        user_pk,
        relay_pk,
        Arc::clone(&renew_calls),
        Arc::clone(&issued_certs),
    )
    .await;

    // Write relay.toml on disk with operator_url and expired UserCert
    let cfg_path = tmp.path().join("relay.toml");
    let bundle = EnrollmentBundle::new(vec![format!("http://{}", grpc_addr)], relay_sk, grant);
    let mut cfg_file = RelayConfigFile::from_bundle(&bundle);
    cfg_file.operator_url = Some(format!("http://{}", op_addr));
    cfg_file.pubkey_cache_path = Some(tmp.path().join("pubkeys.json").to_string_lossy().to_string());
    std::fs::write(&cfg_path, toml::to_string_pretty(&cfg_file).unwrap()).unwrap();

    let cfg = RelayConfig::load(Some(&cfg_path)).unwrap();
    assert_eq!(cfg.config_path.as_deref(), Some(cfg_path.as_path()));
    assert_eq!(
        cfg.operator_url.as_deref(),
        Some(format!("http://{}", op_addr).as_str())
    );

    let coord = Arc::new(CoordinatorClient::new(cfg));

    // get_identities triggers proactive renewal before RPC, hot-swaps cert, persists to disk, and succeeds
    let keys = coord.get_identities().await;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].comment, "renew@workstation");
    assert_eq!(renew_calls.load(Ordering::SeqCst), 1);

    let expected_cert = issued_certs.lock().unwrap()[0].clone();
    assert_eq!(coord.current_grant().await.user_cert, Some(expected_cert.clone()));

    // Verify atomic persistence to relay.toml with 0600 perms and no stray temp files
    let reloaded = RelayConfig::load(Some(&cfg_path)).unwrap();
    assert_eq!(reloaded.grant.user_cert, Some(expected_cert.clone()));
    let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let leftover_tmp = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".tmp."));
    assert!(!leftover_tmp, "no leftover temp files should remain after atomic rename");

    // Subsequent sign_challenge uses fresh in-memory cert without re-renewing
    let sign_resp = coord
        .sign_challenge(
            b"ssh-ed25519-renew-test".to_vec(),
            b"challenge-bytes".to_vec(),
            0,
            ProcessContext {
                hostname: "relay-dormant.local".to_string(),
                uid: 1000,
                pid: 42,
                comm: "ssh".to_string(),
                cmdline: "ssh host".to_string(),
                cwd: "/tmp".to_string(),
                ancestors: Vec::new(),
            },
        )
        .await
        .unwrap();
    assert!(sign_resp.approved);
    assert_eq!(renew_calls.load(Ordering::SeqCst), 1);
    let captured_reqs = captured.lock().unwrap();
    assert_eq!(captured_reqs.len(), 1);
    assert_eq!(
        captured_reqs[0]
            .relay_grant
            .as_ref()
            .and_then(|g| g.user_cert.clone()),
        Some(expected_cert)
    );
}

struct RejectStaleCertCoordinator {
    rejected_certs: Arc<Mutex<Vec<UserCert>>>,
}

#[tonic::async_trait]
impl SshcastService for RejectStaleCertCoordinator {
    async fn get_identities(
        &self,
        request: Request<GetIdentitiesRequest>,
    ) -> Result<Response<GetIdentitiesResponse>, Status> {
        let auth = request
            .into_inner()
            .auth
            .ok_or_else(|| Status::unauthenticated("missing auth"))?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        verify_node_auth(&auth, Some(NodeRole::Relay), now_ms, DEFAULT_MAX_CLOCK_SKEW_MS)
            .map_err(|e| Status::unauthenticated(e.to_string()))?;

        let cert = auth
            .grant
            .and_then(|g| g.user_cert)
            .ok_or_else(|| Status::unauthenticated("missing user_cert"))?;
        if self.rejected_certs.lock().unwrap().contains(&cert) {
            return Err(Status::unauthenticated("cert revoked by operator"));
        }

        Ok(Response::new(GetIdentitiesResponse {
            keys: vec![PublicKey {
                key_blob: b"ssh-ed25519-reactive".to_vec(),
                comment: "reactive@workstation".to_string(),
                fingerprint_sha256: "SHA256:reactivefp".to_string(),
                key_type: "ssh-ed25519".to_string(),
            }],
        }))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        verify_sign_request(&req, now_sec)
            .map_err(|e| Status::permission_denied(format!("verify_sign_request failed: {e}")))?;

        let cert = req
            .relay_grant
            .as_ref()
            .and_then(|g| g.user_cert.as_ref())
            .ok_or_else(|| Status::permission_denied("missing user_cert"))?;
        let rejected = self.rejected_certs.lock().unwrap();
        if rejected.contains(cert) {
            return Err(Status::permission_denied("cert must be rotated"));
        }
        drop(rejected);

        Ok(Response::new(SignResponse {
            request_id: req.request_id,
            approved: true,
            signature_blob: b"reactive-sig-blob".to_vec(),
            error_message: String::new(),
            handled_by_node_id: "test-ws".to_string(),
        }))
    }

    type ConnectWorkstationStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ServerStreamMessage, Status>> + Send>>;

    async fn connect_workstation(
        &self,
        _request: Request<Streaming<ClientStreamMessage>>,
    ) -> Result<Response<Self::ConnectWorkstationStream>, Status> {
        Err(Status::unimplemented("not used"))
    }

    type ConnectRelayStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ServerToRelayMessage, Status>> + Send>>;

    async fn connect_relay(
        &self,
        _request: Request<Streaming<RelayStreamMessage>>,
    ) -> Result<Response<Self::ConnectRelayStream>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

#[tokio::test]
async fn test_reactive_renewal_on_unauthenticated_and_permission_denied_rpc() {
    let tmp = TempDir::new().unwrap();
    let op_sk = SigningKey::from_bytes(&[0x81; 32]);
    let user_sk = SigningKey::from_bytes(&[0x82; 32]);
    let relay_sk = SigningKey::from_bytes(&[0x83; 32]);
    let user_pk = user_sk.verifying_key().to_bytes().to_vec();
    let relay_pk = relay_sk.verifying_key().to_bytes().to_vec();

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Fresh (non-expired, >50% TTL remaining) cert_v1 so proactive renewal does NOT trigger
    let mut cert_v1 = UserCert {
        user_id: derive_user_id(&user_pk),
        user_pubkey: user_pk.clone(),
        operator_pubkey: Vec::new(),
        issued_at_unix_sec: now_sec - 10,
        expires_at_unix_sec: now_sec + 7 * 86400,
        operator_signature: Vec::new(),
    };
    sign_user_cert(&mut cert_v1, &op_sk);

    let mut grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "relay-reactive.local".to_string(),
        role: NodeRole::Relay as i32,
        node_pubkey: relay_pk.clone(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
        user_cert: Some(cert_v1.clone()),
    };
    sign_node_grant(&mut grant, &user_sk);

    let rejected_certs = Arc::new(Mutex::new(vec![cert_v1]));
    let mock_svc = RejectStaleCertCoordinator {
        rejected_certs: Arc::clone(&rejected_certs),
    };
    let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_addr = grpc_listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(grpc_listener);
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(SshcastServiceServer::new(mock_svc))
            .serve_with_incoming(incoming)
            .await;
    });

    let renew_calls = Arc::new(AtomicUsize::new(0));
    let issued_certs = Arc::new(Mutex::new(Vec::new()));
    let op_addr = spawn_mock_renew_server(
        op_sk,
        user_pk,
        relay_pk,
        Arc::clone(&renew_calls),
        Arc::clone(&issued_certs),
    )
    .await;

    let cfg_path = tmp.path().join("relay.toml");
    let bundle = EnrollmentBundle::new(vec![format!("http://{}", grpc_addr)], relay_sk, grant);
    let mut cfg_file = RelayConfigFile::from_bundle(&bundle);
    cfg_file.operator_url = Some(format!("http://{}", op_addr));
    cfg_file.pubkey_cache_path = Some(tmp.path().join("pubkeys.json").to_string_lossy().to_string());
    std::fs::write(&cfg_path, toml::to_string_pretty(&cfg_file).unwrap()).unwrap();

    let cfg = RelayConfig::load(Some(&cfg_path)).unwrap();
    let coord = Arc::new(CoordinatorClient::new(cfg));

    // 1. Unauthenticated on GetIdentities triggers force renewal -> cert_v2 -> retry succeeds
    let keys = coord.get_identities().await;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].comment, "reactive@workstation");
    assert_eq!(renew_calls.load(Ordering::SeqCst), 1);
    let cert_v2 = issued_certs.lock().unwrap()[0].clone();
    assert_eq!(coord.current_grant().await.user_cert, Some(cert_v2.clone()));

    // 2. Mark cert_v2 as rejected -> PermissionDenied on Sign triggers force renewal -> cert_v3 -> retry succeeds
    rejected_certs.lock().unwrap().push(cert_v2);
    let sign_resp = coord
        .sign_challenge(
            b"ssh-ed25519-reactive".to_vec(),
            b"challenge".to_vec(),
            0,
            ProcessContext {
                hostname: "relay-reactive.local".to_string(),
                uid: 1000,
                pid: 99,
                comm: "ssh".to_string(),
                cmdline: "ssh host".to_string(),
                cwd: "/tmp".to_string(),
                ancestors: Vec::new(),
            },
        )
        .await
        .unwrap();
    assert!(sign_resp.approved);
    assert_eq!(sign_resp.signature_blob, b"reactive-sig-blob");
    assert_eq!(renew_calls.load(Ordering::SeqCst), 2);
    let cert_v3 = issued_certs.lock().unwrap()[1].clone();
    assert_eq!(coord.current_grant().await.user_cert, Some(cert_v3.clone()));

    let reloaded = RelayConfig::load(Some(&cfg_path)).unwrap();
    assert_eq!(reloaded.grant.user_cert, Some(cert_v3));

    // 3. Concurrent force renewals share renew_lock and only make 1 HTTP /api/v1/renew request
    let (r1, r2) = tokio::join!(coord.maybe_renew_cert(true), coord.maybe_renew_cert(true));
    assert!(r1 && r2);
    assert_eq!(renew_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn test_renew_user_cert_http_handles_operator_rejection() {
    let user_sk = SigningKey::from_bytes(&[0x61; 32]);
    let relay_sk = SigningKey::from_bytes(&[0x62; 32]);
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "relay-reject.local".to_string(),
        role: NodeRole::Relay as i32,
        node_pubkey: relay_sk.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
        user_cert: None,
    };
    sign_node_grant(&mut grant, &user_sk);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = read_http_request(&mut stream).await;
            let body = r#"{"ok":false,"error":"node revoked"}"#;
            let resp = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    let err = sshcast_relay::renew::renew_user_cert_http(
        &format!("http://{}", addr),
        &grant,
        &relay_sk,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("node revoked"),
        "unexpected error message: {err:#}"
    );
}
