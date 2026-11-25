use ed25519_dalek::SigningKey;
use sshcast_proto::bundle::EnrollmentBundle;
use sshcast_proto::crypto::{sign_node_grant, verify_node_auth, verify_sign_request, DEFAULT_MAX_CLOCK_SKEW_MS};
use sshcast_proto::v1::sshcast_service_server::{SshcastService, SshcastServiceServer};
use sshcast_proto::v1::{
    ClientStreamMessage, GetIdentitiesRequest, GetIdentitiesResponse, NodeGrant, NodeRole,
    PublicKey, RelayStreamMessage, ServerStreamMessage, ServerToRelayMessage, SignRequest,
    SignResponse,
};
use sshcast_relay::agent::{
    read_agent_frame, write_agent_frame, SSH2_AGENTC_ADD_IDENTITY, SSH2_AGENTC_REMOVE_ALL_IDENTITIES,
    SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST, SSH2_AGENT_IDENTITIES_ANSWER,
    SSH2_AGENT_SIGN_RESPONSE, SSH_AGENTC_LOCK, SSH_AGENT_FAILURE,
};
use sshcast_relay::config::RelayConfig;
use sshcast_relay::init::{run_init, InitOptions};
use sshcast_relay::listener::{bind_standalone_socket, serve_with_listener};
use sshcast_relay::proc_inspector::{
    format_cmdline, inspect_process_context_in_proc, parse_proc_stat,
};
use sshcast_relay::zellij::{
    ensure_zellij_web_sharing_in_file, inject_set_cookie_into_http_response,
    parse_zellij_create_token_output, parse_zellij_list_sessions_output,
    rewrite_http_request_for_zellij_web, rewrite_websocket_normal_close_to_4001,
    try_build_sshcast_asset_http_response,
};
use std::os::unix::fs::PermissionsExt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
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
