use ed25519_dalek::SigningKey;
use sockcast_proto::bundle::EnrollmentBundle;
use sockcast_proto::crypto::{sign_node_grant, verify_node_auth, verify_sign_request, DEFAULT_MAX_CLOCK_SKEW_MS};
use sockcast_proto::v1::sockcast_service_server::{SockcastService, SockcastServiceServer};
use sockcast_proto::v1::{
    ClientStreamMessage, GetIdentitiesRequest, GetIdentitiesResponse, NodeGrant, NodeRole,
    PublicKey, ServerStreamMessage, SignRequest, SignResponse,
};
use sockcast_relay::agent::{
    read_agent_frame, write_agent_frame, SSH2_AGENTC_ADD_IDENTITY, SSH2_AGENTC_REMOVE_ALL_IDENTITIES,
    SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST, SSH2_AGENT_IDENTITIES_ANSWER,
    SSH2_AGENT_SIGN_RESPONSE, SSH_AGENTC_LOCK, SSH_AGENT_FAILURE,
};
use sockcast_relay::config::RelayConfig;
use sockcast_relay::init::{run_init, InitOptions};
use sockcast_relay::listener::{bind_standalone_socket, serve_with_listener};
use sockcast_relay::proc_inspector::{
    format_cmdline, inspect_process_context_in_proc, parse_proc_stat,
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
    })
    .unwrap();

    assert!(out1.installed_local_units);
    assert!(user_systemd_1.join("sockcast-relay.socket").exists());
    assert!(user_systemd_1.join("sockcast-relay.service").exists());

    let mode = std::fs::metadata(&cfg_path_1).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let loaded_cfg = RelayConfig::load(Some(&cfg_path_1)).unwrap();
    assert_eq!(loaded_cfg.grant.node_id, "server-x.infra.local");
    assert_eq!(loaded_cfg.node_signing_key.to_bytes(), relay_sk.to_bytes());

    // Case 2: Global RPM units DO exist in /usr/lib/systemd/user -> does NOT write ~/.config/systemd/user units
    let fake_global_rpm = tmp.path().join("global-rpm");
    std::fs::create_dir_all(&fake_global_rpm).unwrap();
    std::fs::write(fake_global_rpm.join("sockcast-relay.socket"), "[Socket]\n").unwrap();
    std::fs::write(fake_global_rpm.join("sockcast-relay.service"), "[Service]\n").unwrap();

    let cfg_path_2 = tmp.path().join("cfg2").join("relay.toml");
    let user_systemd_2 = tmp.path().join("systemd-user-2");

    let out2 = run_init(&InitOptions {
        bundle_token: token,
        config_path: Some(cfg_path_2),
        systemd_user_dir: Some(user_systemd_2.clone()),
        global_systemd_user_dir: fake_global_rpm,
        skip_systemctl: true,
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
impl SockcastService for MockCoordinator {
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
            .add_service(SockcastServiceServer::new(mock_svc))
            .serve_with_incoming(incoming)
            .await;
    });

    let sock_path = tmp.path().join("sockcast.sock");
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
