#![cfg(unix)]
#![allow(dead_code)]

include!("../src/main.rs");

use iroh::{EndpointAddr, RelayConfig, address_lookup::memory::MemoryLookup};
use iroh_relay::server::{Server, testing};
use tokio::{net::TcpListener, task::JoinHandle};

async fn open_local_proxy(path: &Path, target: String, port: u16) -> Result<UnixStream> {
    request_local_proxy(UnixStream::connect(path).await?, target, port).await
}

/// Real daemon handlers and QUIC streams, with a private relay and no IP transport
/// or public discovery services. Every byte must travel through the relay.
struct ProxyFixture {
    dir: PathBuf,
    socket: PathBuf,
    port: u16,
    tcp: TcpListener,
    local: Endpoint,
    remote: Endpoint,
    actor: ConfigActorHandle,
    remote_actor: ConfigActorHandle,
    local_server: JoinHandle<()>,
    remote_server: JoinHandle<Result<()>>,
    relay: Server,
}

impl ProxyFixture {
    async fn new(max_connections: usize) -> Self {
        Self::with_transport_idle(max_connections, None).await
    }

    async fn with_transport_idle(max_connections: usize, idle: Option<Duration>) -> Self {
        let dir = std::env::temp_dir().join(format!("esp-p-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        // Keep the path under macOS's Unix socket path length limit.
        let socket = dir.join(".esp.sock");
        let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = tcp.local_addr().unwrap().port();

        let mut relay_config = testing::server_config();
        relay_config.relay.as_mut().unwrap().tls = None;
        relay_config.quic = None;
        let relay = Server::spawn(relay_config).await.unwrap();
        let relay_url = relay.http_url().unwrap();
        let relay_map = iroh::RelayMap::from(RelayConfig::new(relay_url.clone(), None));
        let lookup = MemoryLookup::new();
        let local_key = SecretKey::generate();
        let remote_key = SecretKey::generate();
        let mut cfg = create_creator_config(
            &local_key,
            Uuid::new_v4().to_string(),
            "local".to_string(),
            "ABC123".to_string(),
            DEFAULT_MAX_KNOWN_PEERS,
        )
        .unwrap();
        cfg.membership = Some(
            MembershipCertificate::issue(
                &cfg,
                &local_key,
                &Peer {
                    node_id: local_key.public(),
                    name: cfg.name.clone(),
                    connection_id: cfg.connection_id.clone(),
                },
                &[port],
                MembershipRole::Admin,
            )
            .unwrap(),
        );
        let peer = Peer {
            node_id: remote_key.public(),
            name: "remote-host".to_string(),
            connection_id: "DEF456".to_string(),
        };
        let membership =
            MembershipCertificate::issue(&cfg, &local_key, &peer, &[port], MembershipRole::Peer)
                .unwrap();
        let remote_cfg = Config {
            version: CONFIG_VERSION,
            network_id: cfg.network_id.clone(),
            secret_key: encode_secret_key(&remote_key),
            network_policy: cfg.network_policy.clone(),
            creator_node_id: cfg.creator_node_id,
            invite_proof: None,
            membership: Some(membership.clone()),
            memberships: vec![cfg.membership.clone().unwrap()],
            name: peer.name.clone(),
            connection_id: peer.connection_id.clone(),
            invites: Vec::new(),
            peer_last_connected: HashMap::new(),
            peers: vec![Peer {
                node_id: local_key.public(),
                name: cfg.name.clone(),
                connection_id: cfg.connection_id.clone(),
            }],
            revocations: Vec::new(),
        };
        cfg.peers.push(peer);
        cfg.memberships.push(membership);
        cfg.save(&dir.join("local.yml")).unwrap();
        remote_cfg.save(&dir.join("remote.yml")).unwrap();
        let actor = spawn_config_actor(dir.join("local.yml"), cfg);
        let remote_actor = spawn_config_actor(dir.join("remote.yml"), remote_cfg);

        let mut endpoints = Vec::new();
        for (index, key) in [local_key, remote_key].into_iter().enumerate() {
            lookup.add_endpoint_info(
                EndpointAddr::new(key.public()).with_relay_url(relay_url.clone()),
            );
            let endpoint = Endpoint::builder(presets::Minimal)
                .secret_key(key)
                .alpns(if index == 0 && idle.is_some() {
                    vec![CONTROL_ALPN.to_vec()]
                } else {
                    vec![CONTROL_ALPN.to_vec(), TCP_ALPN.to_vec()]
                })
                .relay_mode(RelayMode::Custom(relay_map.clone()))
                .address_lookup(lookup.clone())
                .clear_ip_transports()
                .bind()
                .await
                .unwrap();
            timeout(Duration::from_secs(5), endpoint.online())
                .await
                .unwrap();
            endpoints.push(endpoint);
        }
        let remote = endpoints.pop().unwrap();
        let local = endpoints.pop().unwrap();
        let listener = bind_local_control_socket(&socket).unwrap();
        let local_server = if let Some(idle) = idle {
            let lock = transport::try_lock(&socket).unwrap().unwrap();
            let guard = LocalControlSocket {
                path: socket.clone(),
            };
            let actor = actor.clone();
            let endpoint = local.clone();
            tokio::spawn(async move {
                let _lock = lock;
                let _guard = guard;
                transport::serve(listener, actor, endpoint, idle)
                    .await
                    .unwrap();
            })
        } else {
            tokio::spawn(run_local_control_server(
                listener,
                actor.clone(),
                local.clone(),
                None,
            ))
        };
        let remote_server = tokio::spawn(run_acceptor(
            remote.clone(),
            remote_actor.clone(),
            vec![port],
            max_connections,
        ));
        Self {
            dir,
            socket,
            port,
            tcp,
            local,
            remote,
            actor,
            remote_actor,
            local_server,
            remote_server,
            relay,
        }
    }

    async fn connect(&self) -> UnixStream {
        open_local_proxy(&self.socket, "remote-host".to_string(), self.port)
            .await
            .unwrap()
    }

    async fn close(self) {
        self.local_server.abort();
        let _ = self.local_server.await;
        self.local.close().await;
        self.remote.close().await;
        timeout(Duration::from_secs(5), self.remote_server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.relay.shutdown().await.unwrap();
        fs::remove_dir_all(self.dir).unwrap();
    }
}

async fn exchange(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let (mut read, mut write) = stream.split();
        let mut received = vec![0; payload.len()];
        tokio::try_join!(write.write_all(payload), read.read_exact(&mut received))?;
        assert_eq!(received, payload);
        Ok(())
    })
    .await
    .context("echo timed out")?
}

async fn echo_server(listener: TcpListener) {
    let mut sessions = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.unwrap();
                sessions.spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = io::copy(&mut read, &mut write).await;
                });
            }
            _ = sessions.join_next(), if !sessions.is_empty() => {}
        }
    }
}

#[tokio::test]
async fn concurrent_proxy_sessions_share_endpoint_over_relay() {
    timeout(Duration::from_secs(50), async {
        // Exercise a configured limit above the previous hard-coded limit of eight.
        let mut fixture = ProxyFixture::new(9).await;
        let replacement = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let echo = tokio::spawn(echo_server(std::mem::replace(
            &mut fixture.tcp,
            replacement,
        )));
        let mut jobs = tokio::task::JoinSet::new();
        for id in 0..9u8 {
            let path = fixture.socket.clone();
            let port = fixture.port;
            jobs.spawn(async move {
                let mut stream = open_local_proxy(&path, "remote-host".to_string(), port)
                    .await
                    .unwrap();
                exchange(&mut stream, &vec![id; 128 * 1024]).await.unwrap();
                stream
            });
        }
        let mut sessions = Vec::new();
        while let Some(result) = jobs.join_next().await {
            sessions.push(result.unwrap());
        }
        // A rejected connection must not interfere with existing sessions.
        if let Ok(mut excess) =
            open_local_proxy(&fixture.socket, "remote-host".to_string(), fixture.port).await
        {
            assert!(exchange(&mut excess, b"over quota").await.is_err());
        }

        let mut ended = sessions.pop().unwrap();
        ended.shutdown().await.unwrap();
        let mut tail = Vec::new();
        timeout(Duration::from_secs(5), ended.read_to_end(&mut tail))
            .await
            .unwrap()
            .unwrap();
        assert!(tail.is_empty());
        drop(ended);

        // Wait past the old timeout around the entire local control handler.
        tokio::time::sleep(LOCAL_CONTROL_SETUP_TIMEOUT + Duration::from_secs(1)).await;
        for (id, session) in sessions.iter_mut().enumerate() {
            exchange(session, &[id as u8; 1024]).await.unwrap();
        }
        let mut reopened = fixture.connect().await;
        exchange(&mut reopened, b"released slot can be reused")
            .await
            .unwrap();
        // Control requests can still run alongside active tunnels.
        let status =
            send_local_control_request_to_path(&fixture.socket, LocalControlRequest::Status)
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(status, LocalControlOk::Status { .. }));
        assert_eq!(
            fixture.relay.metrics().server.clients_inactive_added.get(),
            0
        );
        drop(reopened);
        drop(sessions);
        echo.abort();
        fixture.close().await;
    })
    .await
    .expect("relay session test timed out");
}

#[tokio::test]
async fn proxy_preserves_response_after_stdin_eof() {
    let fixture = ProxyFixture::new(8).await;
    let stream = fixture.connect().await;
    let (mut tcp, _) = timeout(Duration::from_secs(5), fixture.tcp.accept())
        .await
        .unwrap()
        .unwrap();
    let payload: Vec<u8> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
    let expected = payload.clone();
    let remote = tokio::spawn(async move {
        let mut request = Vec::new();
        tcp.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request before EOF");
        tcp.write_all(&payload).await.unwrap();
        tcp.shutdown().await.unwrap();
    });
    let mut output = Vec::new();
    timeout(
        Duration::from_secs(10),
        proxy_stdio(&b"request before EOF"[..], &mut output, stream),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(output, expected);
    remote.await.unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn shared_transport_survives_first_proxy_exit_and_closes_after_last_session() {
    let idle = Duration::from_secs(1);
    let mut fixture = ProxyFixture::with_transport_idle(8, Some(idle)).await;
    // Keep the short test timer from expiring while macOS starts fresh binaries.
    let startup_lease = UnixStream::connect(&fixture.socket).await.unwrap();
    let replacement = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let echo = tokio::spawn(echo_server(std::mem::replace(
        &mut fixture.tcp,
        replacement,
    )));
    let start_proxy = || {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_esp"))
            .args(["proxy", "remote-host", &fixture.port.to_string()])
            .env("HOME", &fixture.dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    };
    let mut first = start_proxy();
    let mut second = start_proxy();
    async fn exchange_process(child: &mut tokio::process::Child, payload: &[u8]) {
        timeout(Duration::from_secs(5), async {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(payload)
                .await
                .unwrap();
            let mut received = vec![0; payload.len()];
            if let Err(err) = child
                .stdout
                .as_mut()
                .unwrap()
                .read_exact(&mut received)
                .await
            {
                let mut errors = String::new();
                child
                    .stderr
                    .as_mut()
                    .unwrap()
                    .read_to_string(&mut errors)
                    .await
                    .unwrap();
                panic!(
                    "proxy read failed for {}: {err}: {errors}",
                    String::from_utf8_lossy(payload)
                );
            }
            assert_eq!(received, payload);
        })
        .await
        .unwrap();
    }
    exchange_process(&mut first, b"first SSH session").await;
    exchange_process(&mut second, b"second SSH session").await;
    drop(startup_lease);

    // Client transports do not expose localhost services to inbound peers.
    assert!(
        timeout(
            Duration::from_secs(5),
            fixture.remote.connect(fixture.local.id(), TCP_ALPN)
        )
        .await
        .unwrap()
        .is_err()
    );

    first.kill().await.unwrap();
    tokio::time::sleep(idle * 2).await;
    assert!(!fixture.local_server.is_finished());
    exchange_process(&mut second, b"still connected after first process exited").await;
    let mut third = start_proxy();
    exchange_process(&mut third, b"later session shares the live endpoint").await;
    third.kill().await.unwrap();
    second.stdin.take();
    assert!(
        timeout(Duration::from_secs(5), second.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );

    timeout(Duration::from_secs(5), async {
        while !fixture.local_server.is_finished() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("transport did not exit after its final session");
    assert!(!fixture.socket.exists());
    assert!(transport::try_lock(&fixture.socket).unwrap().is_some());
    assert_eq!(
        fixture.relay.metrics().server.clients_inactive_added.get(),
        0
    );
    echo.abort();
    fixture.close().await;
}

#[tokio::test]
async fn remote_eof_ends_proxy_with_stdin_still_open() {
    let fixture = ProxyFixture::new(8).await;
    let stream = fixture.connect().await;
    let (mut tcp, _) = timeout(Duration::from_secs(5), fixture.tcp.accept())
        .await
        .unwrap()
        .unwrap();
    let (input, _keep_stdin_open) = io::duplex(64);
    let remote = tokio::spawn(async move {
        tcp.write_all(b"goodbye").await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut rest = Vec::new();
        tcp.read_to_end(&mut rest).await.unwrap();
    });
    let mut output = Vec::new();
    timeout(
        Duration::from_secs(5),
        proxy_stdio(input, &mut output, stream),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(output, b"goodbye");
    timeout(Duration::from_secs(5), remote)
        .await
        .unwrap()
        .unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn proxy_setup_errors_leave_daemon_available() {
    let fixture = ProxyFixture::new(8).await;
    let err = open_local_proxy(&fixture.socket, "unknown".to_string(), fixture.port)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("no configured esp peer named unknown"));
    let mut stream = fixture.connect().await;
    let (mut tcp, _) = timeout(Duration::from_secs(5), fixture.tcp.accept())
        .await
        .unwrap()
        .unwrap();
    tcp.write_all(b"still available").await.unwrap();
    let mut response = [0; 15];
    timeout(Duration::from_secs(5), stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"still available");
    drop(tcp);
    drop(stream);
    fixture.close().await;
}

#[tokio::test]
async fn cancelling_local_server_closes_active_proxy_connections() {
    let fixture = ProxyFixture::new(8).await;
    let mut stream = fixture.connect().await;
    let (mut tcp, _) = timeout(Duration::from_secs(5), fixture.tcp.accept())
        .await
        .unwrap()
        .unwrap();
    fixture.local_server.abort();
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        timeout(Duration::from_secs(5), tcp.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    fixture.close().await;
}

#[tokio::test]
async fn revocation_cancels_outgoing_proxy_connections() {
    let fixture = ProxyFixture::new(8).await;
    let mut stream = fixture.connect().await;
    let (mut tcp, _) = timeout(Duration::from_secs(5), fixture.tcp.accept())
        .await
        .unwrap()
        .unwrap();
    fixture
        .actor
        .revoke("remote-host".to_string())
        .await
        .unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        timeout(Duration::from_secs(5), tcp.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(
        open_local_proxy(&fixture.socket, "remote-host".to_string(), fixture.port)
            .await
            .is_err()
    );
    fixture.close().await;
}

#[test]
fn proxy_without_config_fails_without_starting_a_transport() {
    let dir = std::env::temp_dir().join(format!("esp-n-{}", Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_esp"))
        .args(["proxy", "remote-host", "22"])
        .env("HOME", &dir)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("config.yml"), "{stderr}");
    assert!(!stderr.contains("Endpoint dropped"), "{stderr}");
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    fs::remove_dir(dir).unwrap();
}

#[test]
fn daemon_connection_limit_must_be_positive() {
    assert!(Cli::try_parse_from(["esp", "daemon", "--max-connections-per-peer", "0"]).is_err());
    let cli = Cli::try_parse_from(["esp", "daemon", "--max-connections-per-peer", "32"]).unwrap();
    assert!(
        matches!(cli.command, Some(Command::Daemon { max_connections_per_peer, .. }) if max_connections_per_peer.get() == 32)
    );
}

#[tokio::test]
async fn proxy_process_exits_on_remote_eof_with_stdin_open() {
    let fixture = ProxyFixture::new(8).await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_esp"))
        .args(["proxy", "remote-host", &fixture.port.to_string()])
        .env("HOME", &fixture.dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let _keep_stdin_open = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let (mut tcp, _) = timeout(Duration::from_secs(5), fixture.tcp.accept())
        .await
        .unwrap()
        .unwrap();
    tcp.write_all(b"goodbye from process test").await.unwrap();
    tcp.shutdown().await.unwrap();
    let status = timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("proxy process did not exit after remote EOF")
        .unwrap();
    assert!(status.success());
    let mut output = Vec::new();
    stdout.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, b"goodbye from process test");
    let mut errors = String::new();
    stderr.read_to_string(&mut errors).await.unwrap();
    assert!(!errors.contains("Endpoint dropped"), "{errors}");
    fixture.close().await;
}

#[tokio::test(start_paused = true)]
async fn incomplete_local_request_still_times_out() {
    let key = SecretKey::generate();
    let cfg = create_creator_config(
        &key,
        Uuid::new_v4().to_string(),
        "local".to_string(),
        "ABC123".to_string(),
        DEFAULT_MAX_KNOWN_PEERS,
    )
    .unwrap();
    let actor = spawn_config_actor(
        std::env::temp_dir().join(format!("esp-unused-{}", Uuid::new_v4())),
        cfg,
    );
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .bind()
        .await
        .unwrap();
    let (_client, server) = UnixStream::pair().unwrap();
    let task = tokio::spawn(handle_local_control_connection(
        server,
        actor,
        endpoint.clone(),
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(LOCAL_CONTROL_SETUP_TIMEOUT + Duration::from_secs(1)).await;
    let err = task.await.unwrap().unwrap_err();
    assert!(format!("{err:#}").contains("timed out reading local esp control request"));
    endpoint.close().await;
}

#[tokio::test]
async fn join_bootstraps_cbor_membership_and_policy_over_relay() {
    let fixture = ProxyFixture::new(8).await;
    let acceptor = tokio::spawn(run_acceptor(
        fixture.local.clone(),
        fixture.actor.clone(),
        vec![fixture.port],
        8,
    ));
    let code = fixture
        .actor
        .issue_invite(
            "Test peer".to_string(),
            vec![fixture.port],
            MembershipRole::Peer,
        )
        .await
        .unwrap()
        .code;
    let invite = Invite::decode(&code).unwrap();
    let key = SecretKey::generate();
    let inviter = Peer {
        node_id: invite.inviter_node_id,
        name: String::new(),
        connection_id: String::new(),
    };
    let mut cfg = Config {
        version: CONFIG_VERSION,
        network_id: invite.network_id.clone(),
        network_policy: pending_join_network_policy(&invite.network_id, invite.creator_node_id),
        secret_key: encode_secret_key(&key),
        creator_node_id: invite.creator_node_id,
        invite_proof: Some(InviteProof {
            invite_id: invite.invite_id,
            invite_secret: invite.invite_secret,
        }),
        membership: None,
        memberships: Vec::new(),
        name: "joined-host".to_string(),
        connection_id: "XYZ789".to_string(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: vec![inviter.clone()],
        revocations: Vec::new(),
    };
    let relay_url = fixture.relay.http_url().unwrap();
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(EndpointAddr::new(inviter.node_id).with_relay_url(relay_url.clone()));
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .clear_ip_transports()
        .relay_mode(RelayMode::Custom(iroh::RelayMap::from(RelayConfig::new(
            relay_url, None,
        ))))
        .address_lookup(lookup)
        .bind()
        .await
        .unwrap();
    timeout(Duration::from_secs(10), async {
        let conn = endpoint
            .connect(inviter.node_id, CONTROL_ALPN)
            .await
            .unwrap();
        assert!(
            sync_control_config(&conn, &mut cfg, &inviter, true)
                .await
                .unwrap()
        );
        conn.close(GRACEFUL_CLOSE, b"synced");
    })
    .await
    .expect("CBOR join timed out");
    ensure_completed_join(&cfg).unwrap();
    assert!(cfg.invite_proof.is_none());
    assert_eq!(
        cfg.membership.as_ref().unwrap().allowed_ports,
        vec![fixture.port]
    );
    cfg.membership.as_ref().unwrap().verify_signature().unwrap();
    cfg.network_policy.verify_signature().unwrap();
    let path = fixture.dir.join("joined.yml");
    save_completed_join(&path, &cfg).unwrap();
    let loaded = Config::load(&path).unwrap();
    assert_eq!(loaded.membership, cfg.membership);
    assert_eq!(loaded.network_policy, cfg.network_policy);
    assert!(fixture.actor.status().await.unwrap().invites.is_empty());
    endpoint.close().await;
    acceptor.abort();
    fixture.close().await;
}

#[tokio::test]
async fn admin_presence_tracks_authorized_incoming_and_outgoing_tunnels() {
    timeout(Duration::from_secs(20), async {
        let mut fixture = ProxyFixture::new(8).await;
        let local_acceptor = tokio::spawn(run_acceptor(
            fixture.local.clone(),
            fixture.actor.clone(),
            vec![fixture.port],
            8,
        ));
        let replacement = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let echo = tokio::spawn(echo_server(std::mem::replace(
            &mut fixture.tcp,
            replacement,
        )));
        async fn detail(fixture: &ProxyFixture) -> admin::PeerDetail {
            let response = fixture
                .actor
                .request(|respond| ConfigActorCommand::Admin {
                    request: admin::Request::Detail {
                        node_id: fixture.remote.id(),
                    },
                    respond,
                })
                .await
                .unwrap();
            let admin::Response::Detail(detail) = response else {
                panic!()
            };
            detail
        }
        let rejected_port = if fixture.port == 22 { 23 } else { 22 };
        assert!(
            open_local_proxy(&fixture.socket, "remote-host".into(), rejected_port)
                .await
                .is_err()
        );
        let initial = detail(&fixture).await;
        assert_eq!(initial.peer.active_connections, 0);
        assert_eq!(initial.last_connected, None);
        assert!(
            Config::load(&fixture.dir.join("remote.yml"))
                .unwrap()
                .peer_last_connected
                .is_empty()
        );

        let mut outgoing = fixture.connect().await;
        exchange(&mut outgoing, b"outgoing session").await.unwrap();
        assert_eq!(detail(&fixture).await.peer.active_connections, 1);
        let mut incoming = open_proxy_tunnel(
            &fixture.remote,
            &fixture.remote_actor,
            "local".into(),
            fixture.port,
        )
        .await
        .unwrap();
        incoming.send.write_all(b"incoming session").await.unwrap();
        let mut bytes = [0; 16];
        incoming.recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"incoming session");
        assert_eq!(detail(&fixture).await.peer.active_connections, 2);
        assert!(detail(&fixture).await.last_connected.is_some());
        drop(incoming);
        timeout(Duration::from_secs(5), async {
            while detail(&fixture).await.peer.active_connections != 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        drop(outgoing);
        timeout(Duration::from_secs(5), async {
            while detail(&fixture).await.peer.active_connections != 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(detail(&fixture).await.last_connected.is_some());
        assert!(
            Config::load(&fixture.dir.join("remote.yml"))
                .unwrap()
                .peer_last_connected
                .contains_key(&fixture.local.id().to_string())
        );
        local_acceptor.abort();
        echo.abort();
        fixture.close().await;
    })
    .await
    .unwrap();
}
