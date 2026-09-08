#![cfg(unix)]
#![allow(dead_code)]
include!("../src/main.rs");

use iroh::address_lookup::memory::MemoryLookup;
use networks::{
    GlobalConfig, Manager, Request as ManagerRequest, Runtime, Store, TransportOverrides,
    TransportSettings,
};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Mutex};

struct Profile {
    dir: PathBuf,
    store: Store,
}
impl Profile {
    fn new() -> Self {
        let dir = PathBuf::from("/tmp").join(format!(
            "esp-m-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ));
        fs::create_dir(&dir).unwrap();
        let store = Store {
            root: dir.join(ESP_DIR),
        };
        store.prepare().unwrap();
        Self { dir, store }
    }
    fn command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_esp"));
        command
            .env("HOME", &self.dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        command
    }
    async fn report(&self, args: &[&str]) -> serde_json::Value {
        let result = self
            .command()
            .args(args)
            .args(["--format", "json", "--no-color"])
            .output()
            .await
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice(&result.stdout).unwrap()
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn concurrent_init_is_serialized_and_networks_have_separate_identities() {
    let profile = Profile::new();
    let mut children = Vec::new();
    for _ in 0..8 {
        children.push(
            profile
                .command()
                .args(["init", "Work", "--format", "json", "--no-color"])
                .spawn()
                .unwrap(),
        );
    }
    let mut ids = HashSet::new();
    for child in children {
        let result = child.wait_with_output().await.unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        ids.insert(report["network_id"].as_str().unwrap().to_string());
    }
    assert_eq!(ids.len(), 1);
    let work = profile.store.select("Work").unwrap();
    let other = profile.report(&["init", "Personal"]).await;
    assert_ne!(work.network_id, other["network_id"]);
    assert_ne!(
        work.secret_key().unwrap().public().to_string(),
        other["node_id"]
    );
    profile.report(&["init", "Work", "--max-peers", "7"]).await;
    assert_eq!(
        profile
            .store
            .select("Work")
            .unwrap()
            .network_policy
            .max_peers,
        100
    );
    profile.report(&["rename", "Work", "same-host"]).await;
    profile.report(&["rename", "Personal", "same-host"]).await;
    let summary = profile.report(&["status", "--peers"]).await;
    assert_eq!(summary["networks"][0]["network_label"], "Personal");
    assert_eq!(summary["networks"][1]["network_label"], "Work");
    assert!(summary["networks"][0]["connected_peers"].is_null());
    let global: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(profile.store.root.join(CONFIG_FILE)).unwrap())
            .unwrap();
    assert_eq!(global["version"].as_u64(), Some(3));
    assert!(global.get("secret_key").is_none());
}

#[test]
fn transport_precedence_and_empty_inbound_allowlist() {
    let global = GlobalConfig::default();
    let network = TransportOverrides {
        ports: Some(vec![]),
        max_connections_per_peer: Some(2),
    };
    let flags = TransportOverrides {
        ports: Some(vec![443]),
        max_connections_per_peer: Some(5),
    };
    let settings =
        networks::effective_transport(&global, &network, &TransportOverrides::default(), true)
            .unwrap();
    assert!(settings.ports.is_empty());
    assert_eq!(settings.max_connections_per_peer, 2);
    let settings = networks::effective_transport(&global, &network, &flags, true).unwrap();
    assert_eq!(settings.ports, vec![443]);
    assert_eq!(settings.max_connections_per_peer, 5);
    assert!(
        networks::effective_transport(&global, &network, &flags, false)
            .unwrap()
            .ports
            .is_empty()
    );
}

#[tokio::test]
async fn manager_add_remove_failure_isolation_and_permanent_destruction() {
    let profile = Profile::new();
    let mut manager = Manager::start(profile.store.clone(), true, TransportOverrides::default())
        .await
        .unwrap();
    assert!(
        manager.status(None, false).await.unwrap()["networks"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let a = manager
        .lifecycle(ManagerRequest::Init {
            label: "A".into(),
            max_peers: 100,
        })
        .await
        .unwrap()
        .json()
        .unwrap();
    let b = manager
        .lifecycle(ManagerRequest::Init {
            label: "B".into(),
            max_peers: 100,
        })
        .await
        .unwrap()
        .json()
        .unwrap();
    let a_id = a["network_id"].as_str().unwrap();
    let b_id = b["network_id"].as_str().unwrap();
    let b_endpoint = manager.runtime(b_id).unwrap().endpoint.id();
    manager
        .lifecycle(ManagerRequest::Destroy {
            id: a_id.into(),
            global: false,
        })
        .await
        .unwrap();
    assert!(!profile.store.path(a_id).unwrap().exists());
    assert_eq!(manager.runtime(b_id).unwrap().endpoint.id(), b_endpoint);
    manager
        .lifecycle(ManagerRequest::Destroy {
            id: b_id.into(),
            global: true,
        })
        .await
        .unwrap();
    let terminal = profile.store.load(b_id).unwrap();
    assert!(terminal.destruction.is_some());
    assert!(
        manager
            .runtime(b_id)
            .unwrap()
            .actor
            .issue_invite("bad".into(), vec![22], MembershipRole::Peer)
            .await
            .is_err()
    );
    assert!(
        manager.status(None, true).await.unwrap()["networks"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let replacement = manager
        .lifecycle(ManagerRequest::Init {
            label: "B".into(),
            max_peers: 100,
        })
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_ne!(replacement["network_id"], b_id);
    manager.stop().await;
    let broken = Uuid::new_v4().to_string();
    write_private_config(&profile.store.path(&broken).unwrap(), b"version: 2\n").unwrap();
    let mut manager = Manager::start(profile.store.clone(), true, TransportOverrides::default())
        .await
        .unwrap();
    let summary = manager.status(None, false).await.unwrap();
    assert_eq!(summary["networks"].as_array().unwrap().len(), 2);
    assert!(
        summary["networks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["transport"] == "error")
    );
    assert!(profile.store.load(b_id).unwrap().destruction.is_some());
    manager.stop().await;
}

fn pair(label: &str, ports: &[u16]) -> (Config, Config) {
    let key = SecretKey::generate();
    let other_key = SecretKey::generate();
    let mut origin = create_creator_config(
        label,
        &key,
        Uuid::new_v4().to_string(),
        "origin".into(),
        "ORIGIN".into(),
        100,
    )
    .unwrap();
    origin.membership = Some(
        MembershipCertificate::issue(
            &origin,
            &key,
            &origin.local_peer().unwrap(),
            ports,
            MembershipRole::Admin,
        )
        .unwrap(),
    );
    let peer = Peer {
        node_id: other_key.public(),
        name: "same-peer".into(),
        connection_id: "PEER01".into(),
    };
    let member =
        MembershipCertificate::issue(&origin, &key, &peer, ports, MembershipRole::Peer).unwrap();
    let other = Config {
        version: 3,
        transport: TransportOverrides::default(),
        destruction: None,
        network_id: origin.network_id.clone(),
        secret_key: encode_secret_key(&other_key),
        creator_node_id: key.public(),
        network_policy: origin.network_policy.clone(),
        membership: Some(member.clone()),
        memberships: vec![origin.membership.clone().unwrap()],
        invite_proof: None,
        name: peer.name.clone(),
        connection_id: peer.connection_id.clone(),
        invites: Vec::new(),
        peers: vec![origin.local_peer().unwrap()],
        revocations: Vec::new(),
        peer_last_connected: HashMap::new(),
    };
    origin.peers.push(peer);
    origin.memberships.push(member);
    (origin, other)
}

#[test]
fn destruction_authority_tampering_revocation_and_cross_network_rejection() {
    let (mut origin, member) = pair("A", &[22]);
    let valid = destruction::Certificate::issue(&origin).unwrap();
    valid.verify(&member).unwrap();
    assert!(destruction::Certificate::issue(&member).is_err());
    for which in 0..4 {
        let mut altered = valid.clone();
        match which {
            0 => altered.network_id = Uuid::new_v4().to_string(),
            1 => altered.issued_at_unix += 1,
            2 => altered.version = 2,
            _ => altered.authority[0].role = MembershipRole::Peer,
        }
        assert!(altered.verify(&member).is_err());
    }
    let (different, _) = pair("B", &[22]);
    assert!(valid.verify(&different).is_err());
    let peer = origin.peers[0].clone();
    let admin = MembershipCertificate::issue(
        &origin,
        &origin.secret_key().unwrap(),
        &peer,
        &[22],
        MembershipRole::Admin,
    )
    .unwrap();
    origin.memberships[0] = admin.clone();
    let mut delegated = member;
    delegated.membership = Some(admin);
    let delegated_cert = destruction::Certificate::issue(&delegated).unwrap();
    delegated_cert.verify(&origin).unwrap();
    origin.issue_revocation(&peer.node_id.to_string()).unwrap();
    assert!(delegated_cert.verify(&origin).is_err());
}

#[test]
fn peer_labels_and_hostnames_are_scoped_and_ambiguous_names_fail_with_ids() {
    let (mut cfg, _) = pair("A", &[22]);
    let mut other = cfg.peers[0].clone();
    other.node_id = SecretKey::generate().public();
    other.connection_id = "PEER02".into();
    cfg.memberships.push(
        MembershipCertificate::issue(
            &cfg,
            &cfg.secret_key().unwrap(),
            &other,
            &[22],
            MembershipRole::Peer,
        )
        .unwrap(),
    );
    cfg.peers.push(other.clone());
    let error = cfg.resolve_peer("same-peer").unwrap_err().to_string();
    assert!(error.contains(&other.node_id.to_string()));
    assert!(error.contains("PEER01"));
    assert_eq!(cfg.resolve_peer("PEER02").unwrap().node_id, other.node_id);
    assert_eq!(
        cfg.resolve_peer(&other.node_id.to_string())
            .unwrap()
            .node_id,
        other.node_id
    );
}

async fn endpoint(cfg: &Config, lookup: &MemoryLookup) -> Endpoint {
    let ep = Endpoint::builder(presets::Minimal)
        .secret_key(cfg.secret_key().unwrap())
        .relay_mode(RelayMode::Disabled)
        .address_lookup(lookup.clone())
        .alpns(vec![
            CONTROL_ALPN.to_vec(),
            TCP_ALPN.to_vec(),
            destruction::ALPN.to_vec(),
        ])
        .bind()
        .await
        .unwrap();
    lookup.add_endpoint_info(ep.addr());
    ep
}
async fn exchange(stream: &mut UnixStream, expected: &[u8]) {
    stream.write_all(expected).await.unwrap();
    let mut received = vec![0; expected.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn simultaneous_network_proxies_survive_promotion_and_isolate_removal() {
    let local = Profile::new();
    let remote = Profile::new();
    let mut manager = Manager::start(local.store.clone(), false, TransportOverrides::default())
        .await
        .unwrap();
    let lookup = MemoryLookup::new();
    let mut remotes = Vec::new();
    let mut ids = Vec::new();
    let mut echoes = tokio::task::JoinSet::new();
    let mut ports = Vec::new();
    for label in ["A", "B"] {
        let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        ports.push(port);
        echoes.spawn(async move { let mut clients = tokio::task::JoinSet::new(); loop { tokio::select! { result = tcp.accept() => { let (mut client, _) = result.unwrap(); clients.spawn(async move { let (mut reader, mut writer) = client.split(); let _ = io::copy(&mut reader, &mut writer).await; }); }, _ = clients.join_next(), if !clients.is_empty() => {} } } });
        let (cfg, mut other) = pair(label, &[port]);
        other.transport.ports = Some(vec![port]);
        let id = cfg.network_id.clone();
        ids.push(id.clone());
        let local_path = local.store.path(&id).unwrap();
        let remote_path = remote.store.path(&id).unwrap();
        cfg.save(&local_path).unwrap();
        other.save(&remote_path).unwrap();
        let ep = endpoint(&cfg, &lookup).await;
        let remote_ep = endpoint(&other, &lookup).await;
        manager
            .replace_runtime(
                &id,
                Runtime::attach(
                    local_path,
                    cfg,
                    TransportSettings {
                        ports: vec![],
                        max_connections_per_peer: 8,
                    },
                    ep,
                ),
            )
            .await;
        remotes.push(Runtime::attach(
            remote_path,
            other,
            TransportSettings {
                ports: vec![port],
                max_connections_per_peer: 8,
            },
            remote_ep,
        ));
    }
    let socket = local.store.root.join(LOCAL_CONTROL_SOCKET_FILE);
    let listener = bind_local_control_socket(&socket).unwrap();
    let manager = Arc::new(Mutex::new(manager));
    let server = tokio::spawn(networks::serve_manager(
        listener,
        manager.clone(),
        Duration::from_secs(60),
    ));
    let mut a = networks::request_proxy(
        UnixStream::connect(&socket).await.unwrap(),
        ids[0].clone(),
        "same-peer".into(),
        ports[0],
    )
    .await
    .unwrap();
    let mut b = networks::request_proxy(
        UnixStream::connect(&socket).await.unwrap(),
        ids[1].clone(),
        "same-peer".into(),
        ports[1],
    )
    .await
    .unwrap();
    let ((), ()) = tokio::join!(
        exchange(&mut a, b"alpha-before"),
        exchange(&mut b, b"beta-before")
    );
    let node = manager.lock().await.runtime(&ids[0]).unwrap().endpoint.id();
    manager
        .lock()
        .await
        .promote(TransportOverrides {
            ports: Some(ports.clone()),
            max_connections_per_peer: Some(4),
        })
        .await
        .unwrap();
    assert_eq!(
        manager.lock().await.runtime(&ids[0]).unwrap().endpoint.id(),
        node
    );
    assert!(
        manager
            .lock()
            .await
            .promote(TransportOverrides::default())
            .await
            .is_err()
    );
    let ((), ()) = tokio::join!(
        exchange(&mut a, b"alpha-after"),
        exchange(&mut b, b"beta-after")
    );
    // B cannot forward A's port; membership and inbound settings both stay scoped.
    assert!(
        networks::request_proxy(
            UnixStream::connect(&socket).await.unwrap(),
            ids[1].clone(),
            "same-peer".into(),
            ports[0]
        )
        .await
        .is_err()
    );
    manager
        .lock()
        .await
        .lifecycle(ManagerRequest::Destroy {
            id: ids[0].clone(),
            global: false,
        })
        .await
        .unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(5), a.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    exchange(&mut b, b"beta-still-live").await;
    drop(b);
    server.abort();
    let _ = server.await;
    manager.lock().await.stop().await;
    for runtime in remotes {
        runtime.stop().await;
    }
    echoes.abort_all();
}

#[tokio::test]
async fn destruction_delivers_to_an_offline_member_after_origin_restart() {
    let origin = Profile::new();
    let member = Profile::new();
    let (cfg, other) = pair("A", &[22]);
    let id = cfg.network_id.clone();
    let origin_path = origin.store.path(&id).unwrap();
    let member_path = member.store.path(&id).unwrap();
    cfg.save(&origin_path).unwrap();
    other.save(&member_path).unwrap();
    let actor = spawn_config_actor(origin_path.clone(), cfg.clone());
    actor
        .request(|respond| ConfigActorCommand::Destroy {
            certificate: None,
            respond,
        })
        .await
        .unwrap();
    actor
        .request(|respond| ConfigActorCommand::Stop { respond })
        .await
        .unwrap();
    let terminal = Config::load(&origin_path).unwrap();
    assert_eq!(terminal.destruction.as_ref().unwrap().pending.len(), 1);
    let lookup = MemoryLookup::new();
    let a = endpoint(&terminal, &lookup).await;
    let b = endpoint(&other, &lookup).await;
    let origin_runtime = Runtime::attach(
        origin_path.clone(),
        terminal,
        TransportSettings::default(),
        a,
    );
    let member_runtime =
        Runtime::attach(member_path.clone(), other, TransportSettings::default(), b);
    timeout(Duration::from_secs(10), async {
        loop {
            if Config::load(&member_path).unwrap().destruction.is_some()
                && Config::load(&origin_path)
                    .unwrap()
                    .destruction
                    .unwrap()
                    .pending
                    .is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        member_runtime
            .actor
            .rename("resurrection".into())
            .await
            .is_err()
    );
    assert!(
        member_runtime
            .actor
            .prepare_proxy("origin".into(), 22)
            .await
            .is_err()
    );
    origin_runtime.stop().await;
    member_runtime.stop().await;
    Config::load(&member_path)
        .unwrap()
        .destruction
        .unwrap()
        .certificate
        .verify(&cfg)
        .unwrap();
}

#[tokio::test]
async fn destroy_requires_confirmation_and_global_requires_serving_mode() {
    let profile = Profile::new();
    profile.report(&["init", "A"]).await;
    let result = profile
        .command()
        .args(["destroy", "A"])
        .output()
        .await
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--yes"));
    let result = profile
        .command()
        .args(["destroy", "A", "--global", "--yes"])
        .output()
        .await
        .unwrap();
    assert!(!result.status.success());
    assert!(profile.store.select("A").is_ok());
    profile.report(&["destroy", "A", "--yes"]).await;
    assert!(profile.store.select("A").is_err());
}

#[tokio::test]
async fn invitation_label_collisions_and_failed_joins_do_not_create_state() {
    let profile = Profile::new();
    profile.report(&["init", "Taken"]).await;
    let mut other = create_creator_config(
        "Taken",
        &SecretKey::generate(),
        Uuid::new_v4().to_string(),
        "remote".into(),
        "REMOTE".into(),
        100,
    )
    .unwrap();
    let code = other
        .issue_invite("new", &[22], MembershipRole::Peer)
        .unwrap()
        .code;
    let result = profile
        .command()
        .args(["join", &code])
        .output()
        .await
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("already used locally"));
    let code = "invalid-code";
    let result = profile
        .command()
        .args(["join", code])
        .output()
        .await
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(
        fs::read_dir(profile.store.root.join("networks"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn invitation_label_tampering_is_rejected_before_consuming_the_invite() {
    let (mut cfg, _) = pair("Signed label", &[22]);
    let code = cfg
        .issue_invite("new peer", &[22], MembershipRole::Peer)
        .unwrap()
        .code;
    let invite = Invite::decode(&code).unwrap();
    let remote = Hello {
        network_id: cfg.network_id.clone(),
        network_label: "Tampered label".into(),
        network_policy: None,
        name: "new peer".into(),
        connection_id: "NEW001".into(),
        invite_proof: Some(InviteProof {
            invite_id: invite.invite_id,
            invite_secret: invite.invite_secret,
        }),
        membership: None,
        memberships: vec![],
        peers: vec![],
        revocations: vec![],
    };
    let count = cfg.invites.len();
    assert!(apply_control_sync(&mut cfg, SecretKey::generate().public(), remote, None).is_err());
    assert_eq!(cfg.invites.len(), count);
}
