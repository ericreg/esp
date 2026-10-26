use super::*;
use iroh::{EndpointAddr, RelayConfig, address_lookup::memory::MemoryLookup};
use iroh_relay::server::{Server, testing};
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
        transport: networks::TransportOverrides::default(),
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

struct Fixture {
    dir: PathBuf,
    host: Endpoint,
    client: Endpoint,
    host_actor: ConfigActorHandle,
    client_actor: ConfigActorHandle,
    accept: tokio::task::JoinHandle<Result<()>>,
    relay: Option<Server>,
}
impl Fixture {
    async fn new(relayed: bool) -> Self {
        let dir = std::env::temp_dir().join(format!("esp-video-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        // Membership currently requires a port; the acceptor enables no TCP serving.
        let (a, b) = pair("Video test", &[22]);
        a.save(&dir.join("a.yml")).unwrap();
        b.save(&dir.join("b.yml")).unwrap();
        let lookup = MemoryLookup::new();
        let mut relay = None;
        let mode = if relayed {
            let mut config = testing::server_config();
            config.relay.as_mut().unwrap().tls = None;
            config.quic = None;
            let server = Server::spawn(config).await.unwrap();
            let url = server.http_url().unwrap();
            for cfg in [&a, &b] {
                lookup.add_endpoint_info(
                    EndpointAddr::new(cfg.secret_key().unwrap().public())
                        .with_relay_url(url.clone()),
                );
            }
            relay = Some(server);
            RelayMode::Custom(iroh::RelayMap::from(RelayConfig::new(url, None)))
        } else {
            RelayMode::Disabled
        };
        let mut endpoints = Vec::new();
        for cfg in [&a, &b] {
            let mut builder = Endpoint::builder(presets::Minimal)
                .secret_key(cfg.secret_key().unwrap())
                .alpns(vec![ALPN.to_vec()])
                .relay_mode(mode.clone())
                .address_lookup(lookup.clone());
            if relayed {
                builder = builder.clear_ip_transports();
            }
            let ep = builder.bind().await.unwrap();
            if relayed {
                timeout(Duration::from_secs(5), ep.online()).await.unwrap();
            } else {
                lookup.add_endpoint_info(ep.addr());
            }
            endpoints.push(ep);
        }
        let client = endpoints.pop().unwrap();
        let host = endpoints.pop().unwrap();
        let host_actor = spawn_config_actor(dir.join("a.yml"), a);
        let client_actor = spawn_config_actor(dir.join("b.yml"), b);
        let accept = tokio::spawn(run_acceptor(
            host.clone(),
            host_actor.clone(),
            Vec::new(),
            8,
        ));
        Self {
            dir,
            host,
            client,
            host_actor,
            client_actor,
            accept,
            relay,
        }
    }
    async fn owner(&self) -> (UnixStream, tokio::task::JoinHandle<Result<()>>, String) {
        let (mut owner, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(local(
            server,
            self.host_actor.clone(),
            self.host.clone(),
            LocalRequest::Share {
                peer: "same-peer".into(),
                display: "test-source".into(),
                format: format(),
            },
        ));
        let ready: Reply = read_cbor_frame(&mut owner, CONTROL_LIMIT, "test owner")
            .await
            .unwrap();
        let Reply::Ready { share, .. } = ready else {
            panic!("{ready:?}")
        };
        (owner, task, share)
    }
    async fn view(
        &self,
        resume: Option<String>,
    ) -> (UnixStream, tokio::task::JoinHandle<Result<()>>, Reply) {
        let (mut client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(local(
            server,
            self.client_actor.clone(),
            self.client.clone(),
            LocalRequest::View {
                host: "origin".into(),
                resume,
            },
        ));
        let reply = timeout(
            Duration::from_secs(5),
            read_cbor_frame(&mut client, CONTROL_LIMIT, "test viewer"),
        )
        .await
        .unwrap()
        .unwrap();
        (client, task, reply)
    }
    async fn close(self) {
        self.host_actor.video.stop();
        for actor in [&self.host_actor, &self.client_actor] {
            actor
                .request(|respond| ConfigActorCommand::Stop { respond })
                .await
                .unwrap();
        }
        self.client.close().await;
        self.host.close().await;
        timeout(Duration::from_secs(5), self.accept)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Some(relay) = self.relay {
            relay.shutdown().await.unwrap();
        }
        fs::remove_dir_all(self.dir).unwrap();
    }
}
fn format() -> Format {
    Format {
        width: 64,
        height: 48,
        fps: 30,
        kbps: 4000,
    }
}
fn frame(sequence: u64) -> Frame {
    Frame {
        sequence,
        timestamp_us: sequence * 33333,
        key: true,
        data: vec![0x12, 0].into(),
    }
}
async fn ack(client: &mut UnixStream, sequence: u64) {
    client.write_all(&[1]).await.unwrap();
    client.write_all(&sequence.to_be_bytes()).await.unwrap();
}
async fn exchange(relayed: bool) {
    let f = Fixture::new(relayed).await;
    let (mut owner, owner_task, id) = f.owner().await;
    let (mut client, client_task, reply) = f.view(None).await;
    assert!(matches!(reply,Reply::Ready {share,..} if share==id));
    for seq in 0..4 {
        write_frame(&mut owner, &frame(seq)).await.unwrap();
        let received = timeout(Duration::from_secs(3), read_frame(&mut client))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.sequence, seq);
        ack(&mut client, seq).await;
    }
    drop(client);
    let _ = timeout(Duration::from_secs(3), client_task)
        .await
        .unwrap()
        .unwrap();
    drop(owner);
    assert!(
        timeout(Duration::from_secs(3), owner_task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(f.host_actor.video.status()["state"], "stopped");
    f.close().await;
}
#[tokio::test]
async fn direct_video_without_tcp_serving() {
    exchange(false).await;
}
#[tokio::test]
async fn forced_relay_video_without_tcp_serving() {
    exchange(true).await;
}
#[tokio::test]
async fn no_grant_and_stale_share_are_rejected() {
    let f = Fixture::new(false).await;
    let (_, task, reply) = f.view(None).await;
    assert!(matches!(reply, Reply::Error(_) | Reply::Rejected(_)));
    task.await.unwrap().unwrap();
    let (owner, task, _) = f.owner().await;
    let (_, view, reply) = f.view(Some(Uuid::new_v4().to_string())).await;
    assert!(matches!(reply, Reply::Error(_) | Reply::Rejected(_)));
    view.await.unwrap().unwrap();
    drop(owner);
    let _ = task.await;
    f.close().await;
}
#[tokio::test]
async fn stop_revocation_and_single_viewer() {
    for revoke in [false, true] {
        let f = Fixture::new(false).await;
        let (mut owner, owner_task, _) = f.owner().await;
        let (mut client, task, reply) = f.view(None).await;
        assert!(matches!(reply, Reply::Ready { .. }));
        let (_, second, reply) = f.view(None).await;
        assert!(matches!(reply, Reply::Error(_) | Reply::Rejected(_)));
        second.await.unwrap().unwrap();
        write_frame(&mut owner, &frame(0)).await.unwrap();
        let _ = read_frame(&mut client).await.unwrap();
        ack(&mut client, 0).await;
        if revoke {
            f.host_actor.revoke("same-peer".into()).await.unwrap();
        } else {
            f.host_actor.video.stop();
        }
        assert!(
            timeout(Duration::from_secs(3), read_frame(&mut client))
                .await
                .unwrap()
                .is_err()
        );
        let _ = timeout(Duration::from_secs(3), task).await.unwrap();
        let _ = timeout(Duration::from_secs(3), owner_task).await.unwrap();
        assert_eq!(f.host_actor.video.status()["state"], "stopped");
        f.close().await;
    }
}
#[tokio::test]
async fn stalled_presentation_ends_timeline() {
    let f = Fixture::new(false).await;
    let (mut owner, owner_task, _) = f.owner().await;
    let (mut client, client_task, _) = f.view(None).await;
    write_frame(&mut owner, &frame(0)).await.unwrap();
    read_frame(&mut client).await.unwrap();
    ack(&mut client, 0).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    for seq in 1..3 {
        write_frame(&mut owner, &frame(seq)).await.unwrap();
        read_frame(&mut client).await.unwrap();
    }
    write_frame(&mut owner, &frame(3)).await.unwrap();
    assert!(
        timeout(Duration::from_secs(3), read_frame(&mut client))
            .await
            .unwrap()
            .is_err()
    );
    let _ = client_task.await;
    drop(owner);
    let _ = owner_task.await;
    f.close().await;
}
#[tokio::test]
async fn malformed_owner_frame_revokes_grant() {
    let f = Fixture::new(false).await;
    let (mut owner, task, _) = f.owner().await;
    let mut invalid = frame(0);
    invalid.key = false;
    write_frame(&mut owner, &invalid).await.unwrap();
    assert!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(f.host_actor.video.status()["state"], "stopped");
    f.close().await;
}

#[tokio::test]
async fn membership_proofs_are_required_and_bound_to_the_remote_key() {
    let f = Fixture::new(false).await;
    let cfg = snapshot(&f.client_actor).await.unwrap();
    let hello = hello_from_config(&cfg).unwrap();
    let mut missing = hello.clone();
    missing.membership = None;
    assert!(
        authenticate(&f.host_actor, f.client.id(), missing, None)
            .await
            .is_err()
    );
    let mut wrong_network = hello.clone();
    wrong_network.network_id = Uuid::new_v4().to_string();
    assert!(
        authenticate(&f.host_actor, f.client.id(), wrong_network, None)
            .await
            .is_err()
    );
    let mut forged = hello.clone();
    forged.membership.as_mut().unwrap().role = MembershipRole::Admin;
    assert!(
        authenticate(&f.host_actor, f.client.id(), forged, None)
            .await
            .is_err()
    );
    assert!(
        authenticate(&f.host_actor, SecretKey::generate().public(), hello, None)
            .await
            .is_err()
    );
    f.close().await;
}

#[tokio::test]
async fn owner_exit_and_network_destruction_cancel_an_active_viewer() {
    for destroy in [false, true] {
        let f = Fixture::new(false).await;
        let (mut owner, owner_task, _) = f.owner().await;
        let (mut client, client_task, reply) = f.view(None).await;
        assert!(matches!(reply, Reply::Ready { .. }));
        write_frame(&mut owner, &frame(0)).await.unwrap();
        read_frame(&mut client).await.unwrap();
        ack(&mut client, 0).await;
        if destroy {
            f.host_actor
                .request(|respond| ConfigActorCommand::Destroy {
                    certificate: None,
                    respond,
                })
                .await
                .unwrap();
        }
        drop(owner);
        let _ = timeout(Duration::from_secs(3), owner_task).await.unwrap();
        assert!(
            timeout(Duration::from_secs(3), read_frame(&mut client))
                .await
                .unwrap()
                .is_err()
        );
        let _ = timeout(Duration::from_secs(3), client_task).await.unwrap();
        assert_eq!(f.host_actor.video.status()["state"], "stopped");
        f.close().await;
    }
}

#[cfg(feature = "video-codec")]
#[tokio::test]
async fn encoded_pixels_survive_direct_and_relayed_video() {
    use crate::video::codec::{Av1Decoder, Encoder, xrgb_to_yuv};
    for relayed in [false, true] {
        let f = Fixture::new(relayed).await;
        let (mut owner, owner_task, _) = f.owner().await;
        let (mut client, client_task, reply) = f.view(None).await;
        assert!(matches!(reply, Reply::Ready { .. }));
        let mut raw = vec![0; 64 * 48 * 4];
        for pixel in raw.chunks_exact_mut(4) {
            pixel.copy_from_slice(&[0, 0, 255, 0]);
        }
        let yuv = xrgb_to_yuv(&raw, 64, 48, format()).unwrap();
        let mut encoder = Encoder::new(format(), 2).unwrap();
        let mut decoder = Av1Decoder::new(format()).unwrap();
        let mut packets = Vec::new();
        for sequence in 0..8 {
            packets.extend(encoder.encode(&yuv, sequence * 33333, false).unwrap());
        }
        packets.extend(encoder.finish().unwrap());
        assert_eq!(packets.len(), 8);
        for (sequence, packet) in packets.into_iter().enumerate() {
            let sequence = sequence as u64;
            let frame = Frame {
                sequence,
                timestamp_us: packet.timestamp_us,
                key: packet.key,
                data: packet.data.into(),
            };
            write_frame(&mut owner, &frame).await.unwrap();
            let received = timeout(Duration::from_secs(3), read_frame(&mut client))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.data, frame.data);
            let pixels = decoder.decode(&received.data, received.key).unwrap();
            assert!(
                pixels
                    .into_iter()
                    .all(|px| (px >> 16) & 255 > 230 && px & 65535 < 0x1010)
            );
            ack(&mut client, sequence).await;
        }
        drop(client);
        let _ = client_task.await;
        drop(owner);
        let _ = owner_task.await;
        f.close().await;
    }
}
