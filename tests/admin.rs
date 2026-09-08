#![allow(dead_code)]

include!("../src/main.rs");

use admin::{Action, App, PeerDetail, Request, Response, View};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend, style::Color};

fn fixture() -> (Config, SecretKey, Peer) {
    let key = SecretKey::generate();
    let mut cfg = create_creator_config(
        "Office / Lab",
        &key,
        Uuid::new_v4().to_string(),
        "origin".into(),
        "ROOT01".into(),
        ABSOLUTE_MAX_KNOWN_PEERS,
    )
    .unwrap();
    cfg.issue_network_policy_with_label(ABSOLUTE_MAX_KNOWN_PEERS, Some("Office / Lab".into()))
        .unwrap();
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "laptop-host".into(),
        connection_id: "PEER01".into(),
    };
    enroll(&mut cfg, &peer, "Eric laptop");
    (cfg, key, peer)
}

fn enroll(cfg: &mut Config, peer: &Peer, label: &str) -> Invite {
    let invite = Invite::decode(
        &cfg.issue_invite(label, &[22], MembershipRole::Peer)
            .unwrap()
            .code,
    )
    .unwrap();
    let proof = InviteProof {
        invite_id: invite.invite_id.clone(),
        invite_secret: invite.invite_secret.clone(),
    };
    let (grant, _) =
        remember_control_peer_in_config(cfg, peer.clone(), false, Some(&proof), None, &[]).unwrap();
    assert_eq!(
        grant.unwrap().invite_id.as_deref(),
        Some(invite.invite_id.as_str())
    );
    invite
}

fn view(cfg: &Config, online: bool) -> View {
    let Response::Overview(overview) =
        admin::respond(cfg, &HashMap::new(), Request::Overview).unwrap()
    else {
        panic!()
    };
    let Response::Peers { peers, .. } = admin::respond(
        cfg,
        &HashMap::new(),
        Request::Peers {
            revision: overview.revision.clone(),
            offset: 0,
        },
    )
    .unwrap() else {
        panic!()
    };
    View {
        overview,
        peers,
        online,
    }
}

fn get_detail(cfg: &Config, peer: &Peer) -> PeerDetail {
    let Response::Detail(detail) = admin::respond(
        cfg,
        &HashMap::new(),
        Request::Detail {
            node_id: peer.node_id,
        },
    )
    .unwrap() else {
        panic!()
    };
    detail
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn screen(app: &mut App, width: u16, height: u16) -> (String, ratatui::buffer::Buffer) {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let text = buffer
        .content
        .chunks(width as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    (text, buffer)
}

#[test]
fn invite_names_are_required_validated_and_distinct_from_hostnames() {
    assert!(Cli::try_parse_from(["esp", "invite"]).is_err());
    assert!(
        Cli::try_parse_from(["esp", "invite", "Office / Lab", "laptop", "--role", "admin"]).is_ok()
    );
    let (mut cfg, _, peer) = fixture();
    for name in ["", "   ", "line\nbreak", "\x1b[31m", "é", &"x".repeat(65)] {
        assert!(cfg.issue_invite(name, &[22], MembershipRole::Peer).is_err());
    }
    assert!(cfg.invites.is_empty());
    let first = cfg
        .issue_invite("  Same label  ", &[22], MembershipRole::Peer)
        .unwrap();
    let second = cfg
        .issue_invite("Same label", &[22], MembershipRole::Peer)
        .unwrap();
    assert_ne!(first.code, second.code);
    assert_eq!(cfg.invites[0].admin_label, "Same label");
    let member = find_membership_by_subject(&cfg, &[], peer.node_id).unwrap();
    assert_eq!(member.admin_label, "Eric laptop");
    assert_eq!(cfg.peers[0].name, "laptop-host");
    assert_eq!(
        cfg.resolve_peer("Eric laptop").unwrap().node_id,
        peer.node_id
    );
    assert_eq!(
        cfg.resolve_peer("laptop-host").unwrap().node_id,
        peer.node_id
    );
    assert!(cfg.membership.as_ref().unwrap().invite_id.is_none());
    assert_eq!(cfg.membership.as_ref().unwrap().admin_label, "origin");
}

#[test]
fn invite_provenance_is_signed_shared_and_unchanged_by_hostname_rename() {
    let (mut cfg, _, peer) = fixture();
    let member = find_membership_by_subject(&cfg, &[], peer.node_id)
        .unwrap()
        .clone();
    assert!(member.joined_at_unix > 0);
    assert!(member.invite_id.is_some());
    for mut tampered in [member.clone(), member.clone(), member.clone()]
        .into_iter()
        .enumerate()
    {
        match tampered.0 {
            0 => tampered.1.admin_label = "replacement".into(),
            1 => tampered.1.invite_id = Some("OTHER1".into()),
            _ => tampered.1.joined_at_unix += 1,
        }
        assert!(verify_membership_chain(&cfg, &tampered.1, &[]).is_err());
    }
    let hello = hello_from_config(&cfg).unwrap();
    let encoded = minicbor::to_vec(&hello).unwrap();
    let decoded: Hello = cbor::decode_exact(&encoded).unwrap();
    let shared = decoded
        .memberships
        .iter()
        .find(|member| member.subject_node_id == peer.node_id)
        .unwrap();
    assert_eq!(shared, &member);
    let mut renamed = peer.clone();
    renamed.name = "new-hostname".into();
    insert_peer(&mut cfg, renamed.clone()).unwrap();
    member.matches_peer(&cfg, &renamed).unwrap();
    assert_eq!(get_detail(&cfg, &renamed).peer.admin_label, "Eric laptop");
    assert_eq!(get_detail(&cfg, &renamed).peer.hostname, "new-hostname");
    assert_eq!(get_detail(&cfg, &renamed).invite_id, member.invite_id);
    assert_eq!(
        serde_yaml::from_str::<Config>(&serde_yaml::to_string(&cfg).unwrap())
            .unwrap()
            .memberships,
        cfg.memberships
    );
}

#[test]
fn admin_pages_cover_maximum_network_and_detect_directory_changes() {
    let (mut cfg, key, first) = fixture();
    for index in 1..ABSOLUTE_MAX_KNOWN_PEERS {
        let peer = Peer {
            node_id: SecretKey::generate().public(),
            name: format!("host-{index}"),
            connection_id: format!("{index:06}"),
        };
        cfg.memberships.push(
            MembershipCertificate::issue(&cfg, &key, &peer, &[22], MembershipRole::Peer).unwrap(),
        );
        cfg.peers.push(peer);
    }
    let Response::Overview(overview) =
        admin::respond(&cfg, &HashMap::new(), Request::Overview).unwrap()
    else {
        panic!()
    };
    assert_eq!(overview.total, ABSOLUTE_MAX_KNOWN_PEERS);
    let mut seen = HashSet::new();
    for offset in (0..overview.total).step_by(50) {
        let response = admin::respond(
            &cfg,
            &HashMap::new(),
            Request::Peers {
                revision: overview.revision.clone(),
                offset,
            },
        )
        .unwrap();
        let encoded = minicbor::to_vec(&response).unwrap();
        assert!(encoded.len() < MAX_LOCAL_CONTROL_MESSAGE_LEN);
        let decoded: Response = cbor::decode_exact(&encoded).unwrap();
        let Response::Peers { peers, .. } = decoded else {
            panic!()
        };
        assert!(peers.len() <= 50);
        for peer in peers {
            assert!(seen.insert(peer.node_id));
        }
    }
    assert_eq!(seen.len(), overview.total);
    let mut presence = HashMap::new();
    presence.insert(first.node_id, HashSet::from([Uuid::new_v4()]));
    assert!(
        admin::respond(
            &cfg,
            &presence,
            Request::Peers {
                revision: overview.revision.clone(),
                offset: 0
            }
        )
        .is_ok()
    );
    cfg.peers[0].name = "changed".into();
    assert!(
        admin::respond(
            &cfg,
            &presence,
            Request::Peers {
                revision: overview.revision,
                offset: 0
            }
        )
        .is_err()
    );
}

#[test]
fn render_three_panes_connection_colors_offline_and_small_terminals() {
    let assert_transport_style = |buffer: &ratatui::buffer::Buffer, value: &str, color| {
        let row: String = (0..buffer.area.width)
            .map(|x| buffer[(x, 3)].symbol())
            .collect();
        let phrase = format!("transport: {value}");
        let start = row[..row.find(&phrase).expect("transport status in header")]
            .chars()
            .count() as u16;
        for x in start..start + "transport:".len() as u16 {
            let cell = &buffer[(x, 3)];
            assert_eq!(cell.fg, Color::Reset);
            assert!(cell.modifier.contains(ratatui::style::Modifier::BOLD));
        }
        let start = start + "transport: ".len() as u16;
        for x in start..start + value.len() as u16 {
            let cell = &buffer[(x, 3)];
            assert_eq!(cell.fg, color);
            assert!(cell.modifier.contains(ratatui::style::Modifier::BOLD));
        }
    };
    let (cfg, _, peer) = fixture();
    let mut app = App::new(view(&cfg, true));
    app.view.peers[0].active_connections = 2;
    app.view.overview.connected = 1;
    app.detail = Some(get_detail(&cfg, &peer));
    let (text, buffer) = screen(&mut app, 120, 30);
    assert_transport_style(&buffer, "running", Color::Green);
    for text_part in [
        "esp admin",
        "network_id:",
        "network_label: Office / Lab",
        "transport: running",
        "Peers",
        "Peer details",
        "Eric laptop",
        "laptop-host",
        "invite_id:",
        "last_connected:",
        "Never observed",
        "status: connected",
    ] {
        assert!(text.contains(text_part), "missing {text_part}:\n{text}");
    }
    assert!(
        buffer
            .content
            .iter()
            .any(|cell| cell.fg == Color::Green && cell.symbol() == "E")
    );
    // Inspect the details pane independently of the bold selected peer row.
    for label in [
        "admin_label:",
        "hostname:",
        "connection_id:",
        "node_id:",
        "status:",
        "role:",
        "allowed_ports:",
        "invite_id:",
        "inviter:",
        "joined:",
        "active_connections:",
        "last_connected:",
    ] {
        let row = (0..30)
            .find(|&y| {
                (63..119)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .starts_with(label)
            })
            .unwrap_or_else(|| panic!("missing detail label {label}"));
        for x in 63..63 + label.len() as u16 {
            assert!(
                buffer[(x, row)]
                    .modifier
                    .contains(ratatui::style::Modifier::BOLD),
                "{label}"
            );
        }
        // Long IDs wrap in the narrower third pane; inspect the first nonblank value cell.
        let value = (row..30)
            .find_map(|y| {
                let start = if y == row {
                    64 + label.len() as u16
                } else {
                    63
                };
                (start..119)
                    .map(|x| &buffer[(x, y)])
                    .find(|cell| cell.symbol() != " ")
            })
            .unwrap();
        if label == "status:" {
            assert_eq!(value.symbol(), "c");
            assert_eq!(value.fg, Color::Green);
            assert!(value.modifier.contains(ratatui::style::Modifier::BOLD));
        } else {
            assert_eq!(value.fg, Color::LightBlue, "value for {label}");
            assert!(
                !value.modifier.contains(ratatui::style::Modifier::BOLD),
                "value for {label}"
            );
        }
    }
    app.stale("transport stopped".into());
    let (text, buffer) = screen(&mut app, 80, 24);
    assert_transport_style(&buffer, "not_running", Color::Red);
    assert!(text.contains("Unknown"));
    assert!(text.contains("read only"));
    assert!(text.contains("transport: not_running"));
    assert!(!buffer.content.iter().any(|cell| cell.fg == Color::Green));
    let (text, buffer) = screen(&mut app, 120, 30);
    assert!(text.contains("connection_status: unknown"));
    let row: String = (0..120).map(|x| buffer[(x, 3)].symbol()).collect();
    let start = row[..row.find("connection_status:").unwrap()]
        .chars()
        .count() as u16;
    for x in start..start + 18 {
        assert_eq!(buffer[(x, 3)].fg, Color::White);
        assert!(
            buffer[(x, 3)]
                .modifier
                .contains(ratatui::style::Modifier::BOLD)
        );
    }
    for x in start + 19..start + 26 {
        assert_eq!(buffer[(x, 3)].fg, Color::Gray);
        assert!(
            !buffer[(x, 3)]
                .modifier
                .contains(ratatui::style::Modifier::BOLD)
        );
    }
    assert!(screen(&mut app, 50, 10).0.contains("Resize terminal"));
    assert!(screen(&mut app, 120, 30).0.contains("Peer details"));
}

#[test]
fn revocation_prompt_accepts_yes_and_no_and_checks_online_state() {
    let (cfg, _, peer) = fixture();
    let mut app = App::new(view(&cfg, true));
    app.key(key(KeyCode::Char('r')));
    assert!(
        screen(&mut app, 120, 30)
            .0
            .contains("remove peer Eric laptop from network \"Office / Lab\"? y/n")
    );
    assert!(matches!(app.key(key(KeyCode::Char('n'))), Action::None));
    assert!(app.confirmation.is_none());
    assert!(!app.revoking);
    app.key(key(KeyCode::Char('r')));
    assert!(
        matches!(app.key(key(KeyCode::Char('y'))), Action::Revoke(node) if node == peer.node_id)
    );
    assert!(app.revoking);
    assert!(app.confirmation.is_none());
    assert!(matches!(app.key(key(KeyCode::Char('y'))), Action::None));
    let mut app = App::new(view(&cfg, true));
    app.key(key(KeyCode::Char('r')));
    app.stale("offline".into());
    assert!(matches!(app.key(key(KeyCode::Char('y'))), Action::None));
}

#[test]
fn selection_survives_refresh_and_revocation_defaults_to_cancel() {
    let (mut cfg, _, peer) = fixture();
    let mut app = App::new(view(&cfg, true));
    assert!(matches!(app.key(key(KeyCode::Char('r'))), Action::None));
    assert!(app.confirmation.is_some());
    assert!(!app.confirm_yes);
    assert!(
        screen(&mut app, 120, 30)
            .0
            .contains("remove peer Eric laptop from network \"Office / Lab\"? y/n")
    );
    assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
    assert!(!app.revoking);
    assert!(app.confirmation.is_none());
    app.key(key(KeyCode::Char('r')));
    app.key(key(KeyCode::Tab));
    assert!(matches!(app.key(key(KeyCode::Enter)), Action::Revoke(node) if node == peer.node_id));
    let other = Peer {
        node_id: SecretKey::generate().public(),
        name: "other".into(),
        connection_id: "PEER02".into(),
    };
    enroll(&mut cfg, &other, "A first label");
    app.update(view(&cfg, true));
    assert_eq!(app.selected().unwrap().node_id, peer.node_id);
    cfg.peers.retain(|row| row.node_id != peer.node_id);
    app.update(view(&cfg, true));
    assert_eq!(app.selected().unwrap().node_id, other.node_id);
    app.revoking = false;
    app.stale("offline".into());
    app.key(key(KeyCode::Char('r')));
    assert!(app.confirmation.is_none());
    assert!(app.message.contains("disabled"));
    app.update(view(&cfg, true));
    app.key(key(KeyCode::Char('r')));
    assert!(app.confirmation.is_some());
    app.key(key(KeyCode::Esc));
    assert!(app.confirmation.is_none());
    cfg.peers.clear();
    app.update(view(&cfg, true));
    assert!(screen(&mut app, 120, 30).0.contains("No joined peers"));
    assert!(matches!(app.key(key(KeyCode::Down)), Action::None));
}

#[test]
fn details_scroll_long_fields_and_display_clock_edges() {
    let (cfg, _, peer) = fixture();
    let mut app = App::new(view(&cfg, true));
    let mut info = get_detail(&cfg, &peer);
    info.allowed_ports = (1..=200).collect();
    app.detail = Some(info);
    for _ in 0..30 {
        app.key(key(KeyCode::Char('J')));
    }
    screen(&mut app, 80, 20);
    assert!(app.scroll > 0);
    assert_eq!(admin::timestamp(None), "Never observed");
    assert!(admin::timestamp(Some(0)).contains("1970-01-01T00:00:00Z"));
    assert!(admin::timestamp(Some(u64::MAX)).contains("clock is ahead"));
}

struct SavedFixture {
    path: PathBuf,
}
impl SavedFixture {
    fn new(cfg: &Config) -> Self {
        let path = std::env::temp_dir().join(format!("esp-admin-{}.yml", Uuid::new_v4()));
        cfg.save(&path).unwrap();
        Self { path }
    }
}
impl Drop for SavedFixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

async fn actor_detail(actor: &ConfigActorHandle, node_id: EndpointId) -> PeerDetail {
    let response = actor
        .request(|respond| ConfigActorCommand::Admin {
            request: Request::Detail { node_id },
            respond,
        })
        .await
        .unwrap();
    let Response::Detail(detail) = response else {
        panic!()
    };
    detail
}

#[tokio::test]
async fn status_counts_distinct_established_peers_and_excludes_revoked_peers() {
    let (mut cfg, _, peer) = fixture();
    let other = Peer {
        node_id: SecretKey::generate().public(),
        name: "other-host".into(),
        connection_id: "OTHER1".into(),
    };
    enroll(&mut cfg, &other, "Other peer");
    let saved = SavedFixture::new(&cfg);
    let actor = spawn_config_actor(saved.path.clone(), cfg);
    let first = actor.register_connection(peer.node_id).await.unwrap();
    let second = actor.register_connection(peer.node_id).await.unwrap();
    let third = actor.register_connection(other.node_id).await.unwrap();
    assert_eq!(actor.status().await.unwrap().connected_peers, Some(0));
    first.connected().await.unwrap();
    second.connected().await.unwrap();
    assert_eq!(actor.status().await.unwrap().connected_peers, Some(1));
    third.connected().await.unwrap();
    assert_eq!(actor.status().await.unwrap().connected_peers, Some(2));
    drop(first);
    assert_eq!(actor.status().await.unwrap().connected_peers, Some(2));
    actor.revoke(other.connection_id).await.unwrap();
    assert_eq!(actor.status().await.unwrap().connected_peers, Some(1));
    drop(second);
    assert_eq!(actor.status().await.unwrap().connected_peers, Some(0));
}

#[tokio::test]
async fn presence_excludes_attempts_counts_sessions_and_persists_after_restart() {
    let (cfg, _, peer) = fixture();
    let saved = SavedFixture::new(&cfg);
    let actor = spawn_config_actor(saved.path.clone(), cfg);
    let first = actor.register_connection(peer.node_id).await.unwrap();
    assert_eq!(
        actor_detail(&actor, peer.node_id)
            .await
            .peer
            .active_connections,
        0
    );
    assert_eq!(
        actor_detail(&actor, peer.node_id).await.last_connected,
        None
    );
    first.connected().await.unwrap();
    first.connected().await.unwrap(); // Idempotent; does not count the same session twice.
    assert_eq!(
        actor_detail(&actor, peer.node_id)
            .await
            .peer
            .active_connections,
        1
    );
    let second = actor.register_connection(peer.node_id).await.unwrap();
    second.connected().await.unwrap();
    assert_eq!(
        actor_detail(&actor, peer.node_id)
            .await
            .peer
            .active_connections,
        2
    );
    drop(first);
    assert_eq!(
        actor_detail(&actor, peer.node_id)
            .await
            .peer
            .active_connections,
        1
    );
    drop(second);
    let last = actor_detail(&actor, peer.node_id).await;
    assert_eq!(last.peer.active_connections, 0);
    assert!(last.last_connected.is_some());
    let unknown = actor
        .register_connection(SecretKey::generate().public())
        .await
        .unwrap();
    assert!(unknown.connected().await.is_err());
    let loaded = Config::load(&saved.path).unwrap();
    assert_eq!(
        loaded
            .peer_last_connected
            .get(&peer.node_id.to_string())
            .copied(),
        last.last_connected
    );
    drop(unknown);
    drop(actor);
    let restarted = spawn_config_actor(saved.path.clone(), loaded);
    let detail = actor_detail(&restarted, peer.node_id).await;
    assert_eq!(detail.peer.active_connections, 0);
    assert_eq!(detail.last_connected, last.last_connected);
}

#[cfg(unix)]
#[tokio::test]
async fn admin_control_reports_live_presence_and_revokes_with_existing_actor() {
    let (cfg, key, peer) = fixture();
    let saved = SavedFixture::new(&cfg);
    let actor = spawn_config_actor(saved.path.clone(), cfg.clone());
    let socket = std::env::temp_dir().join(format!("esp-a-{}.sock", Uuid::new_v4()));
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let listener = bind_local_control_socket(&socket).unwrap();
    let server = tokio::spawn(run_local_control_server(
        listener,
        actor.clone(),
        endpoint.clone(),
        None,
    ));
    let mut active = actor.register_connection(peer.node_id).await.unwrap();
    active.connected().await.unwrap();
    let response = send_local_control_request_to_path(
        &socket,
        LocalControlRequest::Admin {
            request: Request::Detail {
                node_id: peer.node_id,
            },
        },
    )
    .await
    .unwrap()
    .unwrap();
    let LocalControlOk::Admin {
        report: Response::Detail(detail),
    } = response
    else {
        panic!()
    };
    assert_eq!(detail.peer.active_connections, 1);
    assert!(detail.invite_id.is_some());
    let response = send_local_control_request_to_path(
        &socket,
        LocalControlRequest::Revoke {
            target: peer.node_id.to_string(),
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(response, LocalControlOk::Revoked { .. }));
    timeout(Duration::from_secs(1), active.cancelled())
        .await
        .unwrap();
    let loaded = Config::load(&saved.path).unwrap();
    assert!(is_node_revoked(&loaded, peer.node_id));
    assert!(loaded.peers.is_empty());
    assert!(actor.register_connection(peer.node_id).await.is_err());
    assert!(active.connected().await.is_err());
    server.abort();
    endpoint.close().await;
    let _ = fs::remove_file(socket);
}

#[test]
fn admin_requests_allow_read_only_memberships_and_reject_legacy_state() {
    let (mut cfg, key, _) = fixture();
    let peer = cfg.local_peer().unwrap();
    cfg.membership =
        Some(MembershipCertificate::issue(&cfg, &key, &peer, &[22], MembershipRole::Peer).unwrap());
    assert!(admin::respond(&cfg, &HashMap::new(), Request::Overview).is_ok());
    let mut app = App::new(view(&cfg, true));
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    assert!(app.confirmation.is_none());
    let (cfg, _, _) = fixture();
    let saved = SavedFixture::new(&cfg);
    let original = serde_yaml::to_string(&cfg)
        .unwrap()
        .replacen("version: 3", "version: 1", 1);
    fs::write(&saved.path, &original).unwrap();
    assert!(
        Config::load(&saved.path)
            .unwrap_err()
            .to_string()
            .contains("recreate the network")
    );
    assert_eq!(fs::read_to_string(&saved.path).unwrap(), original);
    // Old unnamed invite requests must fail, rather than silently assign a hostname.
    assert!(
        cbor::decode_exact::<LocalControlRequest>(&[0x82, 0x03, 0x82, 0x81, 0x16, 0x01]).is_err()
    );
}

#[test]
fn revoke_dialog_keeps_controls_visible_with_maximum_length_names() {
    let (cfg, _, _) = fixture();
    let mut app = App::new(view(&cfg, true));
    app.view.peers[0].admin_label = "L".repeat(64);
    app.view.peers[0].hostname = "H".repeat(64);
    app.key(key(KeyCode::Char('r')));
    let (text, _) = screen(&mut app, 80, 20);
    assert!(text.contains("[ n ]"));
    assert!(text.contains("n/Esc: cancel"));
}

#[test]
fn network_focus_switching_rejects_stale_details_and_clears_removed_networks() {
    let (cfg, _, peer) = fixture();
    let mut app = App::new(view(&cfg, true));
    let first_id = cfg.network_id.clone();
    let other_id = Uuid::new_v4().to_string();
    app.set_networks(vec![
        admin::NetworkRow {
            id: first_id.clone(),
            label: "A".into(),
            role: "admin".into(),
        },
        admin::NetworkRow {
            id: other_id.clone(),
            label: "B".into(),
            role: "peer".into(),
        },
    ]);
    let old_generation = app.generation;
    let detail = get_detail(&cfg, &peer);
    assert!(app.accept_detail(&first_id, old_generation, detail.clone()));
    assert!(matches!(app.key(key(KeyCode::BackTab)), Action::None));
    assert_eq!(app.focus, 0);
    assert!(matches!(app.key(key(KeyCode::Down)), Action::Network));
    assert_eq!(app.view.overview.network_id, other_id);
    assert!(app.detail.is_none());
    assert!(!app.accept_detail(&first_id, old_generation, detail.clone()));
    // Switching away and back invalidates reads even if the peer and network IDs match.
    app.key(key(KeyCode::Up));
    app.update(view(&cfg, true));
    assert!(!app.accept_detail(&first_id, old_generation, detail));
    app.key(key(KeyCode::Tab));
    assert_eq!(app.focus, 1);
    app.key(key(KeyCode::Tab));
    assert_eq!(app.focus, 2);
    app.key(key(KeyCode::Down));
    assert_eq!(app.scroll, 1);
    assert!(app.set_networks(vec![]));
    assert!(app.view.overview.network_id.is_empty());
    assert!(app.selected().is_none());
    assert!(screen(&mut app, 120, 30).0.contains("Networks"));
}
