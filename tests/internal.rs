#![allow(dead_code)]

include!("../src/main.rs");

const TEST_NETWORK_ID: &str = "00000000-0000-0000-0000-000000000001";

fn creator_config(secret_key: &SecretKey) -> Config {
    create_creator_config(
        secret_key,
        TEST_NETWORK_ID.to_string(),
        "creator".to_string(),
        "ABC123".to_string(),
        DEFAULT_MAX_KNOWN_PEERS,
    )
    .unwrap()
}

fn temp_config_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("esp-{label}-{}.yml", Uuid::new_v4()))
}

#[test]
fn default_config_path_is_under_esp_state_dir() {
    let home = std::env::var_os("HOME").unwrap();
    let expected = PathBuf::from(home).join(".esp").join("config.yml");

    assert_eq!(config_path().unwrap(), expected);
}

#[test]
fn daemon_log_file_name_is_timestamped() {
    let now = UNIX_EPOCH + Duration::new(123, 45);

    assert_eq!(
        timestamped_log_file_name(now).unwrap(),
        "esp-123-000000045.log"
    );
}

#[test]
fn membership_certificate_chains_to_creator_and_rejects_tampering() {
    let creator_key = SecretKey::generate();
    let cfg = creator_config(&creator_key);
    let member = Peer {
        node_id: SecretKey::generate().public(),
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let membership = MembershipCertificate::issue(
        &cfg,
        &creator_key,
        &member,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Peer,
    )
    .unwrap();

    membership.matches_peer(&cfg, &member).unwrap();
    verify_membership_chain(&cfg, &membership, &[]).unwrap();

    let mut tampered = membership;
    tampered.subject_connection_id = "FED654".to_string();
    assert!(verify_membership_chain(&cfg, &tampered, &[]).is_err());
}

#[test]
fn invite_grants_are_signed_into_membership() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let invite = cfg
        .issue_invite(
            "Test peer",
            &[8080, DEFAULT_ALLOWED_PORT, 8080],
            MembershipRole::Admin,
        )
        .unwrap();
    let invite = Invite::decode(&invite.code).unwrap();
    let proof = InviteProof {
        invite_id: invite.invite_id,
        invite_secret: invite.invite_secret,
    };
    let issued_allowed_ports = cfg.invites[0].allowed_ports.clone();
    let issued_role = cfg.invites[0].role;
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "joined".to_string(),
        connection_id: "DEF456".to_string(),
    };

    let granted = consume_invite_and_issue_membership(&mut cfg, &peer, Some(&proof))
        .unwrap()
        .unwrap();

    assert_eq!(issued_allowed_ports, vec![DEFAULT_ALLOWED_PORT, 8080]);
    assert_eq!(issued_role, MembershipRole::Admin);
    assert_eq!(granted.allowed_ports, vec![DEFAULT_ALLOWED_PORT, 8080]);
    assert_eq!(granted.role, MembershipRole::Admin);
    verify_membership_chain(&cfg, &granted, &[]).unwrap();

    let mut tampered = granted;
    tampered.allowed_ports.push(80);
    assert!(verify_membership_chain(&cfg, &tampered, &[]).is_err());

    let mut tampered = cfg.membership.clone().unwrap();
    tampered.role = MembershipRole::Peer;
    assert!(verify_membership_chain(&cfg, &tampered, &[]).is_err());
}

#[test]
fn invite_proof_is_consumed_when_membership_is_granted() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let invite = cfg
        .issue_invite("Test peer", &[DEFAULT_ALLOWED_PORT], MembershipRole::Peer)
        .unwrap();
    let invite = Invite::decode(&invite.code).unwrap();
    let proof = InviteProof {
        invite_id: invite.invite_id,
        invite_secret: invite.invite_secret,
    };
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "joined".to_string(),
        connection_id: "DEF456".to_string(),
    };

    let granted = consume_invite_and_issue_membership(&mut cfg, &peer, Some(&proof))
        .unwrap()
        .unwrap();

    assert_eq!(granted.subject_node_id, peer.node_id);
    assert_eq!(granted.allowed_ports, vec![DEFAULT_ALLOWED_PORT]);
    assert_eq!(granted.role, MembershipRole::Peer);
    assert!(cfg.invites.is_empty());
    assert!(
        consume_invite_and_issue_membership(&mut cfg, &peer, Some(&proof))
            .unwrap()
            .is_none()
    );
}

#[test]
fn consumed_invite_regrants_existing_membership_to_same_node() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let invite = cfg
        .issue_invite("Test peer", &[DEFAULT_ALLOWED_PORT], MembershipRole::Peer)
        .unwrap();
    let invite = Invite::decode(&invite.code).unwrap();
    let proof = InviteProof {
        invite_id: invite.invite_id,
        invite_secret: invite.invite_secret,
    };
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "joined".to_string(),
        connection_id: "DEF456".to_string(),
    };

    let (first_grant, first_changed) =
        remember_control_peer_in_config(&mut cfg, peer.clone(), false, Some(&proof), None, &[])
            .unwrap();
    let first_grant = first_grant.unwrap();

    let (retry_grant, retry_changed) =
        remember_control_peer_in_config(&mut cfg, peer, false, Some(&proof), None, &[]).unwrap();

    assert!(first_changed);
    assert!(cfg.invites.is_empty());
    assert_eq!(retry_grant, Some(first_grant));
    assert!(!retry_changed);
}

#[test]
fn control_response_error_is_reported_to_client() {
    let err = ControlResponse::err("bad invite")
        .into_ok()
        .unwrap_err()
        .to_string();

    assert!(err.contains("remote esp control rejected request: bad invite"));
}

#[test]
fn incomplete_join_is_not_saved() {
    let creator_key = SecretKey::generate();
    let creator_cfg = creator_config(&creator_key);
    let member_key = SecretKey::generate();
    let pending = Config {
        format: output::Format::default(),
        version: 2,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: creator_cfg.network_policy.clone(),
        secret_key: encode_secret_key(&member_key),
        creator_node_id: creator_key.public(),
        invite_proof: Some(InviteProof {
            invite_id: "ABC999".to_string(),
            invite_secret: "secret".to_string(),
        }),
        membership: None,
        memberships: vec![creator_cfg.membership.clone().unwrap()],
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: vec![Peer {
            node_id: creator_key.public(),
            name: "creator".to_string(),
            connection_id: "ABC123".to_string(),
        }],
        revocations: Vec::new(),
    };
    let path = temp_config_path("incomplete-join");

    let err = save_completed_join(&path, &pending)
        .unwrap_err()
        .to_string();

    assert!(err.contains("join did not complete"));
    assert!(!path.exists());
}

#[test]
fn short_invite_join_bootstraps_policy_issuer_membership() {
    let creator_key = SecretKey::generate();
    let mut inviter_cfg = creator_config(&creator_key);
    let invite = inviter_cfg
        .issue_invite("Test peer", &[DEFAULT_ALLOWED_PORT], MembershipRole::Peer)
        .unwrap();
    let invite = Invite::decode(&invite.code).unwrap();
    let member_key = SecretKey::generate();
    let mut join_cfg = Config {
        format: output::Format::default(),
        version: 2,
        network_id: invite.network_id.clone(),
        network_policy: pending_join_network_policy(&invite.network_id, invite.creator_node_id),
        secret_key: encode_secret_key(&member_key),
        creator_node_id: invite.creator_node_id,
        invite_proof: Some(InviteProof {
            invite_id: invite.invite_id,
            invite_secret: invite.invite_secret,
        }),
        membership: None,
        memberships: Vec::new(),
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: vec![Peer {
            node_id: invite.inviter_node_id,
            name: String::new(),
            connection_id: String::new(),
        }],
        revocations: Vec::new(),
    };
    let join_hello = join_hello_from_config(&join_cfg).unwrap();
    let (response, _, _) =
        apply_control_sync(&mut inviter_cfg, member_key.public(), join_hello, None).unwrap();
    let (remote, granted_membership) = response.into_ok().unwrap();
    let inviter = join_cfg.peers[0].clone();

    apply_control_response_to_config(
        &mut join_cfg,
        creator_key.public(),
        remote,
        &inviter,
        granted_membership,
    )
    .unwrap();

    ensure_completed_join(&join_cfg).unwrap();
    verify_network_policy(&join_cfg, &join_cfg.network_policy, &[]).unwrap();
    assert_eq!(join_cfg.membership.unwrap().role, MembershipRole::Peer);
}

#[test]
fn pending_invite_proof_is_only_sent_in_join_hello() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    cfg.membership = None;
    cfg.invite_proof = Some(InviteProof {
        invite_id: "ABC123".to_string(),
        invite_secret: "secret".to_string(),
    });

    assert!(hello_from_config(&cfg).is_err());
    let join_hello = join_hello_from_config(&cfg).unwrap();
    let proof = join_hello.invite_proof.as_ref().unwrap();

    assert_eq!(proof.invite_id, "ABC123");
    assert_eq!(proof.invite_secret, "secret");
}

#[test]
fn config_schema_requires_current_policy_field() {
    let secret_key = SecretKey::generate();
    let yaml = format!(
        "\
version: 2
network_id: net
secret_key: {}
creator_node_id: {}
invite_proof: null
membership: null
memberships: []
name: creator
connection_id: ABC123
invites: []
peers: []
revocations: []
",
        encode_secret_key(&secret_key),
        secret_key.public()
    );

    let err = serde_yaml::from_str::<Config>(&yaml)
        .unwrap_err()
        .to_string();

    assert!(err.contains("network_policy"));
}

#[test]
fn config_serializes_signed_records_compactly() {
    let secret_key = SecretKey::generate();
    let cfg = creator_config(&secret_key);

    let yaml = serde_yaml::to_string(&cfg).unwrap();
    let decoded: Config = serde_yaml::from_str(&yaml).unwrap();

    assert!(yaml.contains("network_policy: "));
    assert!(yaml.contains("membership: "));
    assert!(!yaml.contains("network_policy:\n  version:"));
    assert!(!yaml.contains("membership:\n  version:"));
    assert_eq!(decoded.network_policy, cfg.network_policy);
    assert_eq!(decoded.membership, cfg.membership);
}

#[test]
fn joined_admin_cannot_issue_invite_for_ungranted_port() {
    let creator_key = SecretKey::generate();
    let creator_cfg = creator_config(&creator_key);
    let member_key = SecretKey::generate();
    let member_peer = Peer {
        node_id: member_key.public(),
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let creator_peer = Peer {
        node_id: creator_key.public(),
        name: "creator".to_string(),
        connection_id: "ABC123".to_string(),
    };
    let mut member_cfg = Config {
        format: output::Format::default(),
        version: 2,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: creator_cfg.network_policy.clone(),
        secret_key: encode_secret_key(&member_key),
        creator_node_id: creator_key.public(),
        invite_proof: None,
        membership: Some(
            MembershipCertificate::issue(
                &creator_cfg,
                &creator_key,
                &member_peer,
                &[DEFAULT_ALLOWED_PORT],
                MembershipRole::Admin,
            )
            .unwrap(),
        ),
        memberships: vec![creator_cfg.membership.clone().unwrap()],
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: vec![creator_peer],
        revocations: Vec::new(),
    };

    let err = member_cfg
        .issue_invite("Test peer", &[8080], MembershipRole::Peer)
        .unwrap_err()
        .to_string();

    assert!(err.contains("cannot grant port 8080"));
}

#[test]
fn joined_peer_cannot_issue_invites() {
    let creator_key = SecretKey::generate();
    let creator_cfg = creator_config(&creator_key);
    let member_key = SecretKey::generate();
    let member_peer = Peer {
        node_id: member_key.public(),
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let creator_peer = Peer {
        node_id: creator_key.public(),
        name: "creator".to_string(),
        connection_id: "ABC123".to_string(),
    };
    let mut member_cfg = Config {
        format: output::Format::default(),
        version: 2,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: creator_cfg.network_policy.clone(),
        secret_key: encode_secret_key(&member_key),
        creator_node_id: creator_key.public(),
        invite_proof: None,
        membership: Some(
            MembershipCertificate::issue(
                &creator_cfg,
                &creator_key,
                &member_peer,
                &[DEFAULT_ALLOWED_PORT],
                MembershipRole::Peer,
            )
            .unwrap(),
        ),
        memberships: vec![creator_cfg.membership.clone().unwrap()],
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: vec![creator_peer],
        revocations: Vec::new(),
    };

    let err = member_cfg
        .issue_invite("Test peer", &[DEFAULT_ALLOWED_PORT], MembershipRole::Peer)
        .unwrap_err()
        .to_string();

    assert!(err.contains("cannot issue invites"));
}

#[test]
fn membership_chain_rejects_delegated_port_widening() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let issuer_key = SecretKey::generate();
    let issuer_peer = Peer {
        node_id: issuer_key.public(),
        name: "issuer".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let subject_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "subject".to_string(),
        connection_id: "FED654".to_string(),
    };
    let issuer_membership = MembershipCertificate::issue(
        &cfg,
        &creator_key,
        &issuer_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Admin,
    )
    .unwrap();
    let subject_membership = MembershipCertificate::issue(
        &cfg,
        &issuer_key,
        &subject_peer,
        &[8080],
        MembershipRole::Peer,
    )
    .unwrap();
    cfg.memberships.push(issuer_membership);

    let err = verify_membership_chain(&cfg, &subject_membership, &[])
        .unwrap_err()
        .to_string();

    assert!(err.contains("outside issuer"));
}

#[test]
fn membership_chain_rejects_peer_issuer() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let issuer_key = SecretKey::generate();
    let issuer_peer = Peer {
        node_id: issuer_key.public(),
        name: "issuer".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let subject_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "subject".to_string(),
        connection_id: "FED654".to_string(),
    };
    let issuer_membership = MembershipCertificate::issue(
        &cfg,
        &creator_key,
        &issuer_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Peer,
    )
    .unwrap();
    let subject_membership = MembershipCertificate::issue(
        &cfg,
        &issuer_key,
        &subject_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Peer,
    )
    .unwrap();
    cfg.memberships.push(issuer_membership);

    let err = verify_membership_chain(&cfg, &subject_membership, &[])
        .unwrap_err()
        .to_string();

    assert!(err.contains("cannot issue memberships"));
}

#[test]
fn revocation_rejects_member_and_delegated_memberships() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let admin_key = SecretKey::generate();
    let admin_peer = Peer {
        node_id: admin_key.public(),
        name: "admin".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let subject_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "subject".to_string(),
        connection_id: "FED654".to_string(),
    };
    let admin_membership = MembershipCertificate::issue(
        &cfg,
        &creator_key,
        &admin_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Admin,
    )
    .unwrap();
    let subject_membership = MembershipCertificate::issue(
        &cfg,
        &admin_key,
        &subject_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Peer,
    )
    .unwrap();
    cfg.memberships.push(admin_membership.clone());
    verify_membership_chain(&cfg, &admin_membership, &[]).unwrap();
    verify_membership_chain(&cfg, &subject_membership, &[]).unwrap();

    cfg.issue_revocation(&admin_peer.node_id.to_string())
        .unwrap();

    let admin_err = verify_membership_chain(&cfg, &admin_membership, &[])
        .unwrap_err()
        .to_string();
    let subject_err = verify_membership_chain(&cfg, &subject_membership, &[])
        .unwrap_err()
        .to_string();

    assert!(admin_err.contains("has been revoked"));
    assert!(subject_err.contains("has been revoked"));
}

#[test]
fn joined_peer_cannot_revoke() {
    let creator_key = SecretKey::generate();
    let creator_cfg = creator_config(&creator_key);
    let member_key = SecretKey::generate();
    let member_peer = Peer {
        node_id: member_key.public(),
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let creator_peer = Peer {
        node_id: creator_key.public(),
        name: "creator".to_string(),
        connection_id: "ABC123".to_string(),
    };
    let target_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "target".to_string(),
        connection_id: "FED654".to_string(),
    };
    let mut member_cfg = Config {
        format: output::Format::default(),
        version: 2,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: creator_cfg.network_policy.clone(),
        secret_key: encode_secret_key(&member_key),
        creator_node_id: creator_key.public(),
        invite_proof: None,
        membership: Some(
            MembershipCertificate::issue(
                &creator_cfg,
                &creator_key,
                &member_peer,
                &[DEFAULT_ALLOWED_PORT],
                MembershipRole::Peer,
            )
            .unwrap(),
        ),
        memberships: vec![creator_cfg.membership.clone().unwrap()],
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: vec![creator_peer, target_peer],
        revocations: Vec::new(),
    };

    let err = member_cfg
        .issue_revocation("FED654")
        .unwrap_err()
        .to_string();

    assert!(err.contains("cannot issue invites or revoke peers"));
}

#[test]
fn known_control_peer_without_membership_is_rejected() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "known".to_string(),
        connection_id: "DEF456".to_string(),
    };
    cfg.peers.push(peer.clone());

    let err = remember_control_peer_in_config(&mut cfg, peer, false, None, None, &[])
        .unwrap_err()
        .to_string();

    assert!(err.contains("valid membership certificate"));
}

#[test]
fn known_proxy_peer_without_membership_is_rejected() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "known".to_string(),
        connection_id: "DEF456".to_string(),
    };
    cfg.peers.push(peer.clone());

    let err = remember_proxy_peer_in_config(&mut cfg, peer, None, &[], DEFAULT_ALLOWED_PORT)
        .unwrap_err()
        .to_string();

    assert!(err.contains("valid membership certificate"));
}

#[test]
fn known_peer_with_membership_is_accepted() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "known".to_string(),
        connection_id: "DEF456".to_string(),
    };
    cfg.peers.push(peer.clone());
    let membership = MembershipCertificate::issue(
        &cfg,
        &creator_key,
        &peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Peer,
    )
    .unwrap();

    let changed = remember_proxy_peer_in_config(
        &mut cfg,
        peer.clone(),
        Some(&membership),
        &[],
        DEFAULT_ALLOWED_PORT,
    )
    .unwrap();

    assert!(changed);
    assert_eq!(
        cfg.peer_by_id(peer.node_id).unwrap().connection_id,
        peer.connection_id
    );
}

#[test]
fn proxy_requires_membership_port_grant() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "known".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let membership = MembershipCertificate::issue(
        &cfg,
        &creator_key,
        &peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Peer,
    )
    .unwrap();

    remember_proxy_peer_in_config(
        &mut cfg,
        peer.clone(),
        Some(&membership),
        &[],
        DEFAULT_ALLOWED_PORT,
    )
    .unwrap();
    let err = remember_proxy_peer_in_config(&mut cfg, peer, Some(&membership), &[], 8080)
        .unwrap_err()
        .to_string();

    assert!(err.contains("does not allow port 8080"));
}

#[test]
fn known_advertised_peer_without_membership_is_rejected() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let remote_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "remote".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let advertised_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "advertised".to_string(),
        connection_id: "FED654".to_string(),
    };
    cfg.peers.push(advertised_peer.clone());

    let err = remember_advertised_peers_in_config(
        &mut cfg,
        &remote_peer,
        vec![advertised_peer],
        Vec::new(),
        true,
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("has no valid membership"));
}

#[test]
fn non_admin_hello_does_not_advertise_directory() {
    let creator_key = SecretKey::generate();
    let creator_cfg = creator_config(&creator_key);
    let member_key = SecretKey::generate();
    let member_peer = Peer {
        node_id: member_key.public(),
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let creator_peer = Peer {
        node_id: creator_key.public(),
        name: "creator".to_string(),
        connection_id: "ABC123".to_string(),
    };
    let advertised_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "advertised".to_string(),
        connection_id: "FED654".to_string(),
    };
    let member_cfg = Config {
        format: output::Format::default(),
        version: 2,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: creator_cfg.network_policy.clone(),
        secret_key: encode_secret_key(&member_key),
        creator_node_id: creator_key.public(),
        invite_proof: None,
        membership: Some(
            MembershipCertificate::issue(
                &creator_cfg,
                &creator_key,
                &member_peer,
                &[DEFAULT_ALLOWED_PORT],
                MembershipRole::Peer,
            )
            .unwrap(),
        ),
        memberships: vec![
            creator_cfg.membership.clone().unwrap(),
            MembershipCertificate::issue(
                &creator_cfg,
                &creator_key,
                &advertised_peer,
                &[DEFAULT_ALLOWED_PORT],
                MembershipRole::Peer,
            )
            .unwrap(),
        ],
        name: "member".to_string(),
        connection_id: "DEF456".to_string(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: vec![creator_peer, advertised_peer.clone()],
        revocations: Vec::new(),
    };
    member_cfg.validate_local_config().unwrap();

    let hello = hello_from_config(&member_cfg).unwrap();

    assert!(hello.peers.is_empty());
    assert!(
        hello
            .memberships
            .iter()
            .any(|membership| membership.subject_node_id == member_peer.node_id)
    );
    assert!(
        hello
            .memberships
            .iter()
            .all(|membership| membership.subject_node_id != advertised_peer.node_id)
    );
}

#[test]
fn non_admin_directory_gossip_is_rejected() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let remote_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "remote".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let advertised_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "advertised".to_string(),
        connection_id: "FED654".to_string(),
    };

    let err = remember_advertised_peers_in_config(
        &mut cfg,
        &remote_peer,
        vec![advertised_peer],
        Vec::new(),
        false,
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("not an admin"));
}

#[test]
fn network_policy_max_peers_limits_inserted_peers() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    cfg.issue_network_policy(1).unwrap();
    let first_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "first".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let second_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "second".to_string(),
        connection_id: "FED654".to_string(),
    };
    let first_membership = MembershipCertificate::issue(
        &cfg,
        &creator_key,
        &first_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Peer,
    )
    .unwrap();
    let second_membership = MembershipCertificate::issue(
        &cfg,
        &creator_key,
        &second_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Peer,
    )
    .unwrap();

    remember_proxy_peer_in_config(
        &mut cfg,
        first_peer.clone(),
        Some(&first_membership),
        &[],
        DEFAULT_ALLOWED_PORT,
    )
    .unwrap();
    let err = remember_proxy_peer_in_config(
        &mut cfg,
        second_peer,
        Some(&second_membership),
        &[],
        DEFAULT_ALLOWED_PORT,
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("known peer limit reached (1)"));
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.peers[0].node_id, first_peer.node_id);
    assert_eq!(cfg.memberships.len(), 1);
}

#[test]
fn joined_admin_can_update_network_policy() {
    let creator_key = SecretKey::generate();
    let creator_cfg = creator_config(&creator_key);
    let admin_key = SecretKey::generate();
    let admin_peer = Peer {
        node_id: admin_key.public(),
        name: "admin".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let admin_membership = MembershipCertificate::issue(
        &creator_cfg,
        &creator_key,
        &admin_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Admin,
    )
    .unwrap();
    let mut admin_cfg = Config {
        format: output::Format::default(),
        version: 2,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: creator_cfg.network_policy.clone(),
        secret_key: encode_secret_key(&admin_key),
        creator_node_id: creator_key.public(),
        invite_proof: None,
        membership: Some(admin_membership.clone()),
        memberships: vec![creator_cfg.membership.clone().unwrap()],
        name: "admin".to_string(),
        connection_id: "DEF456".to_string(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: Vec::new(),
        revocations: Vec::new(),
    };

    let report = admin_cfg.issue_network_policy(7).unwrap();
    let policy = &admin_cfg.network_policy;

    assert_eq!(report.max_peers, 7);
    verify_network_policy(&creator_cfg, policy, &[admin_membership]).unwrap();
}

#[test]
fn connection_names_reject_display_control_characters() {
    normalize_connection_name("host_1.example").unwrap();
    assert!(normalize_connection_name("bad\nname").is_err());
    assert!(normalize_connection_name("bad\u{1b}[31m").is_err());
    assert!(normalize_connection_name("bad\u{202e}name").is_err());
}

#[tokio::test]
async fn config_actor_serializes_invite_consumption() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let invite = cfg
        .issue_invite("Test peer", &[DEFAULT_ALLOWED_PORT], MembershipRole::Peer)
        .unwrap();
    let invite = Invite::decode(&invite.code).unwrap();
    let proof = InviteProof {
        invite_id: invite.invite_id,
        invite_secret: invite.invite_secret,
    };
    let path = temp_config_path("actor-race");
    cfg.save(&path).unwrap();
    let actor = spawn_config_actor(path.clone(), cfg);

    let first_key = SecretKey::generate();
    let second_key = SecretKey::generate();
    let first_hello = Hello {
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: None,
        name: "joined-one".to_string(),
        connection_id: "DEF456".to_string(),
        invite_proof: Some(proof.clone()),
        membership: None,
        memberships: Vec::new(),
        peers: Vec::new(),
        revocations: Vec::new(),
    };
    let second_hello = Hello {
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: None,
        name: "joined-two".to_string(),
        connection_id: "FED654".to_string(),
        invite_proof: Some(proof),
        membership: None,
        memberships: Vec::new(),
        peers: Vec::new(),
        revocations: Vec::new(),
    };

    let (first, second) = tokio::join!(
        actor.control_sync(first_key.public(), first_hello, None),
        actor.control_sync(second_key.public(), second_hello, None)
    );

    let first_granted = first
        .as_ref()
        .ok()
        .and_then(|response| response.granted_membership.as_ref())
        .is_some();
    let second_granted = second
        .as_ref()
        .ok()
        .and_then(|response| response.granted_membership.as_ref())
        .is_some();
    assert_eq!(usize::from(first_granted) + usize::from(second_granted), 1);
    assert!(first.is_err() ^ second.is_err());

    drop(actor);
    let saved = Config::load(&path).unwrap();
    assert!(saved.invites.is_empty());
    assert_eq!(saved.peers.len(), 1);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn config_actor_revoke_cancels_active_connections() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "peer".to_string(),
        connection_id: "DEF456".to_string(),
    };
    cfg.peers.push(peer.clone());
    let path = temp_config_path("actor-revoke");
    cfg.save(&path).unwrap();
    let actor = spawn_config_actor(path.clone(), cfg);
    let mut active = actor.register_connection(peer.node_id).await.unwrap();

    let report = actor.revoke("DEF456".to_string()).await.unwrap();

    assert_eq!(report.node_id, peer.node_id);
    timeout(Duration::from_secs(1), active.cancelled())
        .await
        .expect("active connection was cancelled");
    drop(active);
    drop(actor);
    let saved = Config::load(&path).unwrap();
    assert!(saved.peer_by_id(peer.node_id).is_none());
    assert!(is_node_revoked(&saved, peer.node_id));
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[tokio::test]
async fn local_control_invites_are_fresh_and_persisted_by_config_actor() {
    let creator_key = SecretKey::generate();
    let cfg = creator_config(&creator_key);
    let path = temp_config_path("local-control");
    let socket_path = std::env::temp_dir().join(format!("esp-{}.sock", Uuid::new_v4()));
    cfg.save(&path).unwrap();
    let actor = spawn_config_actor(path.clone(), cfg);
    let listener = bind_local_control_socket(&socket_path).unwrap();
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(creator_key)
        .relay_mode(RelayMode::Default)
        .bind()
        .await
        .unwrap();
    let server = tokio::spawn(run_local_control_server(
        listener,
        actor.clone(),
        endpoint.clone(),
        None,
    ));

    let mut codes = HashSet::new();
    let mut secrets = HashSet::new();
    let mut invite_ids = Vec::new();
    for _ in 0..3 {
        let response = send_local_control_request_to_path(
            &socket_path,
            LocalControlRequest::IssueInvite {
                name: "Test peer".to_string(),
                ports: vec![DEFAULT_ALLOWED_PORT],
                role: MembershipRole::Admin,
            },
        )
        .await
        .unwrap()
        .unwrap();
        let LocalControlOk::Invite { code } = response else {
            panic!("expected invite response");
        };
        let invite = Invite::decode(&code).unwrap();
        assert_eq!(invite.creator_node_id, invite.inviter_node_id);
        assert!(codes.insert(code));
        assert!(!invite_ids.contains(&invite.invite_id));
        invite_ids.push(invite.invite_id);
        assert!(secrets.insert(invite.invite_secret));
    }
    let report = actor.status().await.unwrap();
    let saved = Config::load(&path).unwrap();

    assert_eq!(report.invites, invite_ids);
    assert_eq!(saved.invites.len(), invite_ids.len());
    for (saved_invite, invite_id) in saved.invites.iter().zip(&invite_ids) {
        assert_eq!(&saved_invite.invite_id, invite_id);
        assert_eq!(saved_invite.role, MembershipRole::Admin);
    }

    server.abort();
    endpoint.close().await;
    drop(actor);
    let _ = std::fs::remove_file(socket_path);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn peer_quota_limits_concurrent_connections() {
    let quota = spawn_peer_quota_actor(1);
    let peer_id = SecretKey::generate().public();

    let first = quota.try_acquire(peer_id).await.unwrap();
    assert!(first.is_some());
    assert!(quota.try_acquire(peer_id).await.unwrap().is_none());

    drop(first);
    let reacquired = timeout(Duration::from_secs(1), async {
        loop {
            if let Some(permit) = quota.try_acquire(peer_id).await.unwrap() {
                return permit;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("quota was released");
    drop(reacquired);
}

#[tokio::test]
async fn copy_with_idle_timeout_times_out() {
    let (mut idle_reader, _writer) = io::duplex(64);
    let mut sink = io::sink();

    let err = copy_with_idle_timeout(
        &mut idle_reader,
        &mut sink,
        Duration::from_millis(10),
        "test stream",
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("test stream idle timeout"));
}

#[test]
fn advertised_peer_with_valid_membership_is_remembered_without_invite() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let remote_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "remote".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let advertised_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "advertised".to_string(),
        connection_id: "FED654".to_string(),
    };
    let advertised_membership = MembershipCertificate::issue(
        &cfg,
        &creator_key,
        &advertised_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Peer,
    )
    .unwrap();
    let path = std::env::temp_dir().join(format!("esp-test-{}.yml", Uuid::new_v4()));

    remember_advertised_peers_with_memberships(
        &path,
        &mut cfg,
        &remote_peer,
        vec![advertised_peer.clone()],
        vec![advertised_membership],
        true,
    )
    .unwrap();

    assert_eq!(
        cfg.peer_by_id(advertised_peer.node_id)
            .unwrap()
            .connection_id,
        advertised_peer.connection_id
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn unknown_advertised_peer_without_membership_is_rejected() {
    let creator_key = SecretKey::generate();
    let mut cfg = creator_config(&creator_key);
    let remote_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "remote".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let advertised_peer = Peer {
        node_id: SecretKey::generate().public(),
        name: "advertised".to_string(),
        connection_id: "FED654".to_string(),
    };
    let path = std::env::temp_dir().join(format!("esp-test-{}.yml", Uuid::new_v4()));

    let err = remember_advertised_peers_with_memberships(
        &path,
        &mut cfg,
        &remote_peer,
        vec![advertised_peer.clone()],
        Vec::new(),
        true,
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("has no valid membership"));
    assert!(cfg.peer_by_id(advertised_peer.node_id).is_none());
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn config_save_creates_private_regular_file() {
    use std::os::unix::fs::PermissionsExt;

    let secret_key = SecretKey::generate();
    let cfg = creator_config(&secret_key);
    let path = temp_config_path("private");

    cfg.save(&path).unwrap();

    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, CONFIG_FILE_MODE);
    Config::load(&path).unwrap();

    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn config_save_creates_private_state_directory() {
    use std::os::unix::fs::PermissionsExt;

    let secret_key = SecretKey::generate();
    let cfg = creator_config(&secret_key);
    let dir = std::env::temp_dir().join(format!("esp-state-{}", Uuid::new_v4()));
    let path = dir.join("config.yml");

    cfg.save(&path).unwrap();

    let dir_metadata = std::fs::symlink_metadata(&dir).unwrap();
    assert!(dir_metadata.file_type().is_dir());
    assert_eq!(dir_metadata.permissions().mode() & 0o777, PRIVATE_DIR_MODE);
    Config::load(&path).unwrap();

    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(dir);
}

#[cfg(unix)]
#[test]
fn config_load_and_save_reject_loose_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let secret_key = SecretKey::generate();
    let cfg = creator_config(&secret_key);
    let path = temp_config_path("loose");
    cfg.save(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let load_err = Config::load(&path).unwrap_err().to_string();
    assert!(load_err.contains("group/world access"));
    let save_err = cfg.save(&path).unwrap_err().to_string();
    assert!(save_err.contains("group/world access"));

    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn config_load_and_save_reject_symlinks() {
    use std::os::unix::fs::symlink;

    let secret_key = SecretKey::generate();
    let cfg = creator_config(&secret_key);
    let target_path = temp_config_path("target");
    let link_path = temp_config_path("link");
    cfg.save(&target_path).unwrap();
    symlink(&target_path, &link_path).unwrap();

    let load_err = Config::load(&link_path).unwrap_err().to_string();
    assert!(load_err.contains("is a symlink"));
    let save_err = cfg.save(&link_path).unwrap_err().to_string();
    assert!(save_err.contains("is a symlink"));

    let _ = std::fs::remove_file(link_path);
    let _ = std::fs::remove_file(target_path);
}

#[cfg(unix)]
#[test]
fn config_load_and_save_reject_hard_links() {
    let secret_key = SecretKey::generate();
    let cfg = creator_config(&secret_key);
    let path = temp_config_path("hard-link");
    let link_path = temp_config_path("hard-link-copy");
    cfg.save(&path).unwrap();
    std::fs::hard_link(&path, &link_path).unwrap();

    let load_err = Config::load(&path).unwrap_err().to_string();
    assert!(load_err.contains("hard links"));
    let save_err = cfg.save(&path).unwrap_err().to_string();
    assert!(save_err.contains("hard links"));

    let _ = std::fs::remove_file(link_path);
    let _ = std::fs::remove_file(path);
}
