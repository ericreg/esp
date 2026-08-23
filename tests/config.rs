#![allow(dead_code)]

include!("../src/main.rs");

const TEST_NETWORK_ID: &str = "00000000-0000-0000-0000-000000000001";

fn issue_membership(cfg: &Config, issuer_key: &SecretKey, subject: &Peer) -> MembershipCertificate {
    MembershipCertificate::issue(
        cfg,
        issuer_key,
        subject,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Admin,
    )
    .unwrap()
}

fn issue_policy(network_id: &str, issuer_key: &SecretKey) -> NetworkPolicyCertificate {
    NetworkPolicyCertificate::issue_for_network(network_id, issuer_key, DEFAULT_MAX_KNOWN_PEERS)
        .unwrap()
}

#[test]
fn invite_round_trips() {
    let key = SecretKey::generate();
    let invite = Invite {
        version: 1,
        network_id: TEST_NETWORK_ID.to_string(),
        invite_id: "ABC123".to_string(),
        invite_secret: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
        creator_node_id: key.public(),
        inviter_node_id: key.public(),
    };

    let code = invite.encode().unwrap();
    let decoded = Invite::decode(&code).unwrap();
    assert_eq!(code.len(), 138);
    assert_eq!(decoded.network_id, invite.network_id);
    assert_eq!(decoded.invite_id, invite.invite_id);
    assert_eq!(decoded.invite_secret, invite.invite_secret);
    assert_eq!(decoded.creator_node_id, invite.creator_node_id);
    assert_eq!(decoded.inviter_node_id, invite.inviter_node_id);
}

#[test]
fn joined_admin_issues_unique_invites_without_saving_codes() {
    let secret_key = SecretKey::generate();
    let creator_key = SecretKey::generate();
    let creator_peer = Peer {
        node_id: creator_key.public(),
        name: "creator".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let mut cfg = Config {
        version: 1,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: issue_policy(TEST_NETWORK_ID, &creator_key),
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: creator_key.public(),
        invite_proof: Some(InviteProof {
            invite_id: "ABC999".to_string(),
            invite_secret: "member-proof".to_string(),
        }),
        membership: None,
        memberships: Vec::new(),
        name: "joined".to_string(),
        connection_id: "ABC123".to_string(),
        invites: Vec::new(),
        peers: vec![creator_peer.clone()],
        revocations: Vec::new(),
    };
    let joined_peer = Peer {
        node_id: secret_key.public(),
        name: "joined".to_string(),
        connection_id: "ABC123".to_string(),
    };
    cfg.membership = Some(issue_membership(&cfg, &creator_key, &joined_peer));
    cfg.memberships
        .push(issue_membership(&cfg, &creator_key, &creator_peer));

    let first = cfg
        .issue_invite(&[DEFAULT_ALLOWED_PORT], MembershipRole::Peer)
        .unwrap();
    let second = cfg
        .issue_invite(&[DEFAULT_ALLOWED_PORT], MembershipRole::Peer)
        .unwrap();

    assert_ne!(first.invite_id, second.invite_id);
    assert_eq!(cfg.invites.len(), 2);
    assert_eq!(cfg.invites[0].invite_id, first.invite_id);
    assert_eq!(cfg.invites[0].allowed_ports, vec![DEFAULT_ALLOWED_PORT]);
    assert_eq!(cfg.invites[0].role, MembershipRole::Peer);
    assert_ne!(cfg.invites[0].secret_hash, first.code);
    assert_eq!(
        Invite::decode(&second.code).unwrap().invite_id,
        second.invite_id
    );
    let decoded = Invite::decode(&first.code).unwrap();
    assert!(first.code.len() < 150);
    assert_eq!(decoded.inviter_node_id, secret_key.public());
    assert_eq!(decoded.creator_node_id, creator_key.public());
}

#[test]
fn resolving_duplicate_names_requires_connection_id() {
    let secret_key = SecretKey::generate();
    let first_peer_key = SecretKey::generate();
    let second_peer_key = SecretKey::generate();
    let cfg = Config {
        version: 1,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: issue_policy(TEST_NETWORK_ID, &secret_key),
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: secret_key.public(),
        invite_proof: None,
        membership: None,
        memberships: Vec::new(),
        name: "creator".to_string(),
        connection_id: "ABC123".to_string(),
        invites: Vec::new(),
        peers: vec![
            Peer {
                node_id: first_peer_key.public(),
                name: "amd".to_string(),
                connection_id: "DEF456".to_string(),
            },
            Peer {
                node_id: second_peer_key.public(),
                name: "amd".to_string(),
                connection_id: "FED654".to_string(),
            },
        ],
        revocations: Vec::new(),
    };

    let err = cfg.resolve_peer("amd").unwrap_err().to_string();
    assert!(err.contains("multiple esp peers are named amd"));
    assert_eq!(cfg.resolve_peer("DEF456").unwrap().connection_id, "DEF456");
}

#[test]
fn connection_ids_are_case_sensitive_base62() {
    assert!(is_valid_connection_id("aBc123"));
    assert!(is_valid_connection_id("Zz9Yy8"));
    assert!(!is_valid_connection_id("abc12"));
    assert!(!is_valid_connection_id("abc12-"));

    let secret_key = SecretKey::generate();
    let peer_key = SecretKey::generate();
    let cfg = Config {
        version: 1,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: issue_policy(TEST_NETWORK_ID, &secret_key),
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: secret_key.public(),
        invite_proof: None,
        membership: None,
        memberships: Vec::new(),
        name: "creator".to_string(),
        connection_id: "ABC123".to_string(),
        invites: Vec::new(),
        peers: vec![Peer {
            node_id: peer_key.public(),
            name: "amd".to_string(),
            connection_id: "aBc123".to_string(),
        }],
        revocations: Vec::new(),
    };

    assert_eq!(cfg.resolve_peer("aBc123").unwrap().connection_id, "aBc123");
    assert!(cfg.resolve_peer("ABC123").is_err());
}

#[test]
fn advertised_peer_lists_are_bounded() {
    let secret_key = SecretKey::generate();
    let remote_key = SecretKey::generate();
    let mut cfg = Config {
        version: 1,
        network_id: TEST_NETWORK_ID.to_string(),
        network_policy: issue_policy(TEST_NETWORK_ID, &secret_key),
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: secret_key.public(),
        invite_proof: None,
        membership: None,
        memberships: Vec::new(),
        name: "creator".to_string(),
        connection_id: "ABC123".to_string(),
        invites: Vec::new(),
        peers: Vec::new(),
        revocations: Vec::new(),
    };
    let remote = Peer {
        node_id: remote_key.public(),
        name: "remote".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let advertised = (0..=MAX_SHARED_PEERS)
        .map(|idx| Peer {
            node_id: SecretKey::generate().public(),
            name: format!("peer-{idx}"),
            connection_id: format!("{idx:06}"),
        })
        .collect();

    let err = remember_advertised_peers(
        &PathBuf::from("/tmp/esp-test-no-write.yml"),
        &mut cfg,
        &remote,
        advertised,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("maximum is 100"));
}

#[test]
fn proxy_ports_are_allowlisted() {
    let default_ports = [DEFAULT_ALLOWED_PORT];
    assert!(ensure_port_allowed(22, &default_ports).is_ok());
    assert!(ensure_port_allowed(5432, &default_ports).is_err());

    let custom_ports = [22, 5432, 11434];
    assert!(ensure_port_allowed(5432, &custom_ports).is_ok());
    assert!(ensure_port_allowed(8000, &custom_ports).is_err());

    let duplicated_ports = [5432, 22, 5432];
    assert!(ensure_port_allowed(22, &duplicated_ports).is_ok());
    assert!(ensure_port_allowed(0, &[0]).is_err());
}
