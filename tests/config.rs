use std::path::PathBuf;

use esp::{
    Config, DEFAULT_ALLOWED_PORT, Invite, InviteProof, MAX_SHARED_PEERS, Peer, encode_secret_key,
    ensure_port_allowed, is_valid_connection_id, remember_advertised_peers,
};
use iroh::SecretKey;

#[test]
fn invite_round_trips() {
    let key = SecretKey::generate();
    let invite = Invite {
        version: 1,
        network_id: "net".to_string(),
        invite_id: "invite1".to_string(),
        invite_secret: "secret1".to_string(),
        inviter_node_id: key.public(),
        inviter_name: "creator".to_string(),
        inviter_connection_id: "ABC123".to_string(),
    };

    let code = invite.encode().unwrap();
    let decoded = Invite::decode(&code).unwrap();
    assert_eq!(decoded.network_id, invite.network_id);
    assert_eq!(decoded.invite_id, invite.invite_id);
    assert_eq!(decoded.invite_secret, invite.invite_secret);
    assert_eq!(decoded.inviter_node_id, invite.inviter_node_id);
    assert_eq!(decoded.inviter_name, invite.inviter_name);
    assert_eq!(decoded.inviter_connection_id, invite.inviter_connection_id);
}

#[test]
fn joined_member_issues_unique_invites_without_saving_codes() {
    let secret_key = SecretKey::generate();
    let creator_key = SecretKey::generate();
    let mut cfg = Config {
        version: 1,
        network_id: "net".to_string(),
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: Some(creator_key.public()),
        invite_proof: Some(InviteProof {
            invite_id: "ABC999".to_string(),
            invite_secret: "member-proof".to_string(),
        }),
        name: "joined".to_string(),
        connection_id: "ABC123".to_string(),
        invites: Vec::new(),
        peers: vec![Peer {
            node_id: creator_key.public(),
            name: "creator".to_string(),
            connection_id: "DEF456".to_string(),
        }],
    };

    let first = cfg.issue_invite().unwrap();
    let second = cfg.issue_invite().unwrap();

    assert_ne!(first.invite_id, second.invite_id);
    assert_eq!(cfg.invites.len(), 2);
    assert_eq!(cfg.invites[0].invite_id, first.invite_id);
    assert_ne!(cfg.invites[0].secret_hash, first.code);
    assert_eq!(
        Invite::decode(&second.code).unwrap().invite_id,
        second.invite_id
    );
    assert_eq!(
        Invite::decode(&first.code).unwrap().inviter_node_id,
        secret_key.public()
    );
}

#[test]
fn resolving_duplicate_names_requires_connection_id() {
    let secret_key = SecretKey::generate();
    let first_peer_key = SecretKey::generate();
    let second_peer_key = SecretKey::generate();
    let cfg = Config {
        version: 1,
        network_id: "net".to_string(),
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: Some(secret_key.public()),
        invite_proof: None,
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
        network_id: "net".to_string(),
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: Some(secret_key.public()),
        invite_proof: None,
        name: "creator".to_string(),
        connection_id: "ABC123".to_string(),
        invites: Vec::new(),
        peers: vec![Peer {
            node_id: peer_key.public(),
            name: "amd".to_string(),
            connection_id: "aBc123".to_string(),
        }],
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
        network_id: "net".to_string(),
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: Some(secret_key.public()),
        invite_proof: None,
        name: "creator".to_string(),
        connection_id: "ABC123".to_string(),
        invites: Vec::new(),
        peers: Vec::new(),
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
}
