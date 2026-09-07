#![allow(dead_code)]

include!("../src/main.rs");

fn records() -> (Config, Peer, MembershipCertificate, RevocationCertificate) {
    let key = SecretKey::from_bytes(&[7; 32]);
    let mut cfg = create_creator_config(
        &key,
        // Preserve the exact UUID spelling, including in signed payloads.
        "01234567-89AB-CDEF-0123-456789ABCDEF".to_string(),
        "creator".to_string(),
        "ABC123".to_string(),
        DEFAULT_MAX_KNOWN_PEERS,
    )
    .unwrap();
    let peer = Peer {
        node_id: SecretKey::from_bytes(&[8; 32]).public(),
        name: "other-host".to_string(),
        connection_id: "DEF456".to_string(),
    };
    let membership =
        MembershipCertificate::issue(&cfg, &key, &peer, &[22], MembershipRole::Peer).unwrap();
    let revocation = RevocationCertificate::issue(&cfg, &key, peer.node_id).unwrap();
    cfg.peers.push(peer.clone());
    cfg.memberships.push(membership.clone());
    (cfg, peer, membership, revocation)
}

fn roundtrip<T>(value: &T)
where
    T: Encode<()> + for<'b> Decode<'b, ()> + std::fmt::Debug + PartialEq,
{
    let bytes = minicbor::to_vec(value).unwrap();
    let decoded: T = cbor::decode_exact(&bytes).unwrap();
    assert_eq!(&decoded, value);
}

#[test]
fn message_schema_has_stable_cbor_bytes() {
    assert_eq!(
        minicbor::to_vec(LocalControlRequest::Status).unwrap(),
        [0x82, 0x11, 0x80]
    );
    assert_eq!(
        minicbor::to_vec(LocalControlRequest::Proxy {
            target: "amd".to_string(),
            port: 22
        })
        .unwrap(),
        [0x82, 0x10, 0x82, 0x63, b'a', b'm', b'd', 0x16]
    );
    assert_eq!(minicbor::to_vec(MembershipRole::Admin).unwrap(), [0]);
    assert_eq!(minicbor::to_vec(MembershipRole::Peer).unwrap(), [1]);
}

#[test]
fn all_message_variants_roundtrip_through_cbor() {
    let (mut cfg, peer, membership, revocation) = records();
    let invite = Invite::decode(
        &cfg.issue_invite("Test peer", &[22], MembershipRole::Peer)
            .unwrap()
            .code,
    )
    .unwrap();
    let proof = InviteProof {
        invite_id: invite.invite_id.clone(),
        invite_secret: invite.invite_secret.clone(),
    };
    roundtrip(&invite);
    roundtrip(&proof);
    roundtrip(&peer);
    roundtrip(&membership);
    roundtrip(&cfg.network_policy);
    roundtrip(&revocation);
    let mut hello = hello_from_config(&cfg).unwrap();
    hello.invite_proof = Some(proof);
    hello.revocations.push(revocation);
    roundtrip(&hello);
    roundtrip(&ControlResponse::ok(hello, Some(membership)));
    roundtrip(&ControlResponse::err("rejected"));
    roundtrip(&prepare_proxy_request(&cfg, &peer.name, 22).unwrap().1);
    for request in [
        LocalControlRequest::Proxy {
            target: peer.name.clone(),
            port: 22,
        },
        LocalControlRequest::Status,
        LocalControlRequest::Rename {
            name: "renamed".to_string(),
        },
        LocalControlRequest::IssueInvite {
            name: "Test peer".to_string(),
            ports: vec![22, 8080],
            role: MembershipRole::Admin,
        },
        LocalControlRequest::Revoke {
            target: peer.connection_id.clone(),
        },
        LocalControlRequest::UpdatePolicy { max_peers: 250 },
    ] {
        roundtrip(&request);
    }
    roundtrip(&LocalProxyResponse::Ready);
    roundtrip(&LocalProxyResponse::Error("offline".to_string()));
    let mut status = status_report_from_config(&cfg).unwrap();
    status.revocations.push(peer.node_id);
    for response in [
        LocalControlOk::Status { report: status },
        LocalControlOk::Renamed {
            name: "renamed".to_string(),
            connection_id: cfg.connection_id.clone(),
        },
        LocalControlOk::Invite {
            code: invite.encode().unwrap(),
        },
        LocalControlOk::Revoked {
            report: RevocationReport {
                node_id: peer.node_id,
                display_name: peer.name,
                peers: cfg.peers.clone(),
            },
        },
        LocalControlOk::PolicyUpdated {
            report: NetworkPolicyReport {
                max_peers: 250,
                issuer_node_id: cfg.creator_node_id,
                issued_at_unix: 123,
                peers: cfg.peers.clone(),
            },
        },
    ] {
        roundtrip(&LocalControlResponse::ok(response));
    }
    roundtrip(&LocalControlResponse::err("rejected".to_string()));
}

#[test]
fn compact_records_use_cbor_strings_and_preserve_valid_signatures() {
    let (mut cfg, _, membership, revocation) = records();
    let code = cfg
        .issue_invite("Test peer", &[22], MembershipRole::Peer)
        .unwrap()
        .code;
    let invite = Invite::decode(&code).unwrap();
    let bytes = URL_SAFE_NO_PAD.decode(&code).unwrap();
    let mut d = minicbor::Decoder::new(&bytes);
    assert_eq!(d.array().unwrap(), Some(6));
    assert_eq!(d.u8().unwrap(), INVITE_VERSION);
    assert_eq!(d.str().unwrap(), invite.network_id);
    assert_eq!(d.str().unwrap(), invite.invite_id);
    assert_eq!(d.str().unwrap(), invite.invite_secret);
    assert_eq!(d.bytes().unwrap(), invite.creator_node_id.as_bytes());
    assert_eq!(d.bytes().unwrap(), invite.inviter_node_id.as_bytes());
    assert_eq!(d.position(), bytes.len());

    let member =
        MembershipCertificate::decode_compact(&membership.encode_compact().unwrap()).unwrap();
    assert_eq!(member, membership);
    member.verify_signature().unwrap();
    let policy =
        NetworkPolicyCertificate::decode_compact(&cfg.network_policy.encode_compact().unwrap())
            .unwrap();
    assert_eq!(policy, cfg.network_policy);
    policy.verify_signature().unwrap();
    let revoked =
        RevocationCertificate::decode_compact(&revocation.encode_compact().unwrap()).unwrap();
    assert_eq!(revoked, revocation);
    revoked.verify_signature().unwrap();

    let bytes = URL_SAFE_NO_PAD
        .decode(membership.encode_compact().unwrap())
        .unwrap();
    let mut d = minicbor::Decoder::new(&bytes);
    assert_eq!(d.array().unwrap(), Some(11));
    d.skip().unwrap(); // version
    assert_eq!(d.str().unwrap(), membership.network_id);
    assert_eq!(d.bytes().unwrap().len(), 32);
    assert_eq!(d.str().unwrap(), membership.subject_connection_id);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.array().unwrap(), Some(1));
    assert_eq!(d.u16().unwrap(), 22);
    assert_eq!(d.bytes().unwrap().len(), 32);
    assert_eq!(d.str().unwrap(), membership.signature);
    assert_eq!(d.str().unwrap(), membership.admin_label);
    d.null().unwrap();
    assert_eq!(d.u64().unwrap(), membership.joined_at_unix);
    assert_eq!(d.position(), bytes.len());
}

#[test]
fn invalid_record_versions_and_policy_limits_are_rejected() {
    let (cfg, _, mut membership, mut revocation) = records();
    membership.version += 1;
    let code = URL_SAFE_NO_PAD.encode(minicbor::to_vec(&membership).unwrap());
    assert!(MembershipCertificate::decode_compact(&code).is_err());
    revocation.version += 1;
    let code = URL_SAFE_NO_PAD.encode(minicbor::to_vec(&revocation).unwrap());
    assert!(RevocationCertificate::decode_compact(&code).is_err());
    let mut policy = cfg.network_policy.clone();
    policy.version += 1;
    let code = URL_SAFE_NO_PAD.encode(minicbor::to_vec(&policy).unwrap());
    assert!(NetworkPolicyCertificate::decode_compact(&code).is_err());
    for limit in [0, ABSOLUTE_MAX_KNOWN_PEERS + 1] {
        let mut policy = cfg.network_policy.clone();
        policy.max_peers = limit;
        let code = URL_SAFE_NO_PAD.encode(minicbor::to_vec(&policy).unwrap());
        assert!(NetworkPolicyCertificate::decode_compact(&code).is_err());
    }
    assert!(cbor::decode_exact::<MembershipRole>(&[9]).is_err());
}

#[test]
fn invalid_invite_fields_are_rejected_at_record_boundaries() {
    let (mut cfg, _, _, _) = records();
    let code = cfg
        .issue_invite("Test peer", &[22], MembershipRole::Peer)
        .unwrap()
        .code;
    let invite = Invite::decode(&code).unwrap();
    for (version, network_id, invite_id, secret) in [
        (
            INVITE_VERSION + 1,
            cfg.network_id.as_str(),
            "ABC123",
            invite.invite_secret.clone(),
        ),
        (
            INVITE_VERSION,
            "not-a-uuid",
            "ABC123",
            invite.invite_secret.clone(),
        ),
        (
            INVITE_VERSION,
            cfg.network_id.as_str(),
            "bad id",
            invite.invite_secret.clone(),
        ),
        (
            INVITE_VERSION,
            cfg.network_id.as_str(),
            "ABC123",
            "invalid base64!".to_string(),
        ),
        (
            INVITE_VERSION,
            cfg.network_id.as_str(),
            "ABC123",
            URL_SAFE_NO_PAD.encode([0; 15]),
        ),
        (
            INVITE_VERSION,
            cfg.network_id.as_str(),
            "ABC123",
            URL_SAFE_NO_PAD.encode([0; 17]),
        ),
    ] {
        let invalid = Invite {
            version,
            network_id: network_id.to_string(),
            invite_id: invite_id.to_string(),
            invite_secret: secret,
            ..invite.clone()
        };
        assert!(invalid.encode().is_err());
        // Raw derives encode strings; the application must reject invalid records.
        let code = cbor::encode_compact(&invalid).unwrap();
        assert!(Invite::decode(&code).is_err());
    }
}

#[test]
fn invalid_certificate_strings_are_rejected_at_record_boundaries() {
    let (cfg, _, membership, revocation) = records();
    for (network_id, signature) in [
        ("not-a-uuid", membership.signature.clone()),
        (cfg.network_id.as_str(), "invalid base64!".to_string()),
        (cfg.network_id.as_str(), URL_SAFE_NO_PAD.encode([0; 63])),
        (cfg.network_id.as_str(), URL_SAFE_NO_PAD.encode([0; 65])),
    ] {
        let member = MembershipCertificate {
            network_id: network_id.to_string(),
            signature: signature.clone(),
            ..membership.clone()
        };
        assert!(member.encode_compact().is_err());
        assert!(
            MembershipCertificate::decode_compact(&cbor::encode_compact(&member).unwrap()).is_err()
        );
        assert!(member.verify_signature().is_err());

        let policy = NetworkPolicyCertificate {
            network_id: network_id.to_string(),
            signature: signature.clone(),
            ..cfg.network_policy.clone()
        };
        assert!(policy.encode_compact().is_err());
        assert!(
            NetworkPolicyCertificate::decode_compact(&cbor::encode_compact(&policy).unwrap())
                .is_err()
        );
        assert!(policy.verify_signature().is_err());

        let revoked = RevocationCertificate {
            network_id: network_id.to_string(),
            signature,
            ..revocation.clone()
        };
        assert!(revoked.encode_compact().is_err());
        assert!(
            RevocationCertificate::decode_compact(&cbor::encode_compact(&revoked).unwrap())
                .is_err()
        );
        assert!(revoked.verify_signature().is_err());
    }
}

#[test]
fn invite_proofs_validate_secret_strings_before_granting_access() {
    let (mut cfg, _, _, _) = records();
    let code = cfg
        .issue_invite("Test peer", &[22], MembershipRole::Peer)
        .unwrap()
        .code;
    let invite = Invite::decode(&code).unwrap();
    let mut proof = InviteProof {
        invite_id: invite.invite_id,
        invite_secret: invite.invite_secret,
    };
    assert!(cfg.invite_grant_for_proof(Some(&proof)).unwrap().is_some());
    for secret in [
        "invalid base64!".to_string(),
        URL_SAFE_NO_PAD.encode([0; 15]),
        URL_SAFE_NO_PAD.encode([0; 17]),
    ] {
        // Even a matching stored hash must not make a malformed secret acceptable.
        cfg.invites[0].secret_hash = hash_invite_secret(&secret);
        proof.invite_secret = secret;
        let bytes = minicbor::to_vec(&proof).unwrap();
        let decoded = cbor::decode_exact::<InviteProof>(&bytes).unwrap();
        assert!(cfg.invite_grant_for_proof(Some(&decoded)).is_err());
    }
}

#[test]
fn endpoint_id_adapter_rejects_invalid_key_lengths() {
    let (mut cfg, _, _, _) = records();
    let code = cfg
        .issue_invite("Test peer", &[22], MembershipRole::Peer)
        .unwrap()
        .code;
    let invite = Invite::decode(&code).unwrap();
    for (creator_len, inviter_len) in [(31, 32), (32, 31)] {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(INVITE_VERSION)
            .unwrap()
            .str(&invite.network_id)
            .unwrap()
            .str(&invite.invite_id)
            .unwrap()
            .str(&invite.invite_secret)
            .unwrap()
            .bytes(&invite.creator_node_id.as_bytes()[..creator_len])
            .unwrap()
            .bytes(&invite.inviter_node_id.as_bytes()[..inviter_len])
            .unwrap();
        assert!(Invite::decode(&URL_SAFE_NO_PAD.encode(e.into_writer())).is_err());
    }
}

#[test]
fn compact_decoding_rejects_truncation_trailing_data_and_oversize() {
    let (cfg, _, _, _) = records();
    let bytes = minicbor::to_vec(&cfg.network_policy).unwrap();
    for end in 0..bytes.len() {
        assert!(
            NetworkPolicyCertificate::decode_compact(&URL_SAFE_NO_PAD.encode(&bytes[..end]))
                .is_err()
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(NetworkPolicyCertificate::decode_compact(&URL_SAFE_NO_PAD.encode(trailing)).is_err());
    assert!(cbor::decode_exact::<LocalControlRequest>(&[0xff]).is_err());
    assert!(cbor::decode_exact::<LocalControlRequest>(b"Status\n").is_err());
    let oversized = vec![0; cbor::MAX_VALUE_LEN + 1];
    assert!(cbor::decode_exact::<LocalControlRequest>(&oversized).is_err());
    assert!(Invite::decode(&URL_SAFE_NO_PAD.encode(oversized)).is_err());
}

#[tokio::test]
async fn frames_preserve_boundaries_before_raw_ssh_bytes() {
    let mut wire = Vec::new();
    write_cbor_frame(&mut wire, &LocalProxyResponse::Ready, 1024, "ready")
        .await
        .unwrap();
    let payload_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
    assert_eq!(payload_len, wire.len() - 2);
    assert_eq!(&wire[2..], &[0x82, 0, 0x80]);
    write_cbor_frame(&mut wire, &LocalControlRequest::Status, 1024, "status")
        .await
        .unwrap();
    wire.extend_from_slice(b"SSH-2.0-test\r\n");
    let mut reader = &wire[..];
    assert_eq!(
        read_cbor_frame::<_, LocalProxyResponse>(&mut reader, 1024, "ready")
            .await
            .unwrap(),
        LocalProxyResponse::Ready
    );
    assert_eq!(
        read_cbor_frame::<_, LocalControlRequest>(&mut reader, 1024, "status")
            .await
            .unwrap(),
        LocalControlRequest::Status
    );
    assert_eq!(reader, b"SSH-2.0-test\r\n");
}

#[tokio::test]
async fn frames_reject_invalid_lengths_payloads_and_trailing_values() {
    let mut output = Vec::new();
    assert!(
        write_cbor_frame(&mut output, &LocalControlRequest::Status, 2, "small")
            .await
            .is_err()
    );
    assert!(output.is_empty());
    let oversized = LocalControlRequest::Rename {
        name: "x".repeat(usize::from(u16::MAX)),
    };
    assert!(
        write_cbor_frame(&mut output, &oversized, usize::MAX, "huge")
            .await
            .is_err()
    );
    assert!(output.is_empty());
    let err = read_cbor_frame::<_, LocalControlRequest>(&mut &[0, 64][..], 32, "bounded")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("too large"));
    for bytes in [
        vec![0],                      // truncated length
        vec![0, 0],                   // empty payload
        vec![0, 3, 0x82, 1],          // truncated payload
        vec![0, 1, 0xff],             // invalid CBOR
        vec![0, 4, 0x82, 1, 0x80, 0], // trailing value inside frame
        vec![0, 3, 0x82, 99, 0x80],   // unknown request variant
    ] {
        assert!(
            read_cbor_frame::<_, LocalControlRequest>(&mut &bytes[..], 1024, "invalid")
                .await
                .is_err()
        );
    }
}
