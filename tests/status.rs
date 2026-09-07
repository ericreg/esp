#![allow(dead_code)]

include!("../src/main.rs");

use output::Format;
use status_output::render;

fn report() -> StatusReport {
    StatusReport {
        network_id: "test-network".into(),
        connected_peers: Some(1),
        max_peers: 100,
        name: "laptop \"雪\" \\ path\nnext".into(),
        connection_id: "LOCAL1".into(),
        node_id: SecretKey::generate().public(),
        invites: vec!["invite-1".into()],
        peers: vec![Peer {
            node_id: SecretKey::generate().public(),
            name: "peer".into(),
            connection_id: "REMOTE".into(),
        }],
        revocations: vec![SecretKey::generate().public()],
    }
}

fn strip_colors(value: &str) -> String {
    let mut plain = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            assert_eq!(chars.next(), Some('['));
            for code in chars.by_ref() {
                if code == 'm' {
                    break;
                }
            }
        } else {
            plain.push(ch);
        }
    }
    plain
}

#[test]
fn json_preserves_status_fields_and_escaping_with_or_without_color() {
    let report = report();
    for running in [false, true] {
        let plain = render(
            Path::new("/tmp/config.yml"),
            &report,
            running,
            Format::Json,
            true,
            true,
        )
        .unwrap();
        assert!(!plain.contains('\x1b'));
        let json: serde_json::Value = serde_json::from_str(&plain).unwrap();
        assert_eq!(json["config"], "/tmp/config.yml");
        assert_eq!(
            json["transport"],
            if running { "running" } else { "not running" }
        );
        assert_eq!(json["network_id"], report.network_id);
        assert_eq!(json["max_peers"], 100);
        assert_eq!(json["connected_peers"], 1);
        assert_eq!(json["name"], report.name);
        assert_eq!(json["connection_id"], report.connection_id);
        assert_eq!(json["node_id"], report.node_id.to_string());
        assert_eq!(json["invites"][0], "invite-1");
        assert_eq!(json["peers"][0]["name"], "peer");
        assert_eq!(json["peers"][0]["connection_id"], "REMOTE");
        assert_eq!(
            json["peers"][0]["node_id"],
            report.peers[0].node_id.to_string()
        );
        assert_eq!(json["revocations"][0], report.revocations[0].to_string());
        let colored = render(
            Path::new("/tmp/config.yml"),
            &report,
            running,
            Format::Json,
            false,
            true,
        )
        .unwrap();
        assert!(colored.contains("\x1b[1;36m\"config\"\x1b[0m"));
        assert!(colored.contains("\x1b[33m100\x1b[0m"));
        assert_eq!(strip_colors(&colored), plain);
    }
}

#[test]
fn text_uses_snake_case_keys_without_added_color() {
    let mut report = report();
    report.name = "local".into();
    let expected = format!(
        "esp_config: /tmp/config.yml\ntransport: running\nnetwork: test-network\nmax_peers: 100\nname: local\nconnection_id: LOCAL1\nnode_id: {}\nconnected_peers: 1\nissued_invite: invite-1\npeer: peer (REMOTE) {}\nrevoked: {}",
        report.node_id, report.peers[0].node_id, report.revocations[0],
    );
    for no_color in [false, true] {
        assert_eq!(
            render(
                Path::new("/tmp/config.yml"),
                &report,
                true,
                Format::Text,
                no_color,
                true,
            )
            .unwrap(),
            expected
        );
    }
}

#[test]
fn status_cli_defaults_to_highlighted_json_and_supports_format_options() {
    // Keep the control socket path within macOS's Unix socket path limit.
    let home = std::env::temp_dir().join(format!(
        "esp-s-{}",
        &Uuid::new_v4().simple().to_string()[..12]
    ));
    std::fs::create_dir(&home).unwrap();
    let config = home.join(".esp/config.yml");
    create_creator_config(
        &SecretKey::generate(),
        Uuid::new_v4().to_string(),
        "local".into(),
        "LOCAL1".into(),
        100,
    )
    .unwrap()
    .save(&config)
    .unwrap();
    for args in [
        vec![],
        vec!["--format", "json"],
        vec!["--no-color"],
        vec!["--format", "json", "--no-color"],
        vec!["--format", "text"],
        vec!["--format", "text", "--no-color"],
        vec!["--peers"],
        vec!["--peers", "--no-color"],
        vec!["--format", "text", "--peers"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_esp"))
            .env("HOME", &home)
            .arg("status")
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        if args.contains(&"text") {
            assert!(stdout.starts_with("esp_config: "));
            assert!(stdout.contains("transport: not running\n"));
            assert!(!stdout.contains('\x1b'));
        } else {
            assert_eq!(stdout.contains('\x1b'), !args.contains(&"--no-color"));
            let json: serde_json::Value = serde_json::from_str(&strip_colors(&stdout)).unwrap();
            assert_eq!(json["transport"], "not running");
            assert_eq!(json["connected_peers"], 0);
            if args.contains(&"--peers") {
                assert_eq!(json["peers"], serde_json::json!([]));
            } else {
                assert!(json.get("peers").is_none());
            }
        }
    }
    assert!(Cli::try_parse_from(["esp", "status", "--format", "yaml"]).is_err());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn status_summary_omits_peer_details_in_both_formats() {
    let report = report();
    let json = render(
        Path::new("/tmp/config.yml"),
        &report,
        true,
        Format::Json,
        true,
        false,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["connected_peers"], 1);
    assert!(json.get("peers").is_none());
    let text = render(
        Path::new("/tmp/config.yml"),
        &report,
        true,
        Format::Text,
        false,
        false,
    )
    .unwrap();
    assert!(text.contains("\nconnected_peers: 1\n"));
    assert!(!text.contains("\npeer:"));
    assert!(!text.contains("REMOTE"));
}

#[test]
fn older_transport_reports_unknown_presence() {
    let mut report = report();
    report.connected_peers = None;
    let legacy = minicbor::to_vec(&report).unwrap();
    // Older reports contain the first eight fields, without the presence count.
    // The encoder omits the trailing optional field when it is None.
    assert_eq!(legacy[0], 0x88);
    let decoded: StatusReport = cbor::decode_exact(&legacy).unwrap();
    assert_eq!(decoded, report);
    let json = render(
        Path::new("/tmp/config.yml"),
        &decoded,
        true,
        Format::Json,
        true,
        false,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(json["connected_peers"].is_null());
    let text = render(
        Path::new("/tmp/config.yml"),
        &decoded,
        true,
        Format::Text,
        true,
        false,
    )
    .unwrap();
    assert!(text.contains("connected_peers: unknown"));
}
