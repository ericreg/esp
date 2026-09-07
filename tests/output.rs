#![allow(dead_code)]

include!("../src/main.rs");

use output::{Format, Options};
use serde_json::{Value, json};

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
fn every_report_command_accepts_the_same_format_options() {
    for command in [
        vec!["init"],
        vec!["join", "invite-code"],
        vec!["rename", "host"],
        vec!["invite", "Laptop"],
        vec!["revoke", "ABC123"],
        vec!["policy", "--max-peers", "100"],
        vec!["status"],
    ] {
        for (args, format, no_color) in [
            (vec![], Format::Json, false),
            (vec!["--format", "json"], Format::Json, false),
            (vec!["--no-color"], Format::Json, true),
            (vec!["--format", "text"], Format::Text, false),
            (vec!["--format", "text", "--no-color"], Format::Text, true),
        ] {
            let cli = Cli::try_parse_from(
                ["esp"]
                    .into_iter()
                    .chain(command.iter().copied())
                    .chain(args),
            )
            .unwrap();
            let output = match cli.command.unwrap() {
                Command::Init { output, .. }
                | Command::Join { output, .. }
                | Command::Rename { output, .. }
                | Command::Invite { output, .. }
                | Command::Revoke { output, .. }
                | Command::Policy { output, .. }
                | Command::Status { output, .. } => output,
                _ => panic!("expected a report command"),
            };
            assert_eq!(output.format, format);
            assert_eq!(output.no_color, no_color);
        }
        assert!(
            Cli::try_parse_from(
                ["esp"]
                    .into_iter()
                    .chain(command)
                    .chain(["--format", "yaml"])
            )
            .is_err()
        );
    }
}

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "esp-o-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn config(&self) -> PathBuf {
        self.0.join(ESP_DIR).join(CONFIG_FILE)
    }

    fn report(&self, command: &[&str], flags: &[&str]) -> Value {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_esp"))
            .env("HOME", &self.0)
            .args(command)
            .args(flags)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        if flags.contains(&"text") {
            assert!(!stdout.contains('\x1b'));
            let fields = stdout
                .lines()
                .map(|line| {
                    let (key, value) = line.split_once(": ").expect("key: value text output");
                    assert!(
                        key.bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                    );
                    (key.to_owned(), Value::String(value.to_owned()))
                })
                .collect();
            Value::Object(fields)
        } else {
            assert_eq!(stdout.contains('\x1b'), !flags.contains(&"--no-color"));
            serde_json::from_str(&strip_colors(&stdout)).unwrap()
        }
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn command_reports_are_json_by_default_and_plain_snake_case_text_on_request() {
    for flags in [
        vec![],
        vec!["--format", "json"],
        vec!["--no-color"],
        vec!["--format", "json", "--no-color"],
        vec!["--format", "text"],
        vec!["--format", "text", "--no-color"],
    ] {
        let home = Home::new();
        let init = home.report(&["init"], &flags);
        assert_eq!(init["esp_config"], home.config().display().to_string());
        assert!(init["next_step"].as_str().unwrap().contains("esp invite"));
        let cfg = Config::load(&home.config()).unwrap();
        assert_eq!(
            init["node_id"],
            cfg.secret_key().unwrap().public().to_string()
        );
        assert_eq!(init["connection_id"], cfg.connection_id);
        // Existing-config init uses the same report format.
        assert_eq!(home.report(&["init"], &flags), init);
        let renamed = home.report(&["rename", "new-host"], &flags);
        assert_eq!(renamed["name"], "new-host");
        assert_eq!(renamed["connection_id"], cfg.connection_id);
        let policy = home.report(&["policy", "--max-peers", "200"], &flags);
        assert_eq!(
            policy["max_peers"],
            if flags.contains(&"text") {
                json!("200")
            } else {
                json!(200)
            }
        );
        assert_eq!(
            policy["policy_issuer"],
            cfg.secret_key().unwrap().public().to_string()
        );
        assert!(policy.get("policy_issued_at").is_some());
        let invite = home.report(&["invite", "Laptop"], &flags);
        Invite::decode(invite["invite_code"].as_str().unwrap()).unwrap();

        let mut cfg = Config::load(&home.config()).unwrap();
        let peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "removed".into(),
            connection_id: "REMOVE".into(),
        };
        cfg.memberships.push(
            MembershipCertificate::issue(
                &cfg,
                &cfg.secret_key().unwrap(),
                &peer,
                &[22],
                MembershipRole::Peer,
            )
            .unwrap(),
        );
        cfg.peers.push(peer.clone());
        cfg.save(&home.config()).unwrap();
        let revoked = home.report(&["revoke", "REMOVE"], &flags);
        assert_eq!(revoked["revoked"], peer.node_id.to_string());
        assert_eq!(revoked["name"], peer.display_name());
    }
}

#[test]
fn join_report_contains_all_fields_and_formats_ports_and_identity() {
    let key = SecretKey::generate();
    let mut cfg = create_creator_config(
        &key,
        Uuid::new_v4().to_string(),
        "joined-host".into(),
        "JOIN01".into(),
        100,
    )
    .unwrap();
    cfg.peers.push(Peer {
        node_id: SecretKey::generate().public(),
        name: "inviter".into(),
        connection_id: "INV001".into(),
    });
    let report = join_report(Path::new("/tmp/config.yml"), &cfg).unwrap();
    assert_eq!(
        report,
        json!({
            "esp_config": "/tmp/config.yml",
            "name": "joined-host",
            "connection_id": "JOIN01",
            "node_id": key.public().to_string(),
            "peer": "inviter (INV001)",
            "role": "admin",
            "allowed_ports": [22],
            "join_sync": "complete",
        })
    );
    let colored = Options::default().render(&report).unwrap();
    assert!(colored.contains('\x1b'));
    assert_eq!(
        serde_json::from_str::<Value>(&strip_colors(&colored)).unwrap(),
        report
    );
    for no_color in [false, true] {
        let text = Options {
            format: Format::Text,
            no_color,
        }
        .render(&report)
        .unwrap();
        assert!(!text.contains('\x1b'));
        assert!(text.contains("allowed_ports: 22\n"));
        assert!(text.contains("connection_id: JOIN01\n"));
        assert!(text.contains("join_sync: complete\n"));
    }
}
