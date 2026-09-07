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
            (vec![], None, false),
            (vec!["--format", "json"], Some(Format::Json), false),
            (vec!["--no-color"], None, true),
            (
                vec!["--format", "json_colorized"],
                Some(Format::JsonColorized),
                false,
            ),
            (vec!["--format", "text"], Some(Format::Text), false),
            (
                vec!["--format", "text", "--no-color"],
                Some(Format::Text),
                true,
            ),
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

    fn run(&self, command: &[&str], flags: &[&str]) -> String {
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
        String::from_utf8(output.stdout).unwrap()
    }

    fn report(&self, command: &[&str], flags: &[&str]) -> Value {
        let stdout = self.run(command, flags);
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
            assert_eq!(
                stdout.contains('\x1b'),
                !flags.contains(&"--no-color") && !flags.contains(&"json")
            );
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

#[test]
fn config_format_defaults_and_roundtrips_without_changing_network_identity() {
    let home = Home::new();
    assert_eq!(output::read_format(&home.config()).unwrap(), None);
    home.report(&["init"], &[]);
    let mut cfg = Config::load(&home.config()).unwrap();
    assert_eq!(cfg.format, Format::JsonColorized);
    let mut yaml = serde_yaml::to_value(&cfg).unwrap();
    yaml.as_mapping_mut()
        .unwrap()
        .remove(serde_yaml::Value::String("format".into()));
    write_private_config(
        &home.config(),
        serde_yaml::to_string(&yaml).unwrap().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        Config::load(&home.config()).unwrap().format,
        Format::JsonColorized
    );
    assert!(home.run(&["status"], &[]).contains('\x1b'));
    for (format, name) in [
        (Format::Json, "json"),
        (Format::JsonColorized, "json_colorized"),
        (Format::Text, "text"),
    ] {
        cfg.format = format;
        cfg.save(&home.config()).unwrap();
        assert!(
            fs::read_to_string(home.config())
                .unwrap()
                .contains(&format!("format: {name}\n"))
        );
        assert_eq!(Config::load(&home.config()).unwrap().format, format);
        assert_eq!(output::read_format(&home.config()).unwrap(), Some(format));
    }
    yaml["format"] = serde_yaml::Value::String("invalid".into());
    write_private_config(
        &home.config(),
        serde_yaml::to_string(&yaml).unwrap().as_bytes(),
    )
    .unwrap();
    assert!(Config::load(&home.config()).is_err());
    assert!(output::read_format(&home.config()).is_err());
}

fn assert_report_format(stdout: &str, format: Format, no_color: bool) {
    assert_eq!(
        stdout.contains('\x1b'),
        format == Format::JsonColorized && !no_color
    );
    if format == Format::Text {
        assert!(!stdout.starts_with('{'));
        assert!(stdout.lines().all(|line| line.contains(": ")));
    } else {
        assert!(
            serde_json::from_str::<Value>(&strip_colors(stdout))
                .unwrap()
                .is_object()
        );
    }
}

#[test]
fn command_line_overrides_config_format_without_persisting_overrides() {
    let home = Home::new();
    home.report(&["init"], &[]);
    for configured in [Format::Json, Format::JsonColorized, Format::Text] {
        let mut cfg = Config::load(&home.config()).unwrap();
        cfg.format = configured;
        cfg.save(&home.config()).unwrap();
        for (flags, expected, no_color) in [
            (vec![], configured, false),
            (vec!["--no-color"], configured, true),
            (vec!["--format", "json"], Format::Json, false),
            (
                vec!["--format", "json_colorized"],
                Format::JsonColorized,
                false,
            ),
            (vec!["--format", "text"], Format::Text, false),
            (
                vec!["--format", "json_colorized", "--no-color"],
                Format::JsonColorized,
                true,
            ),
        ] {
            assert_report_format(&home.run(&["status"], &flags), expected, no_color);
        }
        for command in [
            vec!["init"],
            vec!["rename", "configured-host"],
            vec!["invite", "Laptop"],
            vec!["policy", "--max-peers", "100"],
        ] {
            assert_report_format(&home.run(&command, &[]), configured, false);
        }
        home.report(&["rename", "cli-override"], &["--format", "json"]);
        assert_eq!(Config::load(&home.config()).unwrap().format, configured);
    }
}

#[tokio::test]
async fn running_transport_preserves_format_edits_on_disk() {
    let home = Home::new();
    let mut cfg = create_creator_config(
        &SecretKey::generate(),
        Uuid::new_v4().to_string(),
        "local".into(),
        "LOCAL1".into(),
        100,
    )
    .unwrap();
    cfg.save(&home.config()).unwrap();
    let actor = spawn_config_actor(home.config(), cfg.clone());
    for format in [Format::Text, Format::Json, Format::JsonColorized] {
        cfg.format = format;
        cfg.save(&home.config()).unwrap();
        actor.rename("renamed".into()).await.unwrap();
        cfg = Config::load(&home.config()).unwrap();
        assert_eq!(cfg.format, format);
        assert_eq!(cfg.name, "renamed");
    }
}
