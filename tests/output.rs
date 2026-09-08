#![allow(dead_code)]

include!("../src/main.rs");

use output::{Format, FormatConfig, Options};
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
        vec!["init", "Test network"],
        vec!["join", "invite-code"],
        vec!["rename", "Test network", "host"],
        vec!["invite", "Test network", "Laptop"],
        vec!["revoke", "Test network", "ABC123"],
        vec!["policy", "Test network", "--max-peers", "100"],
        vec!["status"],
    ] {
        for (args, format, no_color) in [
            (vec![], None, false),
            (vec!["--format", "json"], Some(Format::Json), false),
            (vec!["--no-color"], None, true),
            (
                vec!["--format", "json", "--color"],
                Some(Format::Json),
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

    fn network(&self) -> PathBuf {
        let store = networks::Store {
            root: self.0.join(ESP_DIR),
        };
        let cfg = store.select("Test network").unwrap();
        store.path(&cfg.network_id).unwrap()
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
        if !flags.contains(&"json") {
            assert_eq!(stdout.contains('\x1b'), !flags.contains(&"--no-color"));
            let plain = strip_colors(&stdout);
            let fields = plain
                .split("\n\n")
                .next()
                .unwrap()
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
fn command_reports_default_to_colorized_text_and_support_json() {
    for flags in [
        vec![],
        vec!["--format", "json"],
        vec!["--no-color"],
        vec!["--format", "json", "--no-color"],
        vec!["--format", "text"],
        vec!["--format", "text", "--no-color"],
    ] {
        let home = Home::new();
        let init = home.report(&["init", "Test network"], &flags);
        assert_eq!(init["network_label"], "Test network");
        assert_eq!(init["esp_config"], home.network().display().to_string());
        if !flags.contains(&"json") {
            assert!(init.get("next_step").is_none());
            let text = home.run(&["init", "Test network"], &flags);
            assert!(text.contains("esp invite 'Test network'"));
        } else {
            assert!(init["next_step"].as_str().unwrap().contains("esp invite"));
        }
        let cfg = Config::load(&home.network()).unwrap();
        assert_eq!(
            init["node_id"],
            cfg.secret_key().unwrap().public().to_string()
        );
        assert_eq!(init["connection_id"], cfg.connection_id);
        // Existing-config init uses the same report format.
        assert_eq!(home.report(&["init", "Test network"], &flags), init);
        let renamed = home.report(&["rename", "Test network", "new-host"], &flags);
        assert_eq!(renamed["name"], "new-host");
        assert_eq!(renamed["connection_id"], cfg.connection_id);
        let policy = home.report(&["policy", "Test network", "--max-peers", "200"], &flags);
        assert_eq!(
            policy["max_peers"],
            if !flags.contains(&"json") {
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
        let invite = home.report(&["invite", "Test network", "Laptop"], &flags);
        Invite::decode(invite["invite_code"].as_str().unwrap()).unwrap();

        let mut cfg = Config::load(&home.network()).unwrap();
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
        cfg.save(&home.network()).unwrap();
        let revoked = home.report(&["revoke", "Test network", "REMOVE"], &flags);
        assert_eq!(revoked["revoked"], peer.node_id.to_string());
        assert_eq!(revoked["name"], peer.display_name());
    }
}

#[test]
fn invite_output_names_destination_and_prints_complete_join_command() {
    let home = Home::new();
    home.run(&["init", "rtn"], &[]);
    for flags in [
        vec![],
        vec!["--no-color"],
        vec!["--format", "json", "--no-color"],
    ] {
        let stdout = home.run(&["invite", "rtn", "  mbp  "], &flags);
        assert_eq!(stdout.contains('\x1b'), !flags.contains(&"--no-color"));
        let plain = strip_colors(&stdout);
        let (code, hint) = if flags.contains(&"json") {
            let report: Value = serde_json::from_str(&plain).unwrap();
            (
                report["invite_code"].as_str().unwrap().to_owned(),
                report["next_step"].as_str().unwrap().to_owned(),
            )
        } else {
            let (field, hint) = plain.trim_end().split_once("\n\n").unwrap();
            (
                field.strip_prefix("invite_code: ").unwrap().to_owned(),
                hint.to_owned(),
            )
        };
        Invite::decode(&code).unwrap();
        assert_eq!(
            hint,
            format!(
                "Copy this join code and run it on the host “mbp” with the command\n\nesp join {code}"
            )
        );
    }
}

#[test]
fn join_report_contains_all_fields_and_formats_ports_and_identity() {
    let key = SecretKey::generate();
    let mut cfg = create_creator_config(
        "Test network",
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
            "network_label": "Test network",
        })
    );
    let colored = Options {
        format: Format::Json,
        no_color: false,
    }
    .render(&report)
    .unwrap();
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
        assert_eq!(text.contains('\x1b'), !no_color);
        let text = strip_colors(&text);
        assert!(text.contains("allowed_ports: 22\n"));
        assert!(text.contains("connection_id: JOIN01\n"));
        assert!(text.contains("join_sync: complete\n"));
    }
}

fn format_configs() -> [FormatConfig; 4] {
    [
        FormatConfig {
            kind: Format::Json,
            colorize: true,
        },
        FormatConfig {
            kind: Format::Json,
            colorize: false,
        },
        FormatConfig {
            kind: Format::Text,
            colorize: true,
        },
        FormatConfig {
            kind: Format::Text,
            colorize: false,
        },
    ]
}

#[test]
fn config_format_defaults_roundtrips_and_rejects_legacy_settings() {
    let home = Home::new();
    assert_eq!(output::read_format(&home.config()).unwrap(), None);
    home.report(&["init", "Test network"], &[]);
    let mut cfg = networks::GlobalConfig::load(&home.config()).unwrap();
    assert_eq!(
        cfg.format,
        FormatConfig {
            kind: Format::Text,
            colorize: true
        }
    );
    for format in format_configs() {
        cfg.format = format;
        cfg.save(&home.config()).unwrap();
        assert_eq!(output::read_format(&home.config()).unwrap(), Some(format));
    }
    for invalid in [
        "json",
        "json_colorized",
        "text",
        "type: yaml\ncolorize: true",
        "type: text\ncolorize: wrong",
        "type: text\ncolorise: true",
    ] {
        let mut yaml = serde_yaml::to_value(&cfg).unwrap();
        yaml["format"] = serde_yaml::from_str(invalid).unwrap();
        write_private_config(
            &home.config(),
            serde_yaml::to_string(&yaml).unwrap().as_bytes(),
        )
        .unwrap();
        assert!(networks::GlobalConfig::load(&home.config()).is_err());
        assert!(output::read_format(&home.config()).is_err());
    }
}

fn assert_report_format(stdout: &str, format: Format, no_color: bool) {
    assert_eq!(stdout.contains('\x1b'), !no_color);
    let plain = strip_colors(stdout);
    if format == Format::Text {
        assert!(!plain.starts_with('{'));
        let fields = plain.split("\n\n").next().unwrap();
        assert!(fields.lines().all(|line| line.contains(": ")));
        if !no_color {
            assert!(stdout.contains("\x1b[1;37m"));
            assert!(stdout.contains("\x1b[94m"));
        }
    } else {
        assert!(serde_json::from_str::<Value>(&plain).unwrap().is_object());
    }
}

#[test]
fn command_line_overrides_type_and_color_independently_without_persisting() {
    let home = Home::new();
    home.report(&["init", "Test network"], &[]);
    for configured in format_configs() {
        let mut cfg = networks::GlobalConfig::load(&home.config()).unwrap();
        cfg.format = configured;
        cfg.save(&home.config()).unwrap();
        for (flags, expected, no_color) in [
            (vec![], configured.kind, !configured.colorize),
            (vec!["--no-color"], configured.kind, true),
            (vec!["--color"], configured.kind, false),
            (vec!["--format", "json"], Format::Json, !configured.colorize),
            (vec!["--format", "text"], Format::Text, !configured.colorize),
            (vec!["--format", "text", "--color"], Format::Text, false),
            (vec!["--format", "text", "--no-color"], Format::Text, true),
        ] {
            assert_report_format(
                &home.run(&["status", "Test network"], &flags),
                expected,
                no_color,
            );
        }
        for command in [
            vec!["init", "Test network"],
            vec!["rename", "Test network", "configured-host"],
            vec!["invite", "Test network", "Laptop"],
            vec!["policy", "Test network", "--max-peers", "100"],
        ] {
            assert_report_format(
                &home.run(&command, &[]),
                configured.kind,
                !configured.colorize,
            );
        }
        home.run(
            &["rename", "Test network", "cli-override"],
            &["--format", "json", "--no-color"],
        );
        assert_eq!(
            networks::GlobalConfig::load(&home.config()).unwrap().format,
            configured
        );
    }
    assert!(Cli::try_parse_from(["esp", "status", "--color", "--no-color"]).is_err());
}

#[test]
fn text_init_hint_follows_fields_without_a_key_or_color() {
    let report = json!({ "connection_id": "H9mx5Y", "node_id": "abc", "next_step": "run `esp invite \"name\"` to create a named invite" });
    for no_color in [true, false] {
        let text = Options {
            format: Format::Text,
            no_color,
        }
        .render(&report)
        .unwrap();
        assert_eq!(
            strip_colors(&text),
            "connection_id: H9mx5Y\nnode_id: abc\n\nrun `esp invite \"name\"` to create a named invite"
        );
        assert!(!text.contains("next_step"));
        assert!(!text.split("\n\n").nth(1).unwrap().contains('\x1b'));
        if !no_color {
            assert!(text.starts_with("\x1b[1;37mconnection_id:\x1b[0m \x1b[94mH9mx5Y\x1b[0m\n"));
        }
    }
    let json = Options {
        format: Format::Json,
        no_color: false,
    }
    .render(&report)
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&strip_colors(&json)).unwrap()["next_step"],
        report["next_step"]
    );
}

#[tokio::test]
async fn running_transport_preserves_transport_edits_on_disk() {
    let home = Home::new();
    home.report(&["init", "Test network"], &[]);
    let path = home.network();
    let mut cfg = Config::load(&path).unwrap();
    let actor = spawn_config_actor(path.clone(), cfg.clone());
    for ports in [Some(vec![]), Some(vec![80, 443]), None] {
        cfg.transport.ports = ports.clone();
        cfg.save(&path).unwrap();
        actor.rename("renamed".into()).await.unwrap();
        cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.transport.ports, ports);
        assert_eq!(cfg.name, "renamed");
    }
}

#[test]
fn init_requires_a_valid_network_label_and_creates_independent_networks() {
    assert!(Cli::try_parse_from(["esp", "init"]).is_err());
    for label in ["", "  ", "line\nbreak", "\x1b[31m", &"x".repeat(65)] {
        let home = Home::new();
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_esp"))
            .env("HOME", &home.0)
            .args(["init", label])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert_eq!(
            fs::read_dir(home.0.join(ESP_DIR).join("networks"))
                .map(|r| r.count())
                .unwrap_or(0),
            0
        );
    }
    let home = Home::new();
    let first = home.report(&["init", "Test network"], &["--no-color"]);
    let other = home.report(&["init", "  Office / Lab  "], &["--no-color"]);
    assert_eq!(other["network_label"], "Office / Lab");
    assert_ne!(first["network_id"], other["network_id"]);
    assert_ne!(first["node_id"], other["node_id"]);
    assert_eq!(
        first,
        home.report(
            &["init", "Test network", "--max-peers", "50"],
            &["--no-color"]
        )
    );
    assert_eq!(
        Config::load(&home.network())
            .unwrap()
            .network_policy
            .max_peers,
        100
    );
}
