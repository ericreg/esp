#![allow(dead_code)]
include!("../src/main.rs");
use output::{Format, Options};
use serde_json::{Value, json};
fn strip_colors(value: &str) -> String {
    let mut plain = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            plain.push(ch);
        }
    }
    plain
}
fn summary() -> Value {
    json!({"daemon":"not_running", "networks":[{"network_label":"A","network_id":"a","transport":"not_running","connected_peers":null,"peer_count":2},{"network_label":"B","network_id":"b","transport":"error","error":"invalid network file"}]})
}
#[test]
fn highlighted_and_plain_json_are_equivalent() {
    let report = summary();
    for no_color in [true, false] {
        let text = status_output::render(
            &report,
            Options {
                format: Format::Json,
                no_color,
            },
        )
        .unwrap();
        assert_eq!(text.contains('\x1b'), !no_color);
        assert_eq!(
            serde_json::from_str::<Value>(&strip_colors(&text)).unwrap(),
            report
        );
    }
}
#[test]
fn text_groups_networks_and_shows_unknown_presence() {
    for no_color in [true, false] {
        let text = status_output::render(
            &summary(),
            Options {
                format: Format::Text,
                no_color,
            },
        )
        .unwrap();
        let plain = strip_colors(&text);
        let blocks: Vec<_> = plain.split("\n\n").collect();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0], "daemon: not_running");
        assert!(blocks[1].contains("network_label: A"));
        assert!(blocks[1].contains("connected_peers: unknown"));
        assert!(blocks[2].contains("error: invalid network file"));
        assert_eq!(text.contains('\x1b'), !no_color);
    }
}
#[test]
fn detailed_status_retains_counts_and_respects_explicit_peer_records() {
    let report = json!({"network_label":"A","connected_peers":2,"peer_count":3,"peers":[{"name":"same","connection_id":"PEER01"}]});
    let text = status_output::render(
        &report,
        Options {
            format: Format::Text,
            no_color: true,
        },
    )
    .unwrap();
    assert!(text.contains("connected_peers: 2"));
    assert!(text.contains("PEER01"));
    let empty = status_output::render(
        &json!({"daemon":"serving","networks":[]}),
        Options {
            format: Format::Text,
            no_color: true,
        },
    )
    .unwrap();
    assert_eq!(empty, "daemon: serving");
}
#[test]
fn status_cli_defaults_to_highlighted_json_and_supports_format_options() {
    let home = PathBuf::from("/tmp").join(format!(
        "esp-s-{}",
        &Uuid::new_v4().simple().to_string()[..12]
    ));
    fs::create_dir(&home).unwrap();
    let store = networks::Store {
        root: home.join(ESP_DIR),
    };
    store.prepare().unwrap();
    let cfg = create_creator_config(
        "Test network",
        &SecretKey::generate(),
        Uuid::new_v4().to_string(),
        "local".into(),
        "LOCAL1".into(),
        100,
    )
    .unwrap();
    cfg.save(&store.path(&cfg.network_id).unwrap()).unwrap();
    for args in [
        vec![],
        vec!["--no-color"],
        vec!["--peers"],
        vec!["--format", "text"],
        vec!["--format", "text", "--no-color", "--peers"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_esp"))
            .env("HOME", &home)
            .args(["status", "Test network"])
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.contains('\x1b'), !args.contains(&"--no-color"));
        let plain = strip_colors(&stdout);
        if args.contains(&"text") {
            assert!(plain.contains("transport: not_running"));
            assert!(plain.contains("connected_peers: unknown"));
        } else {
            let report: Value = serde_json::from_str(&plain).unwrap();
            assert_eq!(report["transport"], "not_running");
            assert!(report["connected_peers"].is_null());
            assert_eq!(report.get("peers").is_some(), args.contains(&"--peers"));
        }
    }
    assert!(Cli::try_parse_from(["esp", "status", "--format", "yaml"]).is_err());
    fs::remove_dir_all(home).unwrap();
}
