use super::*;

fn props(entries: &[(&str, OwnedValue)]) -> Properties {
    entries
        .iter()
        .map(|(key, value)| (key.to_string(), value.try_clone().unwrap()))
        .collect()
}

fn spec(connector: &str) -> MonitorSpec {
    (
        connector.into(),
        "Vendor".into(),
        "Model".into(),
        format!("serial-{connector}"),
    )
}

fn monitor(connector: &str, width: i32, height: i32, active: bool) -> RawMonitor {
    (
        spec(connector),
        vec![(
            format!("{width}x{height}@60"),
            width,
            height,
            60.0,
            1.0,
            vec![1.0, 2.0],
            props(&[("is-current", active.into())]),
        )],
        Properties::new(),
    )
}

fn layout(connectors: &[&str], scale: f64, transform: u32) -> RawLogicalMonitor {
    (
        -1920,
        0,
        scale,
        transform,
        true,
        connectors.iter().map(|name| spec(name)).collect(),
        Properties::new(),
    )
}

fn fixture() -> CurrentState {
    (
        42,
        vec![
            monitor("eDP-1", 3840, 2160, true),
            monitor("DP-1", 1920, 1080, false),
        ],
        vec![layout(&["eDP-1"], 2.0, 0)],
        Properties::new(),
    )
}

#[test]
fn discovery_keeps_inactive_outputs_and_uses_physical_not_logical_pixels() {
    let (_, monitors, logical, _) = fixture();
    let displays = parse_displays(monitors, logical).unwrap();
    assert_eq!(displays.len(), 2);
    assert_eq!(displays[0].identity.connector, "DP-1");
    assert!(!displays[0].active);
    assert_eq!(
        displays[0].source_unavailable_reason.as_deref(),
        Some("display is inactive")
    );
    let active = &displays[1];
    assert_eq!(
        active.mode.as_ref().unwrap().pixels,
        Size {
            width: 3840,
            height: 2160
        }
    );
    assert_eq!(active.placement.as_ref().unwrap().scale, 2.0);
    assert_eq!(
        active.suggested_stream_size,
        Some(Size {
            width: 1920,
            height: 1080
        })
    );
}

#[test]
fn snapshot_order_does_not_change_ids_and_clone_groups_stay_explicit() {
    let monitors = vec![
        monitor("DP-1", 1920, 1080, true),
        monitor("DP-2", 1920, 1080, true),
    ];
    let normal = parse_displays(monitors, vec![layout(&["DP-1", "DP-2"], 1.0, 0)]).unwrap();
    let reversed = parse_displays(
        vec![
            monitor("DP-2", 1920, 1080, true),
            monitor("DP-1", 1920, 1080, true),
        ],
        vec![layout(&["DP-1", "DP-2"], 1.0, 0)],
    )
    .unwrap();
    assert_eq!(
        normal.iter().map(|d| &d.id).collect::<Vec<_>>(),
        reversed.iter().map(|d| &d.id).collect::<Vec<_>>()
    );
    for display in normal {
        assert_eq!(
            display.placement.unwrap().mirrored_connectors,
            ["DP-1", "DP-2"]
        );
    }
}

#[test]
fn unsupported_source_does_not_hide_other_displays() {
    let mut hdr = monitor("DP-2", 1920, 1080, true);
    hdr.2.insert("color-mode".into(), 1u32.into());
    let displays = parse_displays(
        vec![
            monitor("DP-1", 5120, 1440, true),
            hdr,
            monitor("DP-3", 1920, 1080, true),
        ],
        vec![
            layout(&["DP-1"], 1.0, 0),
            layout(&["DP-2"], 1.0, 0),
            layout(&["DP-3"], 1.0, 0),
        ],
    )
    .unwrap();
    assert!(
        displays[0]
            .source_unavailable_reason
            .as_ref()
            .unwrap()
            .contains("4096")
    );
    assert!(
        displays[1]
            .source_unavailable_reason
            .as_ref()
            .unwrap()
            .contains("HDR")
    );
    assert!(displays[2].suggested_stream_size.is_some());
}

#[test]
fn stale_and_ambiguous_layouts_are_rejected() {
    assert!(
        parse_displays(
            vec![monitor("DP-1", 1920, 1080, true)],
            vec![layout(&["DP-2"], 1.0, 0)]
        )
        .is_err()
    );
    assert!(
        parse_displays(
            vec![
                monitor("DP-1", 1920, 1080, true),
                monitor("DP-1", 1920, 1080, true)
            ],
            vec![]
        )
        .is_err()
    );
    assert!(
        parse_displays(
            vec![monitor("DP-1", 1920, 1080, true)],
            vec![layout(&["DP-1"], 1.0, 0), layout(&["DP-1"], 1.0, 0)]
        )
        .is_err()
    );
    assert!(parse_displays(vec![monitor("DP-1", 1920, 1080, true)], vec![]).is_err());
    let mut replaced = layout(&["DP-1"], 1.0, 0);
    replaced.5[0].3 = "different-serial".into();
    assert!(parse_displays(vec![monitor("DP-1", 1920, 1080, true)], vec![replaced]).is_err());
}

#[test]
fn malformed_properties_modes_and_transforms_are_rejected() {
    for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
        assert!(
            parse_displays(
                vec![monitor("DP-1", 1920, 1080, true)],
                vec![layout(&["DP-1"], scale, 0)]
            )
            .is_err()
        );
    }
    assert!(
        parse_displays(
            vec![monitor("DP-1", 1920, 1080, true)],
            vec![layout(&["DP-1"], 1.0, 8)]
        )
        .is_err()
    );
    let mut malformed = monitor("DP-1", 1920, 1080, true);
    malformed.1[0].6.insert("is-current".into(), 1u32.into());
    assert!(parse_displays(vec![malformed], vec![layout(&["DP-1"], 1.0, 0)]).is_err());
    let mut multiple = monitor("DP-1", 1920, 1080, true);
    multiple
        .1
        .push(monitor("DP-1", 1280, 720, true).1.remove(0));
    assert!(parse_displays(vec![multiple], vec![layout(&["DP-1"], 1.0, 0)]).is_err());
}

struct MockDisplayConfig;

#[zbus::interface(name = "org.gnome.Mutter.DisplayConfig")]
impl MockDisplayConfig {
    #[zbus(out_args("serial", "monitors", "logical_monitors", "properties"))]
    fn get_current_state(&self) -> CurrentState {
        fixture()
    }

    #[zbus(property)]
    fn apply_monitors_config_allowed(&self) -> bool {
        true
    }
}

struct MockScreenCast;

#[zbus::interface(name = "org.gnome.Mutter.ScreenCast")]
impl MockScreenCast {
    #[zbus(property)]
    fn version(&self) -> i32 {
        4
    }
}

struct OlderDisplayConfig;

#[zbus::interface(name = "org.gnome.Mutter.DisplayConfig")]
impl OlderDisplayConfig {
    #[zbus(out_args("serial", "monitors", "logical_monitors", "properties"))]
    fn get_current_state(&self) -> CurrentState {
        fixture()
    }
}

/// Exercise real D-Bus serialization on an isolated bus, without contacting or
/// changing the user's desktop. Kill the private bus even when a test panics.
async fn private_bus() -> (tokio::process::Child, String) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut child = tokio::process::Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--nopidfile", "--print-address=1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("video D-Bus integration tests require dbus-daemon");
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!line.trim().is_empty());
    (child, line.trim().into())
}

#[tokio::test]
async fn reads_real_dbus_shapes_and_reports_missing_services_without_activation() {
    let (_bus, address) = private_bus().await;
    let client = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let error = discover_on(&client).await.unwrap_err();
    assert!(error.to_string().contains("no running GNOME/Mutter"));

    let server = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .name(DESTINATION)
        .unwrap()
        .name(SCREENCAST_DESTINATION)
        .unwrap()
        .serve_at(PATH, MockDisplayConfig)
        .unwrap()
        .serve_at("/org/gnome/Mutter/ScreenCast", MockScreenCast)
        .unwrap()
        .build()
        .await
        .unwrap();
    let report = tokio::time::timeout(std::time::Duration::from_secs(5), discover_on(&client))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.configuration_serial, 42);
    assert_eq!(report.configuration_changes_allowed, Some(true));
    assert_eq!(report.screencast_version, Some(4));
    assert_eq!(report.mirror_support, "not_yet_validated");
    assert_eq!(report.displays.len(), 2);
    assert_eq!(
        report.displays[1].suggested_stream_size,
        Some(Size {
            width: 1920,
            height: 1080
        })
    );
    drop(server);
}

#[tokio::test]
async fn missing_optional_apis_do_not_hide_displays_or_claim_mirror_support() {
    let (_bus, address) = private_bus().await;
    let _server = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .name(DESTINATION)
        .unwrap()
        .serve_at(PATH, OlderDisplayConfig)
        .unwrap()
        .build()
        .await
        .unwrap();
    let client = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let report = tokio::time::timeout(std::time::Duration::from_secs(5), discover_on(&client))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.configuration_changes_allowed, None);
    assert_eq!(report.screencast_version, None);
    assert_eq!(report.displays.len(), 2);
    assert_eq!(report.mirror_support, "not_yet_validated");
}
