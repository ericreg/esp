use super::{
    Peer, StatusReport,
    output::{Format, Options},
};
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

pub(super) fn render(
    path: &Path,
    report: &StatusReport,
    transport_running: bool,
    format: Format,
    no_color: bool,
    peers: bool,
) -> Result<String> {
    let transport = if transport_running {
        "running"
    } else {
        "not running"
    };
    let options = Options { format, no_color };
    if format == Format::Text {
        let mut lines = vec![
            options.text_field("esp_config", &path.display().to_string()),
            options.text_field("transport", transport),
            options.text_field("network", &report.network_id),
            options.text_field(
                "network_label",
                report.network_label.as_deref().unwrap_or("not_recorded"),
            ),
            options.text_field("max_peers", &report.max_peers.to_string()),
            options.text_field("name", &report.name),
            options.text_field("connection_id", &report.connection_id),
            options.text_field("node_id", &report.node_id.to_string()),
            options.text_field(
                "connected_peers",
                &report
                    .connected_peers
                    .map_or_else(|| "unknown".into(), |count| count.to_string()),
            ),
        ];
        for invite in &report.invites {
            lines.push(options.text_field("issued_invite", invite));
        }
        if peers {
            for peer in &report.peers {
                lines.push(
                    options
                        .text_field("peer", &format!("{} {}", peer.display_name(), peer.node_id)),
                );
            }
        }
        for revocation in &report.revocations {
            lines.push(options.text_field("revoked", &revocation.to_string()));
        }
        return Ok(lines.join("\n"));
    }

    #[derive(Serialize)]
    struct Output<'a> {
        config: String,
        transport: &'a str,
        #[serde(flatten)]
        report: &'a StatusReport,
        #[serde(skip_serializing_if = "Option::is_none")]
        peers: Option<&'a [Peer]>,
    }
    options.render_json(&Output {
        config: path.display().to_string(),
        transport,
        report,
        peers: peers.then_some(report.peers.as_slice()),
    })
}
