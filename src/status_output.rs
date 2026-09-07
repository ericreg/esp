use super::{
    Peer, StatusReport,
    output::{Format, Options},
};
use anyhow::Result;
use serde::Serialize;
use std::{fmt::Write as _, path::Path};

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
    if format == Format::Text {
        let mut text = format!(
            "esp_config: {}\ntransport: {}\nnetwork: {}\nmax_peers: {}\nname: {}\nconnection_id: {}\nnode_id: {}\nconnected_peers: {}",
            path.display(),
            transport,
            report.network_id,
            report.max_peers,
            report.name,
            report.connection_id,
            report.node_id,
            report
                .connected_peers
                .map_or_else(|| "unknown".into(), |count| count.to_string()),
        );
        for invite in &report.invites {
            write!(text, "\nissued_invite: {invite}")?;
        }
        if peers {
            for peer in &report.peers {
                write!(text, "\npeer: {} {}", peer.display_name(), peer.node_id)?;
            }
        }
        for revocation in &report.revocations {
            write!(text, "\nrevoked: {revocation}")?;
        }
        return Ok(text);
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
    Options { format, no_color }.render_json(&Output {
        config: path.display().to_string(),
        transport,
        report,
        peers: peers.then_some(report.peers.as_slice()),
    })
}
