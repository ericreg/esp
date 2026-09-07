use super::{Peer, StatusReport};
use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;
use std::{fmt::Write as _, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum Format {
    Json,
    Text,
}

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
    let json = serde_json::to_string_pretty(&Output {
        config: path.display().to_string(),
        transport,
        report,
        peers: peers.then_some(report.peers.as_slice()),
    })?;
    Ok(if no_color {
        json
    } else {
        highlight_json(&json)
    })
}

/// Color complete tokens in serialized JSON, preserving its escaping and whitespace.
fn highlight_json(json: &str) -> String {
    let bytes = json.as_bytes();
    let mut output = String::with_capacity(json.len() * 2);
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        let color = match bytes[index] {
            b'"' => {
                index += 1;
                while index < bytes.len() {
                    match bytes[index] {
                        b'\\' => index += 2,
                        b'"' => {
                            index += 1;
                            break;
                        }
                        _ => index += 1,
                    }
                }
                if json[index..].trim_start().starts_with(':') {
                    "\x1b[1;36m"
                } else {
                    "\x1b[32m"
                }
            }
            b'-' | b'0'..=b'9' | b't' | b'f' | b'n' => {
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || b".+-".contains(&bytes[index]))
                {
                    index += 1;
                }
                "\x1b[33m"
            }
            _ => {
                // Outside strings, JSON contains only ASCII punctuation and whitespace.
                output.push(bytes[index] as char);
                index += 1;
                continue;
            }
        };
        output.push_str(color);
        output.push_str(&json[start..index]);
        output.push_str("\x1b[0m");
    }
    output
}
