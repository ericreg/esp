//! Shared formatting for command reports. Proxy streams and the TUI bypass this module.
use anyhow::{Result, anyhow};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum Format {
    Json,
    #[default]
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatConfig {
    #[serde(default, rename = "type")]
    pub kind: Format,
    #[serde(default = "default_colorize")]
    pub colorize: bool,
}
fn default_colorize() -> bool {
    true
}
impl Default for FormatConfig {
    fn default() -> Self {
        Self {
            kind: Format::Text,
            colorize: true,
        }
    }
}

#[derive(Args, Debug, Clone, Copy, Default)]
pub(super) struct Arguments {
    /// Override format.type in the config (default: text).
    #[arg(long, value_enum)]
    pub(super) format: Option<Format>,
    /// Disable colorization, overriding the config.
    #[arg(long)]
    pub(super) no_color: bool,
    /// Enable colorization, overriding the config.
    #[arg(long, conflicts_with = "no_color")]
    pub(super) color: bool,
}

impl Arguments {
    pub(super) fn resolve(&self, configured: FormatConfig) -> Options {
        Options {
            format: self.format.unwrap_or(configured.kind),
            no_color: self.no_color || (!self.color && !configured.colorize),
        }
    }

    pub(super) fn resolve_from_config(&self) -> Result<Options> {
        let configured = read_format(&super::config_path()?)?.unwrap_or_default();
        Ok(self.resolve(configured))
    }
}

/// Read only the local output preference, including while the transport owns the config.
/// A missing config is normal for init and join.
pub(super) fn read_format(path: &Path) -> Result<Option<FormatConfig>> {
    let text = match super::read_private_config(path) {
        Ok(text) => text,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let preferences = super::networks::GlobalConfig::parse(&text)?;
    Ok(Some(preferences.format))
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Options {
    pub(super) format: Format,
    pub(super) no_color: bool,
}

impl Options {
    pub(super) fn print_invite(&self, host: &str, code: &str) -> Result<()> {
        let message =
            format!("Copy this join code and run it on the host “{host}” with the command");
        if self.format == Format::Json {
            return self.print(&serde_json::json!({
                "invite_code": code,
                "message": format!("{message}\n\nesp join INVITE_CODE"),
            }));
        }
        let command = format!("esp join {code}");
        if self.no_color {
            println!("{message}\n\n{command}");
        } else {
            println!("{message}\n\n\x1b[94m{command}\x1b[0m");
        }
        Ok(())
    }

    pub(super) fn print(&self, report: &Value) -> Result<()> {
        println!("{}", self.render(report)?);
        Ok(())
    }

    pub(super) fn render(&self, report: &Value) -> Result<String> {
        if self.format != Format::Text {
            return self.render_json(report);
        }
        let fields = report
            .as_object()
            .ok_or_else(|| anyhow!("command report must be an object"))?;
        let mut text = fields
            .iter()
            .filter(|(key, _)| key.as_str() != "next_step")
            .map(|(key, value)| self.text_field(key, &text_value(value)))
            .collect::<Vec<_>>()
            .join("\n");
        if let Some(next_step) = fields.get("next_step") {
            text.push_str("\n\n");
            text.push_str(&text_value(next_step));
        }
        Ok(text)
    }

    pub(super) fn text_field(&self, key: &str, value: &str) -> String {
        if self.no_color {
            format!("{key}: {value}")
        } else {
            format!("\x1b[1;37m{key}:\x1b[0m \x1b[94m{value}\x1b[0m")
        }
    }

    pub(super) fn render_json(&self, report: &impl Serialize) -> Result<String> {
        let json = serde_json::to_string_pretty(report)?;
        Ok(if self.no_color {
            json
        } else {
            highlight_json(&json)
        })
    }
}

fn text_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Array(values) => values.iter().map(text_value).collect::<Vec<_>>().join(","),
        _ => value.to_string(),
    }
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
