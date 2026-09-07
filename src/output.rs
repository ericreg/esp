//! Shared formatting for command reports. Proxy streams and the TUI bypass this module.
use anyhow::{Result, anyhow};
use clap::{Args, ValueEnum};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub(super) enum Format {
    #[default]
    Json,
    Text,
}

#[derive(Args, Debug, Clone, Copy, Default)]
pub(super) struct Options {
    /// Output format (text is always uncolored).
    #[arg(long, value_enum, default_value = "json")]
    pub(super) format: Format,
    /// Disable JSON syntax highlighting.
    #[arg(long)]
    pub(super) no_color: bool,
}

impl Options {
    pub(super) fn print(&self, report: &Value) -> Result<()> {
        println!("{}", self.render(report)?);
        Ok(())
    }

    pub(super) fn render(&self, report: &Value) -> Result<String> {
        if self.format == Format::Json {
            return self.render_json(report);
        }
        let fields = report
            .as_object()
            .ok_or_else(|| anyhow!("command report must be an object"))?;
        Ok(fields
            .iter()
            .map(|(key, value)| format!("{key}: {}", text_value(value)))
            .collect::<Vec<_>>()
            .join("\n"))
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
