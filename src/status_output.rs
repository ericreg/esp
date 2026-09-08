//! Presentation of detailed and aggregate version 3 status reports.
use super::output::{Format, Options};
use anyhow::Result;
use serde_json::Value;

pub(super) fn render(report: &Value, options: Options) -> Result<String> {
    if options.format == Format::Json {
        return options.render_json(report);
    }
    fn network(value: &Value, options: Options) -> Result<String> {
        let mut value = value.clone();
        if value.get("connected_peers").is_some_and(Value::is_null) {
            value["connected_peers"] = Value::String("unknown".into());
        }
        options.render(&value)
    }
    if let Some(networks) = report.get("networks").and_then(Value::as_array) {
        let mut blocks =
            vec![options.text_field("daemon", report["daemon"].as_str().unwrap_or("unknown"))];
        for item in networks {
            blocks.push(network(item, options)?);
        }
        Ok(blocks.join("\n\n"))
    } else {
        network(report, options)
    }
}
