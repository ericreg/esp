//! Local display discovery for the first video-sharing milestone.

mod display;
#[cfg(target_os = "linux")]
mod mutter;

use anyhow::{Context, Result};
use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// List local source displays and virtual-mirror prerequisites without changing the layout.
    Displays {
        #[command(flatten)]
        output: crate::output::Arguments,
    },
}

pub(super) async fn execute(command: Command) -> Result<()> {
    match command {
        Command::Displays { output } => {
            let output = output.resolve_from_config()?;
            #[cfg(target_os = "linux")]
            {
                let report =
                    tokio::time::timeout(std::time::Duration::from_secs(5), mutter::discover())
                        .await
                        .context("timed out inspecting the graphical session")??;
                report.print(output)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = output;
                anyhow::bail!("local video display discovery currently supports Linux GNOME/Mutter")
            }
        }
    }
}
