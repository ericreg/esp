//! View-only video sharing. Device, media, and GUI dependencies are optional.
#[cfg(feature = "video-codec")]
mod codec;
mod display;
#[cfg(target_os = "linux")]
mod driver;
pub(super) mod protocol;
pub(super) mod service;
#[cfg(all(feature = "video-codec", target_os = "linux"))]
mod share;
#[cfg(feature = "video-viewer")]
mod viewer;

use anyhow::{Result, bail};
use clap::Subcommand;
use protocol::{LocalRequest, Reply};

#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// List Linux DRM outputs and the virtual driver status without changing displays.
    Displays {
        #[command(flatten)]
        output: crate::output::Arguments,
    },
    /// Create a virtual monitor and share its frames with one network peer.
    #[cfg(all(feature = "video-codec", target_os = "linux"))]
    Share {
        network: String,
        #[arg(long)]
        display: String,
        #[arg(long)]
        peer: String,
        #[arg(long,default_value_t=30,value_parser=clap::value_parser!(u32).range(1..=30))]
        fps: u32,
        /// Maximum encoded size, WIDTHxHEIGHT. Does not change the source mode.
        #[arg(long, default_value = "1920x1080")]
        max_size: String,
        /// Average target bitrate in kbit/s.
        #[arg(long,default_value_t=4000,value_parser=clap::value_parser!(u32).range(500..=12000))]
        bitrate: u32,
        /// Encoder worker limit (default: available CPUs, capped at six).
        #[arg(long, default_value_t=codec::default_threads() as u32, value_parser=clap::value_parser!(u32).range(1..=64))]
        threads: u32,
    },
    /// Open a resizable view-only window (F11 toggles fullscreen).
    #[cfg(feature = "video-viewer")]
    View { network: String, host: String },
    /// Report the local share and its viewer/transport state.
    Status {
        network: String,
        #[command(flatten)]
        output: crate::output::Arguments,
    },
    /// Stop the local share and disconnect its virtual monitor.
    Stop { network: String },
}
pub(super) async fn execute(command: Command) -> Result<()> {
    match command {
        Command::Displays { output } => {
            let output = output.resolve_from_config()?;
            #[cfg(target_os = "linux")]
            {
                driver::print(output)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = output;
                bail!("virtual-display hosting currently supports Linux");
            }
        }
        #[cfg(all(feature = "video-codec", target_os = "linux"))]
        Command::Share {
            network,
            display,
            peer,
            fps,
            max_size,
            bitrate,
            threads,
        } => {
            share::run(
                network,
                display,
                peer,
                fps,
                max_size,
                bitrate,
                threads as usize,
            )
            .await
        }
        #[cfg(feature = "video-viewer")]
        Command::View { network, host } => viewer::run(network, host).await,
        Command::Status { network, output } => {
            let (_, reply) = service::connect_local(&network, LocalRequest::Status).await?;
            if let Reply::Report(json) = reply {
                output
                    .resolve_from_config()?
                    .print(&serde_json::from_str(&json)?)
            } else {
                bail!("unexpected video status response")
            }
        }
        Command::Stop { network } => {
            service::connect_local(&network, LocalRequest::Stop).await?;
            println!("Video sharing stopped.");
            Ok(())
        }
    }
}
