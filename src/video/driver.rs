//! Read-only DRM enumeration and exclusive ESP driver frame acquisition.
use super::display::Size;
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};
use video_drm::control::{Device as _, connector};

struct Card(File);
impl AsFd for Card {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl video_drm::Device for Card {}
impl video_drm::control::Device for Card {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Output {
    pub id: String,
    pub connector: String,
    pub device: String,
    pub connected: bool,
    pub active: bool,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub virtual_output: bool,
    pub refresh_hz: Option<u32>,
    pub mode_signature: Option<String>,
}
pub fn discover() -> Result<serde_json::Value> {
    let (outputs, errors) = enumerate()?;
    Ok(
        serde_json::json!({"backend":"linux_drm", "driver_loaded":Path::new("/sys/module/esp_video").exists(),
        "capture_device":"/dev/esp-video", "outputs":outputs, "errors":errors,
        "next_step":"For foreground sharing, load the ESP module and configure mirroring. For login/text consoles or headless output, see esp video serve --help and CONSOLE_SERVICE.md."}),
    )
}
pub fn print(output: crate::output::Options) -> Result<()> {
    let report = discover()?;
    if output.format == crate::output::Format::Json {
        return output.print(&report);
    }
    println!(
        "{}",
        output.text_field(
            "Driver",
            if report["driver_loaded"] == true {
                "loaded"
            } else {
                "not loaded"
            }
        )
    );
    for item in report["outputs"].as_array().unwrap() {
        println!();
        println!(
            "{}",
            output.text_field("Output", item["connector"].as_str().unwrap())
        );
        println!(
            "{}",
            output.text_field("Display ID", item["id"].as_str().unwrap())
        );
        let state = if item["active"] == true {
            format!("active · {}×{}", item["width"], item["height"])
        } else if item["connected"] == true {
            "connected, inactive".into()
        } else {
            "disconnected".into()
        };
        println!("{}", output.text_field("State", &state));
    }
    for error in report["errors"].as_array().unwrap() {
        eprintln!("{}", error.as_str().unwrap());
    }
    println!("\n{}", report["next_step"].as_str().unwrap());
    Ok(())
}
pub fn enumerate() -> Result<(Vec<Output>, Vec<String>)> {
    let mut outputs = Vec::new();
    let mut errors = Vec::new();
    for entry in fs::read_dir("/sys/class/drm").context("Linux DRM is unavailable")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("card") || !name[4..].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let result = read_card(&name);
        match result {
            Ok(mut found) => outputs.append(&mut found),
            Err(e) => errors.push(format!("{name}: {e:#}")),
        }
    }
    outputs.sort_by(|a, b| a.connector.cmp(&b.connector));
    Ok((outputs, errors))
}
fn read_card(name: &str) -> Result<Vec<Output>> {
    let path = format!("/dev/dri/{name}");
    let card = Card(File::open(&path).with_context(|| format!("cannot open {path}"))?);
    let device = fs::canonicalize(format!("/sys/class/drm/{name}/device"))?
        .to_string_lossy()
        .into_owned();
    let mut found = Vec::new();
    for handle in card.resource_handles()?.connectors() {
        // Do not force a connector reprobe or change modes while enumerating.
        let conn = card.get_connector(*handle, false)?;
        if conn.interface() == connector::Interface::Writeback {
            continue;
        }
        let connector = format!("{name}-{conn}");
        let edid = fs::read(format!("/sys/class/drm/{connector}/edid")).unwrap_or_default();
        let mut hash = Sha256::new();
        hash.update(device.as_bytes());
        hash.update([0]);
        hash.update(conn.to_string().as_bytes());
        hash.update([0]);
        hash.update(&edid);
        let id = format!(
            "drm:{}",
            hash.finalize()
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        );
        let mode = conn
            .current_encoder()
            .map(|e| card.get_encoder(e))
            .transpose()?
            .and_then(|e| e.crtc())
            .map(|c| card.get_crtc(c))
            .transpose()?
            .and_then(|c| c.mode());
        found.push(Output {
            id,
            connector,
            device: device.clone(),
            connected: conn.state() == connector::State::Connected,
            active: mode.is_some(),
            width: mode.map(|m| u32::from(m.size().0)),
            height: mode.map(|m| u32::from(m.size().1)),
            refresh_hz: mode.map(|m| m.vrefresh()),
            mode_signature: mode.map(|m| format!("{m:?}")),
            virtual_output: conn.interface() == connector::Interface::Virtual,
        });
    }
    Ok(found)
}
pub fn select(id: &str) -> Result<Output> {
    let (outputs, errors) = enumerate()?;
    let output = outputs.into_iter().find(|o| o.id == id).with_context(|| {
        format!(
            "display ID is unavailable; run esp video displays ({})",
            errors.join(", ")
        )
    })?;
    ensure!(
        output.connected && output.active && !output.virtual_output,
        "select an active physical display"
    );
    Size {
        width: output.width.unwrap(),
        height: output.height.unwrap(),
    }
    .validate_source()?;
    ensure!(
        output.width.unwrap() % 2 == 0 && output.height.unwrap() % 2 == 0,
        "initial virtual driver requires even source dimensions"
    );
    Ok(output)
}
pub fn verify_virtual(size: Size) -> Result<()> {
    let (outputs, _) = enumerate()?;
    let owned: Vec<_> = outputs
        .iter()
        .filter(|o| o.virtual_output && o.device.ends_with("/esp-video"))
        .collect();
    ensure!(
        owned.len() == 1
            && owned[0].connected
            && owned[0].active
            && owned[0].width == Some(size.width)
            && owned[0].height == Some(size.height),
        "ESP virtual output is inactive or its mode changed; configure mirroring again"
    );
    Ok(())
}
pub struct Capture {
    file: File,
    buffer: Vec<u8>,
    pub size: Size,
}
impl Capture {
    pub fn connect(source: &Output) -> Result<Self> {
        let size = Size {
            width: source.width.context("source has no active width")?,
            height: source.height.context("source has no active height")?,
        }
        .validate_source()?;
        Self::connect_size(size)
    }
    pub fn connect_size(size: Size) -> Result<Self> {
        size.validate_source()?;
        let file=OpenOptions::new().read(true).write(true)
            .custom_flags(libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK)
            .open("/dev/esp-video").context("cannot open /dev/esp-video; build/load the ESP module and grant your user access (see drivers/esp_video/README.md)")?;
        use std::os::unix::fs::FileTypeExt;
        ensure!(
            file.metadata()?.file_type().is_char_device(),
            "/dev/esp-video is not a character device"
        );
        let mode = [size.width, size.height];
        // _IOW('E',1,struct esp_video_mode), exactly matching esp_video.h.
        let result = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                0x4008_4501 as libc::c_ulong,
                mode.as_ptr(),
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error())
                .context("connecting ESP virtual monitor failed");
        }
        Ok(Self {
            file,
            buffer: vec![0; 24 + size.width as usize * size.height as usize * 4],
            size,
        })
    }
    /// Nonblocking latest frame; the kernel keeps only one replaceable snapshot.
    pub fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let len = match self.file.read(&mut self.buffer) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        ensure!(len == self.buffer.len(), "truncated driver frame");
        let word = |offset| u32::from_ne_bytes(self.buffer[offset..offset + 4].try_into().unwrap());
        ensure!(
            word(0) == 1
                && word(4) == self.size.width
                && word(8) == self.size.height
                && word(12) as usize == len - 24,
            "invalid driver frame ABI or changed mode"
        );
        Ok(Some(self.buffer[24..].to_vec()))
    }
}
use std::os::unix::fs::OpenOptionsExt;

pub struct Session {
    connection: zbus::Connection,
    path: zbus::zvariant::OwnedObjectPath,
}
impl Session {
    pub async fn graphical() -> Result<Self> {
        let connection = zbus::Connection::system()
            .await
            .context("cannot monitor logind session lifecycle")?;
        let manager = zbus::Proxy::new(
            &connection,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        let sessions: Vec<(String, u32, String, String, zbus::zvariant::OwnedObjectPath)> =
            manager.call("ListSessions", &()).await?;
        let uid = unsafe { libc::geteuid() };
        let mut selected = None;
        for (_, user, _, _, path) in sessions {
            if user != uid {
                continue;
            }
            let proxy = zbus::Proxy::new(
                &connection,
                "org.freedesktop.login1",
                path.as_str(),
                "org.freedesktop.login1.Session",
            )
            .await?;
            let kind: String = proxy.get_property("Type").await?;
            if !matches!(kind.as_str(), "wayland" | "x11") {
                continue;
            }
            if proxy.get_property::<bool>("Active").await? {
                ensure!(
                    selected.is_none(),
                    "multiple active graphical sessions; cannot select a lock monitor safely"
                );
                selected = Some(path);
            }
        }
        let session = Self {
            connection,
            path: selected.context("no active graphical logind session for this user")?,
        };
        session.check().await?;
        Ok(session)
    }
    pub async fn check(&self) -> Result<()> {
        let proxy = zbus::Proxy::new(
            &self.connection,
            "org.freedesktop.login1",
            self.path.as_str(),
            "org.freedesktop.login1.Session",
        )
        .await?;
        let active: bool = proxy.get_property("Active").await?;
        let locked: bool = proxy.get_property("LockedHint").await?;
        let state: String = proxy.get_property("State").await?;
        if !active || locked || state == "closing" {
            bail!("graphical session locked or ended; start a new local share to resume");
        }
        Ok(())
    }
}
