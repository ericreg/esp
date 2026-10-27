//! Persistent machine console. Login, logout and lock do not end its lifetime.
use super::{
    capture,
    codec::{self, Encoder},
    display::Size,
    input,
    protocol::*,
    service, uinput,
};
use anyhow::{Context, Result, ensure};
use std::{
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;

#[derive(Debug, clap::Args)]
pub struct Options {
    /// Root-owned network configuration for this service's exclusive ESP identity.
    #[arg(long)]
    pub config: PathBuf,
    /// The only network peer allowed to see and control the machine console.
    #[arg(long)]
    pub peer: String,
    /// auto, virtual, or a DRM display ID from `esp video displays`.
    #[arg(long, default_value = "auto")]
    pub source: String,
    /// Headless virtual display size and encoded size limit.
    #[arg(long, default_value = "1920x1080")]
    pub size: String,
    #[arg(long,default_value_t=30,value_parser=clap::value_parser!(u32).range(1..=30))]
    pub fps: u32,
    #[arg(long,default_value_t=4000,value_parser=clap::value_parser!(u32).range(500..=12000))]
    pub bitrate: u32,
    #[arg(long,default_value_t=codec::default_threads() as u32,value_parser=clap::value_parser!(u32).range(1..=64))]
    pub threads: u32,
    /// Disable keyboard and mouse control for this console grant.
    #[arg(long)]
    pub view_only: bool,
}
struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
pub async fn run(options: Options) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "system console needs root device access; run through esp-console.service"
    );
    ensure!(
        options.config.is_absolute(),
        "--config must be an absolute path"
    );
    let parent = std::fs::symlink_metadata(
        options
            .config
            .parent()
            .context("missing config directory")?,
    )?;
    ensure!(
        parent.is_dir() && parent.uid() == 0 && parent.mode() & 0o077 == 0,
        "console configuration directory must be root-owned with mode 0700"
    );
    let meta = std::fs::symlink_metadata(&options.config)?;
    ensure!(
        meta.file_type().is_file() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "console configuration must be a root-owned regular file with mode 0600"
    );
    let (w, h) = options
        .size
        .split_once('x')
        .context("--size must be WIDTHxHEIGHT")?;
    let format = Format {
        width: w.parse()?,
        height: h.parse()?,
        fps: options.fps,
        kbps: options.bitrate,
    };
    format.validate()?;
    let size = Size {
        width: format.width,
        height: format.height,
    };
    ensure!(
        options.source == "auto"
            || options.source == "virtual"
            || options.source.starts_with("drm:"),
        "--source must be auto, virtual, or a DRM display ID"
    );
    let config = crate::Config::load(&options.config)?;
    config.ensure_active()?;
    crate::ensure_completed_join(&config)?;
    config.resolve_peer(&options.peer)?;
    // Establish injection before advertising control, not after a client starts typing.
    let device = if options.view_only {
        None
    } else {
        Some(uinput::Device::new()?)
    };
    let endpoint = crate::discovery::endpoint_builder(config.secret_key()?)
        .alpns(vec![
            ALPN.to_vec(),
            crate::CONTROL_ALPN.to_vec(),
            crate::destruction::ALPN.to_vec(),
        ])
        .bind()
        .await?;
    let actor = crate::spawn_config_actor(options.config, config);
    let (_settings, settings_rx) =
        tokio::sync::watch::channel(crate::networks::TransportSettings {
            ports: vec![],
            max_connections_per_peer: 8,
        });
    let mut accept = tokio::spawn(crate::run_acceptor_dynamic(
        endpoint.clone(),
        actor.clone(),
        settings_rx,
    ));
    let (mut owner, local) = tokio::net::UnixStream::pair()?;
    let mut share_task = tokio::spawn(service::local(
        local,
        actor.clone(),
        endpoint.clone(),
        LocalRequest::Share {
            peer: options.peer,
            display: format!("console:{}", options.source),
            format,
            allow_input: !options.view_only,
        },
    ));
    let ready: Reply = tokio::time::timeout(
        SETUP,
        crate::read_cbor_frame(&mut owner, CONTROL_LIMIT, "console grant"),
    )
    .await
    .context("console registration timed out")??;
    ensure!(
        matches!(ready, Reply::Ready { .. }),
        "console registration failed: {ready:?}"
    );
    tracing::info!(source=%options.source,"system console ready; login and lock screens are shared with the configured peer");
    let stop = Arc::new(AtomicBool::new(false));
    let cancel = Cancel(stop.clone());
    let source_ready = Arc::new(AtomicBool::new(false));
    let quality = Arc::new(AtomicU32::new(0));
    let force = Arc::new(AtomicBool::new(true));
    let (events, event_rx) = std::sync::mpsc::sync_channel(128);
    let input_stop = stop.clone();
    let input_ready = source_ready.clone();
    let input_worker = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut device = device;
        while !input_stop.load(Ordering::Acquire) {
            match event_rx.recv_timeout(Duration::from_millis(50)) {
                Ok((epoch, event)) => {
                    if let Some(d) = &mut device {
                        if input_ready.load(Ordering::Acquire) {
                            d.event(epoch, event)?;
                        } else {
                            d.release()?;
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if let Some(d) = &mut device {
                if !input_ready.load(Ordering::Acquire) {
                    d.release()?;
                }
                d.watchdog()?;
            }
        }
        Ok(())
    });
    let (frames, mut frame_rx) = tokio::sync::mpsc::channel(1);
    let capture_stop = stop.clone();
    let capture_quality = quality.clone();
    let capture_force = force.clone();
    let video = actor.video.clone();
    let capture_worker = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut source = capture::Source::new(options.source, size)?;
        let mut encoder = Encoder::new(format, options.threads as usize)?;
        let mut current = format;
        let mut applied = 0;
        let mut identity = String::new();
        let mut pending = std::collections::VecDeque::new();
        let start = Instant::now();
        let mut next = Instant::now();
        let mut seq = 0;
        let mut notified = false;
        let mut log_at = Instant::now() - Duration::from_secs(10);
        while !capture_stop.load(Ordering::Acquire) {
            let raw = match source.read() {
                Ok(image) => {
                    if identity != image.identity {
                        source_ready.store(false, Ordering::Release);
                        video.reset_viewer("console switched; recapture input");
                        identity = image.identity.clone();
                        capture_force.store(true, Ordering::Release);
                    }
                    source_ready.store(true, Ordering::Release);
                    image
                }
                Err(error) => {
                    if source_ready.swap(false, Ordering::AcqRel) {
                        video.reset_viewer("console capture unavailable");
                    }
                    if log_at.elapsed() >= Duration::from_secs(5) {
                        tracing::warn!(%error,"console capture unavailable; sending a blank screen and disabling input");
                        log_at = Instant::now();
                    }
                    // Never continue showing a previous user's pixels when capture fails.
                    if identity != "unavailable" {
                        identity = "unavailable".into();
                        capture_force.store(true, Ordering::Release);
                    }
                    capture::Image {
                        size,
                        pixels: vec![0; format.width as usize * format.height as usize * 4],
                        identity: identity.clone(),
                    }
                }
            };
            if !notified {
                notify_ready()?;
                notified = true;
            }
            let desired = capture_quality.load(Ordering::Acquire);
            if desired != applied {
                current = format.reduced(desired);
                encoder = Encoder::new(current, options.threads as usize)?;
                pending.clear();
                capture_force.store(true, Ordering::Release);
                applied = desired;
            }
            if let Ok(permit) = frames.try_reserve() {
                let force = capture_force.swap(false, Ordering::AcqRel);
                if force {
                    pending.clear();
                }
                if pending.is_empty() {
                    // Fit and letterbox each source into a stable negotiated frame size.
                    let yuv = letterbox(&raw, format)?;
                    pending.extend(encoder.encode(
                        &yuv,
                        start.elapsed().as_micros() as u64,
                        force,
                    )?);
                }
                if let Some(packet) = pending.pop_front() {
                    permit.send(Frame {
                        sequence: seq,
                        timestamp_us: packet.timestamp_us,
                        key: packet.key,
                        data: packet.data.into(),
                    });
                    seq += 1;
                }
            }
            next += Duration::from_secs_f64(1. / current.fps as f64);
            // Short waits keep shutdown bounded even at 1 FPS.
            while Instant::now() < next && !capture_stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(10));
            }
            if next < Instant::now() {
                next = Instant::now();
            }
        }
        source_ready.store(false, Ordering::Release);
        Ok(())
    });
    let (mut read, mut write) = owner.split();
    let send = async {
        while let Some(frame) = frame_rx.recv().await {
            tokio::time::timeout(Duration::from_secs(1), write_frame(&mut write, &frame)).await??;
        }
        anyhow::bail!("console capture worker stopped")
    };
    let feedback = async {
        loop {
            match read.read_u8().await? {
                1 => force.store(true, Ordering::Release),
                2 => {
                    quality.fetch_add(1, Ordering::AcqRel);
                    force.store(true, Ordering::Release);
                }
                3 => {
                    let epoch = read.read_u64().await?;
                    let event = input::read(&mut read).await?;
                    events
                        .try_send((epoch, event))
                        .context("console input worker stopped or overloaded")?;
                }
                _ => anyhow::bail!("invalid console feedback"),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut input_worker = input_worker;
    let mut capture_worker = capture_worker;
    let result = tokio::select! {
        r=send=>r,r=feedback=>r,
        r=&mut input_worker=>r.context("input worker panicked").and_then(|r|r).and(Err(anyhow::anyhow!("input worker stopped"))),
        r=&mut capture_worker=>r.context("capture worker panicked").and_then(|r|r).and(Err(anyhow::anyhow!("capture worker stopped"))),
        r=&mut accept=>r.context("console acceptor panicked").and_then(|r|r).and(Err(anyhow::anyhow!("console acceptor stopped"))),
        r=&mut share_task=>r.context("console grant worker panicked").and_then(|r|r).and(Err(anyhow::anyhow!("console grant stopped"))),
        _=tokio::signal::ctrl_c()=>Ok(()),_=term.recv()=>Ok(()),
    };
    drop(cancel);
    drop(events);
    actor.video.stop();
    share_task.abort();
    accept.abort();
    endpoint.close().await;
    if !input_worker.is_finished() {
        input_worker.await??;
    }
    if !capture_worker.is_finished() {
        capture_worker.await??;
    }
    result
}
fn letterbox(image: &capture::Image, format: Format) -> Result<Vec<u8>> {
    let fit = image.size.fit(Size {
        width: format.width,
        height: format.height,
    })?;
    let small = Format {
        width: fit.width,
        height: fit.height,
        ..format
    };
    let source = codec::xrgb_to_yuv(&image.pixels, image.size.width, image.size.height, small)?;
    let mut out = vec![128; format.yuv_bytes()];
    out[..format.width as usize * format.height as usize].fill(16);
    let (mut src_offset, mut dst_offset) = (0, 0);
    for plane in 0..3 {
        let shift = usize::from(plane > 0);
        let w = (fit.width as usize) >> shift;
        let h = (fit.height as usize) >> shift;
        let dw = (format.width as usize) >> shift;
        let dh = (format.height as usize) >> shift;
        let ox = (((format.width - fit.width) / 2) & !1) as usize >> shift;
        let oy = (((format.height - fit.height) / 2) & !1) as usize >> shift;
        for y in 0..h {
            out[dst_offset + (y + oy) * dw + ox..dst_offset + (y + oy) * dw + ox + w]
                .copy_from_slice(&source[src_offset + y * w..src_offset + (y + 1) * w]);
        }
        src_offset += w * h;
        dst_offset += dw * dh;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn letterbox_preserves_aspect_and_uses_black_borders() {
        let size = Size {
            width: 64,
            height: 32,
        };
        let mut pixels = vec![0; 64 * 32 * 4];
        for p in pixels.chunks_exact_mut(4) {
            p.copy_from_slice(&[0, 0, 255, 0]);
        }
        let image = capture::Image {
            size,
            pixels,
            identity: "test".into(),
        };
        let f = Format {
            width: 64,
            height: 64,
            fps: 30,
            kbps: 4000,
        };
        let yuv = letterbox(&image, f).unwrap();
        assert_eq!(yuv.len(), 64 * 64 * 3 / 2);
        assert!(yuv[..64 * 16].iter().all(|v| *v == 16));
        assert!(yuv[64 * 16..64 * 48].iter().all(|v| *v > 70 && *v < 90));
        assert!(yuv[64 * 48..64 * 64].iter().all(|v| *v == 16));
    }
    #[test]
    #[ignore = "requires isolated VM with esp_console_test=1; never injects host input"]
    fn linux_console_devices_in_vm() {
        use std::{
            fs::OpenOptions,
            io::{Read, Write},
            os::{
                fd::{AsFd, AsRawFd},
                unix::fs::OpenOptionsExt,
            },
        };
        assert!(
            std::fs::read_to_string("/proc/cmdline")
                .unwrap()
                .split_whitespace()
                .any(|s| s == "esp_console_test=1"),
            "VM-only test"
        );
        let size = Size {
            width: 320,
            height: 240,
        };
        let mut source = capture::Source::new("virtual".into(), size).unwrap();
        let mut image = None;
        for _ in 0..100 {
            match source.read() {
                Ok(frame) => {
                    image = Some(frame);
                    break;
                }
                Err(e) => {
                    eprintln!("waiting: {e:#}");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        let before = image.expect("framebuffer console did not activate");
        let vt = capture::terminal().unwrap();
        assert!(!vt.graphics);
        let mut tty = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(format!("/dev/tty{}", vt.number))
            .unwrap();
        tty.write_all(b"\x1b[2J\x1b[HESP CONSOLE LOGIN TEST\r\nlogin: ")
            .unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let after = source.read().unwrap();
        assert_ne!(before.pixels, after.pixels);
        assert!(after.pixels.iter().any(|b| *b != 0));
        let mut device = uinput::Device::new().unwrap();
        std::thread::sleep(Duration::from_millis(150));
        let event_path = |wanted: &str| {
            let entry = std::fs::read_dir("/sys/class/input")
                .unwrap()
                .filter_map(|e| e.ok())
                .find(|e| {
                    e.file_name().to_string_lossy().starts_with("event")
                        && std::fs::read_to_string(e.path().join("device/name"))
                            .is_ok_and(|name| name.trim() == wanted)
                })
                .expect("uinput evdev device");
            std::path::Path::new("/dev/input").join(entry.file_name())
        };
        let mouse_path = event_path("ESP remote console mouse");
        let mut evdev = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&mouse_path)
            .unwrap();
        // EVIOCGKEY flushes queued key events for its evdev client. Use separate
        // open descriptions so state queries do not consume the mouse event test.
        let mouse_state = std::fs::File::open(&mouse_path).unwrap();
        let keyboard_state =
            std::fs::File::open(event_path("ESP remote console keyboard")).unwrap();
        let key_down = |code: usize| {
            let mut keys = [0u8; 96];
            assert_eq!(
                unsafe {
                    libc::ioctl(
                        if code >= 0x110 {
                            mouse_state.as_raw_fd()
                        } else {
                            keyboard_state.as_raw_fd()
                        },
                        0x80604518,
                        keys.as_mut_ptr(),
                    )
                },
                96
            ); // EVIOCGKEY(96)
            keys[code / 8] & (1 << (code % 8)) != 0
        };
        device.event(1, input::Event::Capture).unwrap();
        for code in [30, 28] {
            device
                .event(1, input::Event::Key { code, down: true })
                .unwrap();
            device
                .event(1, input::Event::Key { code, down: false })
                .unwrap();
        }
        let mut typed = [0u8; 128];
        let mut count = 0;
        for _ in 0..50 {
            if let Ok(n) = tty.read(&mut typed) {
                count = n;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(&typed[..count], b"a\n");
        device
            .event(
                1,
                input::Event::Key {
                    code: 29,
                    down: true,
                },
            )
            .unwrap();
        assert!(key_down(29));
        // A new viewer releases the old viewer's keys. Old events cannot release
        // or press keys in the new capture generation.
        device.event(2, input::Event::Capture).unwrap();
        assert!(!key_down(29));
        device
            .event(
                2,
                input::Event::Button {
                    button: 0,
                    down: true,
                },
            )
            .unwrap();
        device.event(1, input::Event::Release).unwrap();
        assert!(key_down(0x110));
        device
            .event(2, input::Event::Motion { x: 17, y: -9 })
            .unwrap();
        device
            .event(2, input::Event::Scroll { x: -1, y: 2 })
            .unwrap();
        std::thread::sleep(Duration::from_millis(2100));
        device.watchdog().unwrap();
        assert!(!key_down(0x110));
        let expected = [(2, 0, 17), (2, 1, -9), (2, 6, -1), (2, 8, 2), (1, 0x110, 0)];
        let mut events = Vec::new();
        let mut bytes = [0u8; 4096];
        for _ in 0..20 {
            match evdev.read(&mut bytes) {
                Ok(count) => events.extend(
                    bytes[..count]
                        .chunks_exact(std::mem::size_of::<libc::input_event>())
                        .map(|bytes| {
                            // input_event is a plain C structure; this buffer need not be aligned.
                            let e = unsafe {
                                std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::input_event>())
                            };
                            (e.type_, e.code, e.value)
                        }),
                ),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("evdev read: {e}"),
            }
            if expected.iter().all(|e| events.contains(e)) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        for expected in expected {
            assert!(
                events.contains(&expected),
                "missing evdev event {expected:?}; got {events:?}"
            );
        }
        assert!(
            !events
                .iter()
                .any(|(kind, _, value)| *kind == 1 && *value == 2),
            "mouse buttons must not autorepeat"
        );
        assert!(
            !events.iter().any(|e| *e == (0, 3, 0)),
            "evdev queue must not overflow"
        );
        // Keep the same VT while a synthetic graphical client takes over the display.
        struct Card(std::fs::File);
        impl AsFd for Card {
            fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
                self.0.as_fd()
            }
        }
        impl video_drm::Device for Card {}
        impl video_drm::control::Device for Card {}
        use video_drm::{
            Device as _,
            control::{Device as _, ModeTypeFlags},
        };
        let (outputs, _) = super::super::driver::enumerate().unwrap();
        let output = outputs.iter().find(|o| o.virtual_output).unwrap();
        let card_name = output.connector.split('-').next().unwrap();
        let card = Card(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/dev/dri/{card_name}"))
                .unwrap(),
        );
        card.acquire_master_lock().unwrap();
        let resources = card.resource_handles().unwrap();
        let connector = resources.connectors()[0];
        let info = card.get_connector(connector, true).unwrap();
        let mode = *info
            .modes()
            .iter()
            .find(|m| m.mode_type().contains(ModeTypeFlags::PREFERRED))
            .unwrap();
        let mut buffer = card
            .create_dumb_buffer((320, 240), video_drm::buffer::DrmFourcc::Xrgb8888, 32)
            .unwrap();
        {
            let mut map = card.map_dumb_buffer(&mut buffer).unwrap();
            for pixel in map.chunks_exact_mut(4) {
                pixel.copy_from_slice(&[0x33, 0x22, 0x11, 0]);
            }
        }
        let fb = card.add_framebuffer(&buffer, 24, 32).unwrap();
        card.set_crtc(
            resources.crtcs()[0],
            Some(fb),
            (0, 0),
            &[connector],
            Some(mode),
        )
        .unwrap();
        assert_eq!(unsafe { libc::ioctl(tty.as_raw_fd(), 0x4b3a, 1) }, 0); // KDSETMODE graphics
        let mut existing = capture::Source::new(output.id.clone(), size).unwrap();
        let graphical = existing.read().unwrap();
        assert_eq!(graphical.size, size);
        assert!(
            graphical
                .pixels
                .chunks_exact(4)
                .all(|p| p[..3] == [0x33, 0x22, 0x11])
        );
        drop(existing);
        assert_eq!(unsafe { libc::ioctl(tty.as_raw_fd(), 0x4b3a, 0) }, 0);
        card.release_master_lock().unwrap();
        drop(card);
        tty.write_all(b"\r\nRETURNED TO TEXT CONSOLE\r\n").unwrap();
        assert!(source.read().unwrap().identity.contains(":text:"));
        println!(
            "ESP_CONSOLE_VM_PASSED: framebuffer text, keyboard/mouse, stale input rejection, watchdog, graphical scanout, text return"
        );
    }
}

fn notify_ready() -> Result<()> {
    use std::os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixDatagram},
    };
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_bytes();
    let address = if bytes.first() == Some(&b'@') {
        SocketAddr::from_abstract_name(&bytes[1..])?
    } else {
        SocketAddr::from_pathname(path)?
    };
    UnixDatagram::unbound()?.send_to_addr(b"READY=1\nSTATUS=Console endpoint ready", &address)?;
    Ok(())
}
