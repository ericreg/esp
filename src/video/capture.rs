//! System-console capture. Never changes physical output modes or starts a new login.
use super::{display::Size, driver};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::fd::{AsFd, AsRawFd},
    os::unix::fs::FileExt,
};
use video_drm::{
    Device as _,
    control::{Device as _, crtc, framebuffer},
};

pub struct Image {
    pub size: Size,
    pub pixels: Vec<u8>,
    pub identity: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terminal {
    pub number: u16,
    pub graphics: bool,
}
pub fn terminal() -> Result<Terminal> {
    let tty = File::open("/dev/tty0").context("open active Linux virtual terminal /dev/tty0")?;
    let mut state = [0u16; 3];
    // SAFETY: VT_GETSTATE writes struct vt_stat (three unsigned shorts).
    ensure!(
        unsafe { libc::ioctl(tty.as_raw_fd(), 0x5603, state.as_mut_ptr()) } >= 0,
        "VT_GETSTATE: {}",
        std::io::Error::last_os_error()
    );
    ensure!((1..=63).contains(&state[0]), "invalid active VT");
    let console = File::open(format!("/dev/tty{}", state[0]))?;
    let mut mode = 0i32;
    ensure!(
        unsafe { libc::ioctl(console.as_raw_fd(), 0x4b3b, &mut mode) } >= 0,
        "KDGETMODE: {}",
        std::io::Error::last_os_error()
    );
    ensure!(mode == 0 || mode == 1, "unsupported console mode");
    Ok(Terminal {
        number: state[0],
        graphics: mode == 1,
    })
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Bitfield {
    offset: u32,
    length: u32,
    msb_right: u32,
}
#[repr(C)]
#[derive(Default)]
struct Variable {
    x: u32,
    y: u32,
    vx: u32,
    vy: u32,
    ox: u32,
    oy: u32,
    bpp: u32,
    grayscale: u32,
    red: Bitfield,
    green: Bitfield,
    blue: Bitfield,
    alpha: Bitfield,
    nonstd: u32,
    activate: u32,
    height: u32,
    width: u32,
    accel: u32,
    pixclock: u32,
    left: u32,
    right: u32,
    upper: u32,
    lower: u32,
    hsync: u32,
    vsync: u32,
    sync: u32,
    vmode: u32,
    rotate: u32,
    colorspace: u32,
    reserved: [u32; 4],
}
#[repr(C)]
#[derive(Default)]
struct Fixed {
    id: [u8; 16],
    smem_start: libc::c_ulong,
    smem_len: u32,
    kind: u32,
    kind_aux: u32,
    visual: u32,
    xpan: u16,
    ypan: u16,
    ywrap: u16,
    line_length: u32,
    mmio_start: libc::c_ulong,
    mmio_len: u32,
    accel: u32,
    capabilities: u16,
    reserved: [u16; 2],
}
fn fb_map(console: u16, new: Option<u32>) -> Result<u32> {
    let fb = OpenOptions::new().read(true).write(true).open("/dev/fb0")?;
    let mut map = [u32::from(console), new.unwrap_or(0)];
    let cmd = if new.is_some() { 0x4610 } else { 0x460f };
    ensure!(
        unsafe { libc::ioctl(fb.as_raw_fd(), cmd, map.as_mut_ptr()) } >= 0,
        "framebuffer console mapping: {}",
        std::io::Error::last_os_error()
    );
    Ok(map[1])
}
fn framebuffer(index: u32) -> Result<Image> {
    let file = File::open(format!("/dev/fb{index}"))?;
    let mut v = Variable::default();
    let mut f = Fixed::default();
    ensure!(
        unsafe { libc::ioctl(file.as_raw_fd(), 0x4600, &mut v) } >= 0,
        "FBIOGET_VSCREENINFO failed"
    );
    ensure!(
        unsafe { libc::ioctl(file.as_raw_fd(), 0x4602, &mut f) } >= 0,
        "FBIOGET_FSCREENINFO failed"
    );
    let size = Size {
        width: v.x,
        height: v.y,
    }
    .validate_source()?;
    ensure!(
        [16, 24, 32].contains(&v.bpp)
            && v.grayscale == 0
            && v.nonstd == 0
            && f.kind == 0
            && f.visual == 2
            && v.rotate == 0,
        "unsupported framebuffer layout (requires packed truecolor RGB)"
    );
    let bytes = (v.bpp / 8) as usize;
    ensure!(
        v.ox.checked_add(v.x).is_some_and(|x| x <= v.vx)
            && v.oy.checked_add(v.y).is_some_and(|y| y <= v.vy),
        "framebuffer viewport out of bounds"
    );
    let pitch = f.line_length as usize;
    ensure!(
        (v.ox as usize + v.x as usize) * bytes <= pitch
            && (v.oy as u64 + v.y as u64) * pitch as u64 <= f.smem_len as u64,
        "framebuffer memory bounds"
    );
    let mut pixels = vec![0; size.width as usize * size.height as usize * 4];
    let mut row = vec![0; v.x as usize * bytes];
    for y in 0..v.y as usize {
        file.read_exact_at(
            &mut row,
            ((y + v.oy as usize) * pitch + v.ox as usize * bytes) as u64,
        )?;
        for x in 0..v.x as usize {
            let mut raw = [0; 4];
            raw[..bytes].copy_from_slice(&row[x * bytes..(x + 1) * bytes]);
            let value = u32::from_le_bytes(raw);
            let at = (y * v.x as usize + x) * 4;
            for (i, field) in [v.blue, v.green, v.red].into_iter().enumerate() {
                ensure!(
                    field.length > 0
                        && field.length <= 16
                        && field.offset + field.length <= v.bpp
                        && field.msb_right == 0,
                    "unsupported framebuffer channels"
                );
                let max = (1u32 << field.length) - 1;
                pixels[at + i] = (((value >> field.offset) & max) * 255 / max) as u8;
            }
        }
    }
    Ok(Image {
        size,
        pixels,
        identity: format!("fb{index}"),
    })
}

pub struct Source {
    selected: String,
    virtual_display: Option<driver::Capture>,
    size: Size,
    restored: BTreeMap<u16, u32>,
    last_virtual: Option<Vec<u8>>,
    last_vt: Option<Terminal>,
    gpu: BTreeMap<String, super::gpu::Reader>,
}
impl Source {
    pub fn new(selected: String, size: Size) -> Result<Self> {
        size.validate_source()?;
        Ok(Self {
            selected,
            virtual_display: None,
            size,
            restored: BTreeMap::new(),
            last_virtual: None,
            last_vt: None,
            gpu: BTreeMap::new(),
        })
    }
    fn restore(&mut self) {
        for (vt, index) in std::mem::take(&mut self.restored) {
            if let Err(e) = fb_map(vt, Some(index)) {
                tracing::error!(%e,vt,"failed to restore console framebuffer");
            }
        }
    }
    pub fn read(&mut self) -> Result<Image> {
        let vt = terminal()?;
        if self.last_vt != Some(vt) {
            self.last_virtual = None;
            self.last_vt = Some(vt);
        }
        let (outputs, errors) = driver::enumerate()?;
        let physical: Vec<_> = outputs
            .iter()
            .filter(|o| !o.virtual_output && o.connected)
            .collect();
        let headless = physical.is_empty();
        let use_virtual = self.selected == "virtual" || (self.selected == "auto" && headless);
        if use_virtual {
            if self.virtual_display.is_none() {
                self.virtual_display = Some(driver::Capture::connect_size(self.size)?);
                // Let fbdev/compositor process the connector hotplug; caller retries.
                bail!("virtual monitor connected; waiting for console/display activation");
            }
            if !vt.graphics {
                let fb=std::fs::read_dir("/sys/class/graphics")?.filter_map(|e|e.ok()).find_map(|entry|{
                    let name=entry.file_name().to_string_lossy().into_owned();
                    let index=name.strip_prefix("fb")?.parse::<u32>().ok()?;
                    let device=std::fs::canonicalize(entry.path().join("device")).ok()?;
                    device.to_string_lossy().contains("esp-video").then_some(index)
                }).context("ESP framebuffer console is unavailable; load the updated module with DRM fbdev emulation enabled")?;
                let previous = fb_map(vt.number, None)?;
                if previous != fb {
                    self.restored.entry(vt.number).or_insert(previous);
                    fb_map(vt.number, Some(fb))?;
                }
                let mut image = framebuffer(fb)?;
                image.identity = format!("vt{}:text:{}", vt.number, image.identity);
                return Ok(image);
            }
            driver::verify_virtual(self.size)
                .context("graphical session has not enabled ESP's virtual monitor")?;
            let capture = self.virtual_display.as_mut().unwrap();
            if let Some(pixels) = capture.read()? {
                self.last_virtual = Some(pixels);
            }
            let pixels = self
                .last_virtual
                .clone()
                .context("waiting for first virtual graphical frame")?;
            return Ok(Image {
                size: self.size,
                pixels,
                identity: format!("vt{}:graphics:virtual", vt.number),
            });
        }
        self.restore();
        if !vt.graphics {
            let index = fb_map(vt.number, None)?;
            let mut image = framebuffer(index)?;
            image.identity = format!("vt{}:text:{}", vt.number, image.identity);
            return Ok(image);
        }
        let output = if self.selected == "auto" {
            let active: Vec<_> = physical.into_iter().filter(|o| o.active).collect();
            ensure!(
                active.len() == 1,
                "select a DRM display ID when zero or multiple physical displays are active ({})",
                errors.join("; ")
            );
            active[0]
        } else {
            outputs
                .iter()
                .find(|o| o.id == self.selected && o.active)
                .context("selected output is not active")?
        };
        let mut image = scanout(output, &mut self.gpu)?;
        image.identity = format!("vt{}:graphics:{}", vt.number, output.id);
        Ok(image)
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        self.restore();
    }
}

struct Card(File);
impl AsFd for Card {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl video_drm::Device for Card {}
impl video_drm::control::Device for Card {}
struct Buffers<'a> {
    card: &'a Card,
    fb: framebuffer::PlanarInfo,
}
impl Drop for Buffers<'_> {
    fn drop(&mut self) {
        let mut closed = std::collections::HashSet::new();
        for handle in self.fb.buffers().into_iter().flatten() {
            if closed.insert(handle) {
                let _ = self.card.close_buffer(handle);
            }
        }
    }
}
struct Mapping {
    ptr: *mut libc::c_void,
    len: usize,
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}
fn plane_pixels(
    card: &Card,
    handle: framebuffer::Handle,
    gpu: &mut Option<&super::gpu::Reader>,
) -> Result<(Size, Vec<u8>, bool)> {
    let fb = card.get_planar_framebuffer(handle)?;
    let owned = Buffers { card, fb };
    let size = Size {
        width: fb.size().0,
        height: fb.size().1,
    }
    .validate_source()?;
    let format = fb.pixel_format();
    let alpha = matches!(
        format,
        video_drm::buffer::DrmFourcc::Argb8888 | video_drm::buffer::DrmFourcc::Abgr8888
    );
    ensure!(
        matches!(
            format,
            video_drm::buffer::DrmFourcc::Xrgb8888
                | video_drm::buffer::DrmFourcc::Argb8888
                | video_drm::buffer::DrmFourcc::Xbgr8888
                | video_drm::buffer::DrmFourcc::Abgr8888
        ),
        "unsupported scanout pixel format {format:?}"
    );
    if let Some(reader) = gpu {
        let mut planes = vec![];
        for (i, handle) in fb.buffers().into_iter().enumerate() {
            if let Some(handle) = handle {
                planes.push((
                    card.buffer_to_prime_fd(handle, libc::O_CLOEXEC as u32)?,
                    fb.offsets()[i],
                    fb.pitches()[i],
                ));
            }
        }
        let pixels = reader.read(
            size.width,
            size.height,
            format as u32,
            &planes,
            fb.modifier().map(u64::from),
        )?;
        return Ok((size, pixels, alpha));
    }
    ensure!(
        fb.modifier().is_none_or(|m| u64::from(m) == 0),
        "nonlinear GPU scanout requires EGL/GBM readback"
    );
    let buffer = fb.buffers()[0].context("DRM framebuffer export requires CAP_SYS_ADMIN")?;
    ensure!(
        fb.buffers()[1..].iter().all(Option::is_none),
        "unsupported multi-plane framebuffer"
    );
    let fd = card.buffer_to_prime_fd(buffer, libc::O_CLOEXEC as u32)?;
    let pitch = fb.pitches()[0] as usize;
    let offset = fb.offsets()[0] as usize;
    let len = offset
        .checked_add(
            pitch
                .checked_mul(size.height as usize)
                .context("pitch overflow")?,
        )
        .context("framebuffer overflow")?;
    ensure!(
        pitch >= size.width as usize * 4 && len <= 256 * 1024 * 1024,
        "invalid framebuffer allocation"
    );
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    ensure!(
        ptr != libc::MAP_FAILED,
        "GPU buffer is not CPU-readable: {}",
        std::io::Error::last_os_error()
    );
    let map = Mapping { ptr, len };
    let mut sync = 1u64; // DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ
    ensure!(
        unsafe { libc::ioctl(fd.as_raw_fd(), 0x40086200, &mut sync) } >= 0,
        "DMA buffer synchronization failed"
    );
    let bytes = unsafe { std::slice::from_raw_parts(map.ptr.cast::<u8>(), map.len) };
    let mut pixels = Vec::with_capacity(size.width as usize * size.height as usize * 4);
    for y in 0..size.height as usize {
        pixels.extend_from_slice(
            &bytes[offset + y * pitch..offset + y * pitch + size.width as usize * 4],
        );
    }
    sync = 5; // DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), 0x40086200, &mut sync) };
    ensure!(rc >= 0, "DMA buffer synchronization failed");
    if matches!(
        format,
        video_drm::buffer::DrmFourcc::Xbgr8888 | video_drm::buffer::DrmFourcc::Abgr8888
    ) {
        for px in pixels.as_chunks_mut::<4>().0 {
            px.swap(0, 2);
        }
    }
    drop(owned);
    Ok((size, pixels, alpha))
}
fn properties(
    card: &Card,
    plane: video_drm::control::plane::Handle,
) -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    for (handle, value) in card.get_properties(plane)?.iter() {
        result.insert(
            card.get_property(*handle)?
                .name()
                .to_string_lossy()
                .into_owned(),
            *value,
        );
    }
    Ok(result)
}
fn scanout(
    output: &driver::Output,
    gpus: &mut BTreeMap<String, super::gpu::Reader>,
) -> Result<Image> {
    let card_name = output
        .connector
        .split('-')
        .next()
        .context("invalid connector")?;
    let card = Card(File::open(format!("/dev/dri/{card_name}"))?);
    if !gpus.contains_key(card_name) {
        match super::gpu::Reader::new(card.0.try_clone()?) {
            Ok(reader) => {
                gpus.insert(card_name.into(), reader);
            }
            Err(error) => {
                tracing::debug!(%error,"GPU readback unavailable; trying linear CPU mapping")
            }
        }
    }
    let mut gpu = gpus.get(card_name);
    card.set_client_capability(video_drm::ClientCapability::UniversalPlanes, true)?;
    card.set_client_capability(video_drm::ClientCapability::Atomic, true)?;
    let target: crtc::Handle = {
        let mut found = None;
        for c in card.resource_handles()?.connectors() {
            let c = card.get_connector(*c, false)?;
            if format!("{card_name}-{c}") == output.connector {
                if let Some(e) = c.current_encoder() {
                    found = card.get_encoder(e)?.crtc();
                }
            }
        }
        found.context("display has no active scanout")?
    };
    let mode = card
        .get_crtc(target)?
        .mode()
        .context("scanout is disabled")?;
    let size = Size {
        width: u32::from(mode.size().0),
        height: u32::from(mode.size().1),
    }
    .validate_source()?;
    let mut planes = vec![];
    for handle in card.plane_handles()? {
        let p = card.get_plane(handle)?;
        if p.crtc() == Some(target) {
            if let Some(fb) = p.framebuffer() {
                let props = properties(&card, handle)?;
                planes.push((
                    props
                        .get("zpos")
                        .copied()
                        .unwrap_or(if props.get("type") == Some(&2) {
                            255
                        } else {
                            0
                        }),
                    fb,
                    props,
                ));
            }
        }
    }
    planes.sort_by_key(|p| p.0);
    ensure!(!planes.is_empty(), "display has no visible planes");
    let mut pixels = vec![0; size.width as usize * size.height as usize * 4];
    for (_, fb, p) in planes {
        let get = |name: &str| {
            p.get(name)
                .copied()
                .with_context(|| format!("missing DRM plane property {name}"))
        };
        ensure!(
            p.get("rotation").is_none_or(|v| *v == 1),
            "rotated scanout not supported"
        );
        ensure!(
            p.get("alpha").is_none_or(|v| *v == 65535),
            "plane alpha not supported"
        );
        let (source, data, alpha) = plane_pixels(&card, fb, &mut gpu)?;
        let sx = get("SRC_X")?;
        let sy = get("SRC_Y")?;
        let sw = get("SRC_W")?;
        let sh = get("SRC_H")?;
        ensure!(
            [sx, sy, sw, sh].iter().all(|n| n & 65535 == 0),
            "fractional source crop not supported"
        );
        let (sx, sy, sw, sh) = (sx >> 16, sy >> 16, sw >> 16, sh >> 16);
        ensure!(
            sw > 0
                && sh > 0
                && sx + sw <= u64::from(source.width)
                && sy + sh <= u64::from(source.height),
            "invalid plane source bounds"
        );
        let (dx, dy, dw, dh) = (
            get("CRTC_X")? as i64,
            get("CRTC_Y")? as i64,
            get("CRTC_W")?,
            get("CRTC_H")?,
        );
        ensure!(
            dw > 0 && dh > 0 && dw <= 16384 && dh <= 16384,
            "invalid plane destination bounds"
        );
        let premult = p.get("pixel blend mode").is_none_or(|v| *v == 0);
        ensure!(
            p.get("pixel blend mode").is_none_or(|v| *v <= 2),
            "unsupported plane blend mode"
        );
        for y in 0..size.height as i64 {
            if y < dy || y - dy >= dh as i64 {
                continue;
            }
            for x in 0..size.width as i64 {
                if x < dx || x - dx >= dw as i64 {
                    continue;
                }
                let ix = sx + (x - dx) as u64 * sw / dw;
                let iy = sy + (y - dy) as u64 * sh / dh;
                let at = ((iy * source.width as u64 + ix) * 4) as usize;
                let dest = ((y * size.width as i64 + x) * 4) as usize;
                let a = if alpha && p.get("pixel blend mode") != Some(&2) {
                    u32::from(data[at + 3])
                } else {
                    255
                };
                for c in 0..3 {
                    pixels[dest + c] = (if premult {
                        u32::from(data[at + c]) + u32::from(pixels[dest + c]) * (255 - a) / 255
                    } else {
                        (u32::from(data[at + c]) * a + u32::from(pixels[dest + c]) * (255 - a))
                            / 255
                    })
                    .min(255) as u8;
                }
            }
        }
    }
    Ok(Image {
        size,
        pixels,
        identity: output.id.clone(),
    })
}
