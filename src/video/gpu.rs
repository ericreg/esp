//! GPU-assisted readback of DRM DMA-BUFs, including tiled/modifier layouts.
//! EGL/GBM/GLES are loaded only for physical graphical capture.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::{c_char, c_void},
    fs::File,
    os::fd::{AsRawFd, OwnedFd},
};
type Ptr = *mut c_void;
type Proc = unsafe extern "C" fn(*const c_char) -> *const c_void;
macro_rules! function {
    ($this:expr,$name:literal,$ty:ty) => {{
        let pointer = unsafe { ($this.proc)(concat!($name, "\0").as_ptr().cast()) };
        ensure!(!pointer.is_null(), concat!("missing GPU function ", $name));
        // SAFETY: signatures below match the EGL/GLES extension specifications.
        unsafe { std::mem::transmute::<*const c_void, $ty>(pointer) }
    }};
}

pub struct Reader {
    _egl: libloading::Library,
    _gbm: libloading::Library,
    _card: File,
    proc: Proc,
    device: Ptr,
    display: Ptr,
    context: Ptr,
    surface: Ptr,
    terminate: unsafe extern "C" fn(Ptr) -> u32,
    destroy_context: unsafe extern "C" fn(Ptr, Ptr) -> u32,
    destroy_surface: unsafe extern "C" fn(Ptr, Ptr) -> u32,
    make_current: unsafe extern "C" fn(Ptr, Ptr, Ptr, Ptr) -> u32,
    destroy_device: unsafe extern "C" fn(Ptr),
}
impl Reader {
    #[allow(unused_unsafe)] // function! also serves safe call sites.
    pub fn new(card: File) -> Result<Self> {
        // SAFETY: system graphics libraries; owned Libraries outlive all function pointers.
        unsafe {
            let egl = libloading::Library::new("libEGL.so.1")
                .context("physical graphics capture requires EGL")?;
            let gbm = libloading::Library::new("libgbm.so.1")
                .context("physical graphics capture requires GBM")?;
            let create_device: unsafe extern "C" fn(i32) -> Ptr =
                *gbm.get(b"gbm_create_device\0")?;
            let mut this = Self {
                proc: *egl.get(b"eglGetProcAddress\0")?,
                terminate: *egl.get(b"eglTerminate\0")?,
                destroy_context: *egl.get(b"eglDestroyContext\0")?,
                destroy_surface: *egl.get(b"eglDestroySurface\0")?,
                make_current: *egl.get(b"eglMakeCurrent\0")?,
                destroy_device: *gbm.get(b"gbm_device_destroy\0")?,
                device: std::ptr::null_mut(),
                display: std::ptr::null_mut(),
                context: std::ptr::null_mut(),
                surface: std::ptr::null_mut(),
                _egl: egl,
                _gbm: gbm,
                _card: card,
            };
            this.device = create_device(this._card.as_raw_fd());
            ensure!(!this.device.is_null(), "GBM device initialization failed");
            let get_display = function!(
                this,
                "eglGetPlatformDisplayEXT",
                unsafe extern "C" fn(u32, Ptr, *const i32) -> Ptr
            );
            this.display = get_display(0x31d7, this.device, std::ptr::null());
            ensure!(!this.display.is_null(), "EGL GBM display unavailable");
            let init = function!(
                this,
                "eglInitialize",
                unsafe extern "C" fn(Ptr, *mut i32, *mut i32) -> u32
            );
            ensure!(
                init(this.display, std::ptr::null_mut(), std::ptr::null_mut()) != 0,
                "EGL initialization failed"
            );
            let bind = function!(this, "eglBindAPI", unsafe extern "C" fn(u32) -> u32);
            ensure!(bind(0x30a0) != 0, "EGL ES API unavailable");
            let choose = function!(
                this,
                "eglChooseConfig",
                unsafe extern "C" fn(Ptr, *const i32, *mut Ptr, i32, *mut i32) -> u32
            );
            let mut config = std::ptr::null_mut();
            let mut count = 0;
            let attributes = [
                0x3033, 0, 0x3040, 4, 0x3024, 8, 0x3023, 8, 0x3022, 8, 0x3038,
            ];
            ensure!(
                choose(
                    this.display,
                    attributes.as_ptr(),
                    &mut config,
                    1,
                    &mut count
                ) != 0
                    && count > 0,
                "EGL ES2 configuration unavailable"
            );
            let context = function!(
                this,
                "eglCreateContext",
                unsafe extern "C" fn(Ptr, Ptr, Ptr, *const i32) -> Ptr
            );
            this.context = context(
                this.display,
                config,
                std::ptr::null_mut(),
                [0x3098, 2, 0x3038].as_ptr(),
            );
            ensure!(!this.context.is_null(), "EGL ES2 context unavailable");
            // GBM commonly exposes window-only configurations. A surfaceless
            // context is sufficient: readback uses an imported image attached to an FBO.
            ensure!(
                (this.make_current)(this.display, this.surface, this.surface, this.context) != 0,
                "EGL make-current failed"
            );
            Ok(this)
        }
    }
    pub fn read(
        &self,
        width: u32,
        height: u32,
        fourcc: u32,
        planes: &[(OwnedFd, u32, u32)],
        modifier: Option<u64>,
    ) -> Result<Vec<u8>> {
        ensure!(
            (1..=4).contains(&planes.len()),
            "invalid DMA-BUF plane count"
        );
        let mut attrs = vec![
            0x3057,
            width as i32,
            0x3056,
            height as i32,
            0x3271,
            fourcc as i32,
        ];
        for (i, (fd, offset, pitch)) in planes.iter().enumerate() {
            let base = if i < 3 { 0x3272 + i as i32 * 3 } else { 0x3440 };
            attrs.extend([
                base,
                fd.as_raw_fd(),
                base + 1,
                *offset as i32,
                base + 2,
                *pitch as i32,
            ]);
            if let Some(m) = modifier {
                attrs.extend([
                    0x3443 + i as i32 * 2,
                    m as u32 as i32,
                    0x3444 + i as i32 * 2,
                    (m >> 32) as i32,
                ]);
            }
        }
        attrs.push(0x3038);
        // Resolve before allocating GPU objects so all errors below have cleanup owners.
        let create = function!(
            self,
            "eglCreateImageKHR",
            unsafe extern "C" fn(Ptr, Ptr, u32, Ptr, *const i32) -> Ptr
        );
        let destroy = function!(
            self,
            "eglDestroyImageKHR",
            unsafe extern "C" fn(Ptr, Ptr) -> u32
        );
        let gen_texture = function!(self, "glGenTextures", unsafe extern "C" fn(i32, *mut u32));
        let del_texture = function!(
            self,
            "glDeleteTextures",
            unsafe extern "C" fn(i32, *const u32)
        );
        let bind_texture = function!(self, "glBindTexture", unsafe extern "C" fn(u32, u32));
        let target = function!(
            self,
            "glEGLImageTargetTexture2DOES",
            unsafe extern "C" fn(u32, Ptr)
        );
        let gen_fb = function!(
            self,
            "glGenFramebuffers",
            unsafe extern "C" fn(i32, *mut u32)
        );
        let del_fb = function!(
            self,
            "glDeleteFramebuffers",
            unsafe extern "C" fn(i32, *const u32)
        );
        let bind_fb = function!(self, "glBindFramebuffer", unsafe extern "C" fn(u32, u32));
        let attach = function!(
            self,
            "glFramebufferTexture2D",
            unsafe extern "C" fn(u32, u32, u32, u32, i32)
        );
        let check = function!(
            self,
            "glCheckFramebufferStatus",
            unsafe extern "C" fn(u32) -> u32
        );
        let read = function!(
            self,
            "glReadPixels",
            unsafe extern "C" fn(i32, i32, i32, i32, u32, u32, Ptr)
        );
        let error = function!(self, "glGetError", unsafe extern "C" fn() -> u32);
        struct Objects {
            display: Ptr,
            image: Ptr,
            texture: u32,
            fb: u32,
            destroy: unsafe extern "C" fn(Ptr, Ptr) -> u32,
            del_texture: unsafe extern "C" fn(i32, *const u32),
            del_fb: unsafe extern "C" fn(i32, *const u32),
        }
        impl Drop for Objects {
            fn drop(&mut self) {
                unsafe {
                    (self.del_fb)(1, &self.fb);
                    (self.del_texture)(1, &self.texture);
                    if !self.image.is_null() {
                        (self.destroy)(self.display, self.image);
                    }
                }
            }
        }
        // SAFETY: all handles belong to this worker's current context and allocation sizes
        // were bounded by the caller's validated display size. ReadPixels writes RGBA8.
        unsafe {
            ensure!(
                (self.make_current)(self.display, self.surface, self.surface, self.context) != 0,
                "EGL make-current failed"
            );
            let image = create(
                self.display,
                std::ptr::null_mut(),
                0x3270,
                std::ptr::null_mut(),
                attrs.as_ptr(),
            );
            ensure!(
                !image.is_null(),
                "GPU cannot import this scanout format/modifier"
            );
            let mut objects = Objects {
                display: self.display,
                image,
                texture: 0,
                fb: 0,
                destroy,
                del_texture,
                del_fb,
            };
            gen_texture(1, &mut objects.texture);
            bind_texture(0x0de1, objects.texture);
            target(0x0de1, image);
            gen_fb(1, &mut objects.fb);
            bind_fb(0x8d40, objects.fb);
            attach(0x8d40, 0x8ce0, 0x0de1, objects.texture, 0);
            ensure!(
                check(0x8d40) == 0x8cd5,
                "GPU scanout image cannot be read as an RGBA framebuffer"
            );
            let mut pixels = vec![0; width as usize * height as usize * 4];
            read(
                0,
                0,
                width as i32,
                height as i32,
                0x1908,
                0x1401,
                pixels.as_mut_ptr().cast(),
            );
            ensure!(error() == 0, "GPU framebuffer readback failed");
            // EGL DMA-BUF import retains buffer row order; convert RGBA to ESP's BGRA.
            for pixel in pixels.as_chunks_mut::<4>().0 {
                pixel.swap(0, 2);
            }
            Ok(pixels)
        }
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        unsafe {
            if !self.display.is_null() {
                (self.make_current)(
                    self.display,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if !self.surface.is_null() {
                    (self.destroy_surface)(self.display, self.surface);
                }
                if !self.context.is_null() {
                    (self.destroy_context)(self.display, self.context);
                }
                (self.terminate)(self.display);
            }
            if !self.device.is_null() {
                (self.destroy_device)(self.device);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use video_drm::{buffer::Buffer, control::Device as _};
    #[test]
    #[ignore = "offscreen GPU import requires an accessible DRM card and EGL; no modesetting"]
    fn offscreen_dmabuf_readback() {
        struct Card(File);
        impl AsFd for Card {
            fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
                self.0.as_fd()
            }
        }
        impl video_drm::Device for Card {}
        impl video_drm::control::Device for Card {}
        let path = std::env::var("ESP_TEST_DRM_CARD").expect("set ESP_TEST_DRM_CARD explicitly");
        let card = Card(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap(),
        );
        let mut buffer = card
            .create_dumb_buffer((64, 48), video_drm::buffer::DrmFourcc::Xrgb8888, 32)
            .unwrap();
        let pitch = buffer.pitch();
        {
            let mut map = card.map_dumb_buffer(&mut buffer).unwrap();
            for y in 0..48 {
                for x in 0..64 {
                    let at = y * pitch as usize + x * 4;
                    map[at..at + 4].copy_from_slice(&[x as u8, y as u8, 0x99, 0]);
                }
            }
        }
        let fd = card
            .buffer_to_prime_fd(buffer.handle(), libc::O_CLOEXEC as u32)
            .unwrap();
        let reader = Reader::new(card.0.try_clone().unwrap()).unwrap();
        let bytes = reader
            .read(
                64,
                48,
                video_drm::buffer::DrmFourcc::Xrgb8888 as u32,
                &[(fd, 0, pitch)],
                Some(0),
            )
            .unwrap();
        for y in 0..48 {
            for x in 0..64 {
                let at = (y * 64 + x) * 4;
                assert_eq!(&bytes[at..at + 3], &[x as u8, y as u8, 0x99]);
            }
        }
        card.destroy_dumb_buffer(buffer).unwrap();
    }
}
