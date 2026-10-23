//! Bounded, independently owned libvpx wrapper and BT.601 limited-range conversion.
use super::protocol::{Format, MAX_FRAME};
use anyhow::{Result, ensure};
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn esp_vpx_encoder(w: u32, h: u32, fps: u32, kbps: u32) -> *mut c_void;
    fn esp_vpx_decoder(w: u32, h: u32) -> *mut c_void;
    fn esp_vpx_free(ctx: *mut c_void);
    fn esp_vpx_encode(
        ctx: *mut c_void,
        yuv: *const u8,
        pts: i64,
        force: c_int,
        out: *mut u8,
        capacity: usize,
        len: *mut usize,
        key: *mut c_int,
    ) -> c_int;
    fn esp_vpx_decode(ctx: *mut c_void, input: *const u8, len: usize, out: *mut u8) -> c_int;
}
pub struct Codec {
    ctx: *mut c_void,
    format: Format,
}
// Each context is exclusively moved to and used by a single bounded worker.
unsafe impl Send for Codec {}
impl Drop for Codec {
    fn drop(&mut self) {
        unsafe { esp_vpx_free(self.ctx) }
    }
}
impl Codec {
    pub fn encoder(format: Format) -> Result<Self> {
        format.validate()?;
        let ctx = unsafe { esp_vpx_encoder(format.width, format.height, format.fps, format.kbps) };
        ensure!(!ctx.is_null(), "libvpx encoder initialization failed");
        Ok(Self { ctx, format })
    }
    pub fn decoder(format: Format) -> Result<Self> {
        format.validate()?;
        let ctx = unsafe { esp_vpx_decoder(format.width, format.height) };
        ensure!(!ctx.is_null(), "libvpx decoder initialization failed");
        Ok(Self { ctx, format })
    }
    pub fn encode(&mut self, yuv: &[u8], pts: i64, force: bool) -> Result<(Vec<u8>, bool)> {
        ensure!(
            yuv.len() == self.format.yuv_bytes(),
            "invalid encoder input size"
        );
        let mut out = vec![0; MAX_FRAME];
        let mut len = 0;
        let mut key = 0;
        let result = unsafe {
            esp_vpx_encode(
                self.ctx,
                yuv.as_ptr(),
                pts,
                force.into(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
                &mut key,
            )
        };
        ensure!(
            result == 0 && len > 0 && len <= out.len(),
            "libvpx encode failed: {result}"
        );
        out.truncate(len);
        Ok((out, key != 0))
    }
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<u32>> {
        ensure!(
            !data.is_empty() && data.len() <= MAX_FRAME,
            "invalid decoder input size"
        );
        let mut yuv = vec![0; self.format.yuv_bytes()];
        let result =
            unsafe { esp_vpx_decode(self.ctx, data.as_ptr(), data.len(), yuv.as_mut_ptr()) };
        ensure!(result == 0, "libvpx decode failed: {result}");
        Ok(yuv_to_rgb(&yuv, self.format))
    }
}

pub fn xrgb_to_yuv(data: &[u8], sw: u32, sh: u32, f: Format) -> Result<Vec<u8>> {
    super::display::Size {
        width: sw,
        height: sh,
    }
    .validate_source()?;
    f.validate()?;
    ensure!(
        data.len() == sw as usize * sh as usize * 4,
        "invalid XRGB input size"
    );
    let (w, h) = (f.width as usize, f.height as usize);
    let mut out = vec![0; f.yuv_bytes()];
    for y in 0..h {
        for x in 0..w {
            let sx = x * sw as usize / w;
            let sy = y * sh as usize / h;
            let i = (sy * sw as usize + sx) * 4;
            let (b, g, r) = (data[i] as i32, data[i + 1] as i32, data[i + 2] as i32);
            out[y * w + x] = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16).clamp(16, 235) as u8;
        }
    }
    // Average each 2x2 block before chroma subsampling.
    for y in 0..h / 2 {
        for x in 0..w / 2 {
            let (mut r, mut g, mut b) = (0, 0, 0);
            for dy in 0..2 {
                for dx in 0..2 {
                    let sx = (2 * x + dx) * sw as usize / w;
                    let sy = (2 * y + dy) * sh as usize / h;
                    let i = (sy * sw as usize + sx) * 4;
                    b += data[i] as i32;
                    g += data[i + 1] as i32;
                    r += data[i + 2] as i32;
                }
            }
            r /= 4;
            g /= 4;
            b /= 4;
            out[w * h + y * (w / 2) + x] =
                (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128).clamp(16, 240) as u8;
            out[w * h + w * h / 4 + y * (w / 2) + x] =
                (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128).clamp(16, 240) as u8;
        }
    }
    Ok(out)
}
fn yuv_to_rgb(yuv: &[u8], f: Format) -> Vec<u32> {
    let (w, h) = (f.width as usize, f.height as usize);
    let mut out = vec![0; w * h];
    for y in 0..h {
        for x in 0..w {
            let c = (yuv[y * w + x] as i32 - 16).max(0);
            let d = yuv[w * h + (y / 2) * (w / 2) + x / 2] as i32 - 128;
            let e = yuv[w * h + w * h / 4 + (y / 2) * (w / 2) + x / 2] as i32 - 128;
            let r = ((298 * c + 409 * e + 128) >> 8).clamp(0, 255) as u32;
            let g = ((298 * c - 100 * d - 208 * e + 128) >> 8).clamp(0, 255) as u32;
            let b = ((298 * c + 516 * d + 128) >> 8).clamp(0, 255) as u32;
            out[y * w + x] = (r << 16) | (g << 8) | b;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_colors_roundtrip() {
        let f = Format {
            width: 64,
            height: 48,
            fps: 30,
            kbps: 4000,
        };
        let mut raw = vec![0; 64 * 48 * 4];
        for pixel in raw.chunks_exact_mut(4) {
            pixel.copy_from_slice(&[0, 0, 255, 0]);
        }
        let yuv = xrgb_to_yuv(&raw, 64, 48, f).unwrap();
        let mut enc = Codec::encoder(f).unwrap();
        let mut dec = Codec::decoder(f).unwrap();
        for pts in 0..3 {
            let (packet, key) = enc.encode(&yuv, pts, pts == 0).unwrap();
            assert!(pts != 0 || key);
            let rgb = dec.decode(&packet).unwrap();
            for px in rgb {
                assert!((px >> 16) & 255 > 230);
                assert!(px & 65535 < 0x1010);
            }
        }
    }
}
