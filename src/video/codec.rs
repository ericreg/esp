//! Bounded AV1 codecs and BT.601 limited-range conversion. No system codec library.
use super::protocol::{Format, MAX_FRAME};
use anyhow::{Result, anyhow, ensure};
use rav1e::prelude::*;
use std::{collections::VecDeque, ptr::NonNull};

pub fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(6))
}

pub struct Encoded {
    pub timestamp_us: u64,
    pub data: Vec<u8>,
    pub key: bool,
}

pub struct Encoder {
    context: Context<u8>,
    format: Format,
    threads: usize,
    timestamps: VecDeque<u64>,
    next_output: u64,
}
impl Encoder {
    pub fn new(format: Format, threads: usize) -> Result<Self> {
        format.validate()?;
        ensure!(
            (1..=64).contains(&threads),
            "encoder threads must be between 1 and 64"
        );
        let mut config = EncoderConfig::with_speed_preset(10);
        config.width = format.width as usize;
        config.height = format.height as usize;
        config.time_base = Rational {
            num: 1,
            den: format.fps as u64,
        };
        config.low_latency = true;
        config.speed_settings.rdo_lookahead_frames = 1;
        config.tiles = 16;
        config.min_key_frame_interval = format.fps as u64;
        config.max_key_frame_interval = format.fps as u64;
        config.bitrate = (format.kbps * 1000) as i32;
        config.quantizer = 255;
        config.bit_depth = 8;
        config.chroma_sampling = ChromaSampling::Cs420;
        config.pixel_range = PixelRange::Limited;
        let context = Config::new()
            .with_encoder_config(config)
            .with_threads(threads)
            .new_context()?;
        Ok(Self {
            context,
            format,
            threads,
            timestamps: VecDeque::new(),
            next_output: 0,
        })
    }
    /// Output is delayed. The caller must continue feeding frames even on a static screen.
    /// A reset discards only unpublished inputs and starts an independent decoding timeline.
    pub fn encode(&mut self, yuv: &[u8], timestamp_us: u64, force: bool) -> Result<Vec<Encoded>> {
        ensure!(
            yuv.len() == self.format.yuv_bytes(),
            "invalid encoder input size"
        );
        if force {
            *self = Self::new(self.format, self.threads)?;
        }
        ensure!(
            self.timestamps.len() < 16,
            "AV1 encoder input backlog exceeded"
        );
        let mut frame = self.context.new_frame();
        let mut offset = 0;
        for (i, plane) in frame.planes.iter_mut().enumerate() {
            let w = (self.format.width as usize) >> usize::from(i > 0);
            let h = (self.format.height as usize) >> usize::from(i > 0);
            plane.copy_from_raw_u8(&yuv[offset..offset + w * h], w, 1);
            offset += w * h;
        }
        self.context.send_frame(frame)?;
        self.timestamps.push_back(timestamp_us);
        self.receive()
    }
    fn receive(&mut self) -> Result<Vec<Encoded>> {
        let mut packets = Vec::new();
        loop {
            match self.context.receive_packet() {
                Ok(packet) => {
                    ensure!(
                        packet.input_frameno == self.next_output,
                        "AV1 output reordered"
                    );
                    ensure!(
                        !packet.data.is_empty() && packet.data.len() <= MAX_FRAME,
                        "AV1 packet exceeds media limit"
                    );
                    let timestamp_us = self
                        .timestamps
                        .pop_front()
                        .ok_or_else(|| anyhow!("unexpected AV1 output"))?;
                    self.next_output += 1;
                    packets.push(Encoded {
                        timestamp_us,
                        data: packet.data,
                        key: packet.frame_type == FrameType::KEY,
                    });
                }
                Err(EncoderStatus::Encoded) => continue,
                Err(EncoderStatus::NeedMoreData | EncoderStatus::LimitReached) => break,
                Err(error) => return Err(anyhow!("rav1e receive: {error:?}")),
            }
        }
        Ok(packets)
    }
    #[cfg(test)]
    pub fn finish(&mut self) -> Result<Vec<Encoded>> {
        self.context.flush();
        self.receive()
    }
}

use rav1d::{
    include::dav1d::{
        data::Dav1dData,
        dav1d::{Dav1dContext, Dav1dSettings},
        picture::Dav1dPicture,
    },
    src::lib::*,
};

// rav1d's public interface retains dav1d's C ABI, but these calls execute Rust.
// No native codec library is linked. Each allocation has an explicit Drop owner.
pub struct Av1Decoder {
    context: Option<Dav1dContext>,
    width: usize,
    height: usize,
}
// SAFETY: this wrapper uniquely owns the context. All public operations require
// &mut self, pictures/data are released before returning, and rav1d owns and
// synchronizes its internal workers. The raw C-ABI handle has no thread affinity.
unsafe impl Send for Av1Decoder {}

struct Data(Dav1dData);
impl Drop for Data {
    fn drop(&mut self) {
        unsafe { dav1d_data_unref(Some(NonNull::from(&mut self.0))) }
    }
}
struct Picture(Dav1dPicture);
impl Drop for Picture {
    fn drop(&mut self) {
        unsafe { dav1d_picture_unref(Some(NonNull::from(&mut self.0))) }
    }
}
impl Drop for Av1Decoder {
    fn drop(&mut self) {
        unsafe { dav1d_close(Some(NonNull::from(&mut self.context))) }
    }
}
impl Av1Decoder {
    pub fn new(format: Format) -> Result<Self> {
        format.validate()?;
        let mut settings = std::mem::MaybeUninit::<Dav1dSettings>::uninit();
        // SAFETY: default_settings initializes the complete live settings allocation.
        unsafe { dav1d_default_settings(NonNull::new(settings.as_mut_ptr()).unwrap()) };
        let mut settings = unsafe { settings.assume_init() };
        settings.n_threads = default_threads() as i32;
        settings.max_frame_delay = 1;
        settings.apply_grain = 0;
        settings.frame_size_limit = format.width * format.height;
        let mut this = Self {
            context: None,
            width: format.width as usize,
            height: format.height as usize,
        };
        let code = unsafe {
            dav1d_open(
                Some(NonNull::from(&mut this.context)),
                Some(NonNull::from(&mut settings)),
            )
        }
        .0;
        ensure!(code == 0, "rav1d open: {code}");
        Ok(this)
    }
    pub fn decode(&mut self, bytes: &[u8], key: bool) -> Result<Vec<u32>> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_FRAME,
            "invalid AV1 packet size"
        );
        let mut data = Data(Dav1dData::default());
        let mut picture = Picture(Dav1dPicture::default());
        // SAFETY: data_create allocates bytes.len() writable bytes, owned by Data.
        // The context remains open; all out pointers refer to live exclusive values.
        unsafe {
            let ptr = dav1d_data_create(Some(NonNull::from(&mut data.0)), bytes.len());
            ensure!(!ptr.is_null(), "rav1d allocation failed");
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            let code = dav1d_send_data(self.context, Some(NonNull::from(&mut data.0))).0;
            ensure!(
                code == 0 && data.0.sz == 0,
                "rav1d send: {code}; unconsumed bytes {}",
                data.0.sz
            );
            let code = dav1d_get_picture(self.context, Some(NonNull::from(&mut picture.0))).0;
            ensure!(
                code == 0,
                "rav1d receive: {code}; expected one immediate picture per packet"
            );
            ensure!(
                picture.0.p.w == self.width as i32
                    && picture.0.p.h == self.height as i32
                    && picture.0.p.bpc == 8
                    && picture.0.p.layout
                        == rav1d::include::dav1d::headers::DAV1D_PIXEL_LAYOUT_I420,
                "unexpected decoded dimensions/bit depth"
            );
            // Header remains owned by Picture until its Drop at the end of this call.
            let header = picture
                .0
                .frame_hdr
                .ok_or_else(|| anyhow!("missing AV1 frame header"))?;
            ensure!(
                (header.as_ref().frame_type
                    == rav1d::include::dav1d::headers::DAV1D_FRAME_TYPE_KEY)
                    == key,
                "AV1 keyframe flag mismatch"
            );
            let mut planes = [vec![], vec![], vec![]];
            for (i, plane) in planes.iter_mut().enumerate() {
                let w = self.width >> usize::from(i > 0);
                let h = self.height >> usize::from(i > 0);
                let stride = picture.0.stride[usize::from(i > 0)];
                ensure!(stride >= w as isize, "invalid decoded stride");
                let ptr = picture.0.data[i]
                    .ok_or_else(|| anyhow!("missing decoded plane"))?
                    .as_ptr()
                    .cast::<u8>();
                plane.reserve(w * h);
                // SAFETY: rav1d owns each returned 8-bit I420 plane until Picture drops.
                for row in 0..h {
                    plane.extend_from_slice(std::slice::from_raw_parts(
                        ptr.offset(row as isize * stride),
                        w,
                    ));
                }
            }
            let yuv = planes.concat();
            Ok(yuv_to_rgb(
                &yuv,
                Format {
                    width: self.width as u32,
                    height: self.height as u32,
                    fps: 30,
                    kbps: 4000,
                },
            ))
        }
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
    fn format() -> Format {
        Format {
            width: 64,
            height: 48,
            fps: 30,
            kbps: 4000,
        }
    }
    fn red(f: Format) -> Vec<u8> {
        let mut raw = vec![0; f.width as usize * f.height as usize * 4];
        for pixel in raw.chunks_exact_mut(4) {
            pixel.copy_from_slice(&[0, 0, 255, 0]);
        }
        xrgb_to_yuv(&raw, f.width, f.height, f).unwrap()
    }
    #[test]
    fn delayed_av1_roundtrip_and_forced_restart() {
        for threads in [1, 6] {
            let f = format();
            let yuv = red(f);
            let mut enc = Encoder::new(f, threads).unwrap();
            // Restart while the old stream still has unpublished buffered inputs.
            for generation in 0..2 {
                let mut dec = Av1Decoder::new(f).unwrap();
                let mut packets = Vec::new();
                for input in 0..12 {
                    packets.extend(
                        enc.encode(&yuv, generation * 1000 + input, input == 0)
                            .unwrap(),
                    );
                }
                assert!(
                    !packets.is_empty(),
                    "static content must produce output without flushing"
                );
                assert!(packets[0].key);
                for (i, p) in packets.iter().enumerate() {
                    assert_eq!(p.timestamp_us, generation * 1000 + i as u64);
                    let rgb = dec.decode(&p.data, p.key).unwrap();
                    assert!(
                        rgb.into_iter()
                            .all(|px| (px >> 16) & 255 > 230 && px & 65535 < 0x1010)
                    );
                }
                if generation == 1 {
                    let tail = enc.finish().unwrap();
                    assert_eq!(packets.len() + tail.len(), 12);
                    for p in tail {
                        dec.decode(&p.data, p.key).unwrap();
                    }
                }
            }
        }
    }
    #[test]
    fn periodic_keyframes_and_bitrate_reconfiguration() {
        let f = Format {
            width: 256,
            height: 128,
            fps: 5,
            kbps: 500,
        };
        let mut decoder = Av1Decoder::new(f).unwrap();
        for format in [
            f,
            Format {
                kbps: 1000,
                fps: 1,
                ..f
            },
        ] {
            let mut encoder = Encoder::new(format, 6).unwrap();
            let yuv = red(format);
            let mut packets = Vec::new();
            for i in 0..16 {
                packets.extend(encoder.encode(&yuv, i, false).unwrap());
            }
            packets.extend(encoder.finish().unwrap());
            assert_eq!(packets.len(), 16);
            assert!(packets[0].key);
            let mut last_key = 0;
            for (i, packet) in packets.iter().enumerate() {
                if packet.key {
                    last_key = i;
                }
                assert!(i - last_key < format.fps as usize);
                decoder.decode(&packet.data, packet.key).unwrap();
            }
            if format.fps > 1 {
                assert!(packets.iter().any(|p| !p.key));
            }
        }
    }

    #[test]
    fn rejects_wrong_dimensions_key_flags_and_malformed_packets() {
        let f = format();
        let mut enc = Encoder::new(f, 2).unwrap();
        let mut packets = enc.encode(&red(f), 123, false).unwrap();
        packets.extend(enc.finish().unwrap());
        let packet = &packets[0];
        assert!(
            Av1Decoder::new(f)
                .unwrap()
                .decode(&packet.data, false)
                .is_err()
        );
        let wrong = Format {
            width: 32,
            height: 96,
            ..f
        };
        assert!(
            Av1Decoder::new(wrong)
                .unwrap()
                .decode(&packet.data, true)
                .is_err()
        );
        for bytes in [
            &[][..],
            &[0xff; 10][..],
            &packet.data[..packet.data.len() / 2],
        ] {
            assert!(Av1Decoder::new(f).unwrap().decode(bytes, true).is_err());
        }
        assert!(Encoder::new(f, 0).is_err());
        assert!(Encoder::new(f, 65).is_err());
        assert!((1..=6).contains(&default_threads()));
    }
}
