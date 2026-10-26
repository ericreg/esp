use crate::{Frame, Settings};
use anyhow::{Result, anyhow, ensure};
use oxideav_vp8::{I420Frame, KeyframeParams, Vp8DecoderState, stream::Vp8InterStreamEncoder};
use rav1e::prelude::*;
use std::ptr::NonNull;

pub struct Packet {
    pub index: usize,
    pub bytes: Vec<u8>,
    pub key: bool,
}

// One codec instance per worker; keep its state inline, outside timed setup.
#[allow(clippy::large_enum_variant)]
pub enum Encoder {
    Vp8(Vp8InterStreamEncoder),
    Av1(Context<u8>),
}
impl Encoder {
    pub fn new(codec: &str, s: &Settings) -> Result<Self> {
        Ok(match codec {
            "vp8" => Self::Vp8(
                Vp8InterStreamEncoder::new(
                    KeyframeParams {
                        y_ac_qi: s.vp8_q,
                        ..KeyframeParams::default()
                    },
                    s.fps as u64,
                )
                .ok_or_else(|| anyhow!("invalid VP8 configuration"))?,
            ),
            "av1" => {
                let mut config = EncoderConfig::with_speed_preset(s.av1_speed);
                config.width = s.width;
                config.height = s.height;
                config.time_base = Rational {
                    num: 1,
                    den: s.fps as u64,
                };
                config.low_latency = true;
                config.tiles = s.av1_tiles;
                // rav1e 0.8.1 requires at least one lookahead frame, even in low-latency mode.
                config.speed_settings.rdo_lookahead_frames = 1;
                config.min_key_frame_interval = s.fps as u64;
                config.max_key_frame_interval = s.fps as u64;
                config.quantizer = s.av1_q;
                config.bitrate = 0;
                config.bit_depth = 8;
                config.chroma_sampling = ChromaSampling::Cs420;
                Self::Av1(
                    Config::new()
                        .with_encoder_config(config)
                        .with_threads(s.threads)
                        .new_context()?,
                )
            }
            _ => anyhow::bail!("unknown codec {codec}"),
        })
    }
    // Caller times this entire adapter, including copies into the codec's input allocation.
    pub fn push(&mut self, input: Option<&Frame>, index: usize) -> Result<Vec<Packet>> {
        match self {
            Self::Vp8(enc) => {
                let Some(f) = input else { return Ok(vec![]) };
                let p = enc.encode_frame(&I420Frame::packed(
                    f.width as u32,
                    f.height as u32,
                    &f.planes[0],
                    &f.planes[1],
                    &f.planes[2],
                ))?;
                let key = p.is_keyframe();
                Ok(vec![Packet {
                    index,
                    bytes: p.bytes,
                    key,
                }])
            }
            Self::Av1(enc) => {
                if let Some(f) = input {
                    let mut frame = enc.new_frame();
                    for (i, plane) in frame.planes.iter_mut().enumerate() {
                        plane.copy_from_raw_u8(&f.planes[i], f.width >> usize::from(i > 0), 1);
                    }
                    enc.send_frame(frame)?;
                } else {
                    enc.flush();
                }
                let mut packets = vec![];
                loop {
                    match enc.receive_packet() {
                        Ok(p) => packets.push(Packet {
                            index: p.input_frameno as usize,
                            bytes: p.data,
                            key: p.frame_type == FrameType::KEY,
                        }),
                        Err(EncoderStatus::Encoded) => continue,
                        Err(EncoderStatus::NeedMoreData | EncoderStatus::LimitReached) => break,
                        Err(e) => return Err(anyhow!("rav1e receive: {e:?}")),
                    }
                }
                Ok(packets)
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Decoder {
    Vp8(Vp8DecoderState),
    Av1(Av1Decoder),
}
impl Decoder {
    pub fn new(codec: &str, s: &Settings) -> Result<Self> {
        Ok(if codec == "vp8" {
            Self::Vp8(Vp8DecoderState::new())
        } else {
            Self::Av1(Av1Decoder::new(s)?)
        })
    }
    pub fn tile_grid(&self) -> Option<[usize; 2]> {
        match self {
            Self::Vp8(_) => None,
            Self::Av1(d) => d.tile_grid,
        }
    }
    pub fn decode(&mut self, bytes: &[u8]) -> Result<Frame> {
        match self {
            Self::Vp8(d) => {
                let f = d.decode_frame(bytes)?;
                Ok(Frame {
                    width: f.width as usize,
                    height: f.height as usize,
                    planes: [f.y, f.u, f.v],
                })
            }
            Self::Av1(d) => d.decode(bytes),
        }
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
    tile_grid: Option<[usize; 2]>,
    context: Option<Dav1dContext>,
    width: usize,
    height: usize,
}
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
    fn new(s: &Settings) -> Result<Self> {
        let mut settings = std::mem::MaybeUninit::<Dav1dSettings>::uninit();
        // SAFETY: default_settings initializes the complete live settings allocation.
        unsafe { dav1d_default_settings(NonNull::new(settings.as_mut_ptr()).unwrap()) };
        let mut settings = unsafe { settings.assume_init() };
        settings.n_threads = s.threads as i32;
        settings.max_frame_delay = 1;
        settings.apply_grain = 0;
        settings.frame_size_limit = (s.width * s.height) as u32;
        let mut this = Self {
            tile_grid: None,
            context: None,
            width: s.width,
            height: s.height,
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
    fn decode(&mut self, bytes: &[u8]) -> Result<Frame> {
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
            let tiling = &header.as_ref().tiling;
            self.tile_grid = Some([tiling.cols as usize, tiling.rows as usize]);
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
            Ok(Frame {
                width: self.width,
                height: self.height,
                planes,
            })
        }
    }
}
