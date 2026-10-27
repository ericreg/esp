//! Versioned, bounded media framing. Local media uses the same framing as QUIC.
use anyhow::{Result, ensure};
use minicbor::{Decode, Encode};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ALPN: &[u8] = b"esp/video/cbor/1";
pub const MAX_FRAME: usize = 2 * 1024 * 1024;
pub const CONTROL_LIMIT: usize = 65535;
pub const SETUP: std::time::Duration = std::time::Duration::from_secs(15);
pub const LIVENESS: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize)]
#[cbor(array)]
pub struct Format {
    #[n(0)]
    pub width: u32,
    #[n(1)]
    pub height: u32,
    #[n(2)]
    pub fps: u32,
    #[n(3)]
    pub kbps: u32,
}
impl Format {
    pub fn validate(self) -> Result<()> {
        ensure!(
            (16..=1920).contains(&self.width)
                && (16..=1080).contains(&self.height)
                && self.width.is_multiple_of(2)
                && self.height.is_multiple_of(2),
            "unsupported video dimensions"
        );
        ensure!(
            (1..=30).contains(&self.fps),
            "frame rate must be between 1 and 30"
        );
        ensure!(
            (500..=12000).contains(&self.kbps),
            "bitrate must be between 500 and 12000 kbit/s"
        );
        Ok(())
    }
    /// A shared policy for congestion feedback; dimensions stay negotiated.
    pub fn reduced(mut self, steps: u32) -> Self {
        for _ in 0..steps.min(32) {
            if self.kbps > 500 {
                self.kbps = (self.kbps * 3 / 4).max(500);
            } else {
                self.fps = (self.fps * 3 / 4).max(1);
            }
        }
        self
    }
    pub fn yuv_bytes(self) -> usize {
        self.width as usize * self.height as usize * 3 / 2
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub enum LocalRequest {
    #[n(0)]
    Capabilities,
    #[n(1)]
    Share {
        #[n(0)]
        peer: String,
        #[n(1)]
        display: String,
        #[n(2)]
        format: Format,
        #[n(3)]
        allow_input: bool,
    },
    #[n(2)]
    View {
        #[n(0)]
        host: String,
        #[n(1)]
        resume: Option<String>,
    },
    #[n(3)]
    Status,
    #[n(4)]
    Stop,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub enum Reply {
    #[n(0)]
    Ready {
        #[n(0)]
        share: String,
        #[n(1)]
        format: Format,
        #[n(2)]
        allow_input: bool,
    },
    #[n(1)]
    Error(#[n(0)] String),
    #[n(2)]
    Report(#[n(0)] String),
    #[n(3)]
    Rejected(#[n(0)] String),
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct ClientHello {
    #[n(0)]
    pub identity: crate::Hello,
    #[n(1)]
    pub resume: Option<String>,
}
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct ServerHello {
    #[n(0)]
    pub identity: crate::Hello,
    #[n(1)]
    pub share: String,
    #[n(2)]
    pub format: Format,
    #[n(3)]
    pub allow_input: bool,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub enum ServerResponse {
    #[n(0)]
    Ready(#[n(0)] ServerHello),
    #[n(1)]
    Rejected(#[n(0)] String),
}
#[derive(Debug)]
pub struct Rejected(pub String);
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Rejected {}

#[derive(Debug, Clone)]
pub struct Frame {
    pub sequence: u64,
    pub timestamp_us: u64,
    pub key: bool,
    pub data: bytes::Bytes,
}
impl Frame {
    pub fn validate(&self, format: Format, need_key: bool) -> Result<()> {
        ensure!(
            !self.data.is_empty() && self.data.len() <= MAX_FRAME,
            "invalid video frame length"
        );
        format.validate()?;
        // Codec-independent services validate the envelope. rav1d validates actual
        // dimensions, bit depth and keyframe flags before the viewer presents pixels.
        ensure!(!need_key || self.key, "expected AV1 keyframe");
        Ok(())
    }
}
pub async fn write_frame<W: AsyncWrite + Unpin>(out: &mut W, frame: &Frame) -> Result<()> {
    ensure!(
        !frame.data.is_empty() && frame.data.len() <= MAX_FRAME,
        "invalid frame length"
    );
    // Version, flags, sequence, sender-relative timestamp, payload length.
    let mut header = [0u8; 22];
    header[0] = 1;
    header[1] = frame.key.into();
    header[2..10].copy_from_slice(&frame.sequence.to_be_bytes());
    header[10..18].copy_from_slice(&frame.timestamp_us.to_be_bytes());
    header[18..22].copy_from_slice(&(frame.data.len() as u32).to_be_bytes());
    out.write_all(&header).await?;
    out.write_all(&frame.data).await?;
    out.flush().await?;
    Ok(())
}
pub async fn read_frame<R: AsyncRead + Unpin>(input: &mut R) -> Result<Frame> {
    let mut h = [0u8; 22];
    input.read_exact(&mut h).await?;
    ensure!(h[0] == 1 && h[1] <= 1, "unsupported video frame header");
    let len = u32::from_be_bytes(h[18..22].try_into().unwrap()) as usize;
    ensure!(len > 0 && len <= MAX_FRAME, "invalid video frame length");
    let mut data = vec![0; len];
    input.read_exact(&mut data).await?;
    Ok(Frame {
        sequence: u64::from_be_bytes(h[2..10].try_into().unwrap()),
        timestamp_us: u64::from_be_bytes(h[10..18].try_into().unwrap()),
        key: h[1] == 1,
        data: data.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn framing_bounds_and_fragmentation() {
        let (mut a, mut b) = tokio::io::duplex(3);
        let frame = Frame {
            sequence: 4,
            timestamp_us: 123,
            key: true,
            data: vec![1; 1000].into(),
        };
        let expected = frame.clone();
        let writer = tokio::spawn(async move { write_frame(&mut a, &frame).await.unwrap() });
        let read = read_frame(&mut b).await.unwrap();
        assert_eq!(read.data, expected.data);
        assert_eq!(read.sequence, 4);
        writer.await.unwrap();
        let mut bad = vec![1, 0];
        bad.extend_from_slice(&[0; 16]);
        bad.extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
        assert!(read_frame(&mut bad.as_slice()).await.is_err());
    }
    #[test]
    fn congestion_policy_preserves_format_and_reaches_a_floor() {
        let format = Format {
            width: 1920,
            height: 1080,
            fps: 30,
            kbps: 12000,
        };
        let mut previous = format;
        for step in 0..40 {
            let next = format.reduced(step);
            next.validate().unwrap();
            assert!(next.kbps <= previous.kbps && next.fps <= previous.fps);
            assert_eq!((next.width, next.height), (1920, 1080));
            previous = next;
        }
        assert_eq!((previous.kbps, previous.fps), (500, 1));
    }
    #[test]
    fn rejects_missing_keyframe_and_invalid_format() {
        let format = Format {
            width: 64,
            height: 48,
            fps: 30,
            kbps: 4000,
        };
        let mut frame = Frame {
            sequence: 0,
            timestamp_us: 0,
            key: true,
            data: vec![0x12, 0].into(),
        };
        frame.validate(format, true).unwrap();
        frame.key = false;
        assert!(frame.validate(format, true).is_err());
        assert!(
            Format {
                width: u32::MAX,
                ..format
            }
            .validate()
            .is_err()
        );
    }
}
