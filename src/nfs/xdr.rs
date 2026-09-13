//! Bounded XDR primitives and ONC RPC record marking (RFC 4506, RFC 5531).
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_RECORD: usize = 4 * 1024 * 1024;
pub const MAX_IO: usize = 1024 * 1024;
pub const MAX_OPS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadXdr;
pub type Result<T> = std::result::Result<T, BadXdr>;

pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn finish(&self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(BadXdr)
        }
    }
    pub fn fixed(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(BadXdr)?;
        let value = self.data.get(self.pos..end).ok_or(BadXdr)?;
        self.pos = end;
        Ok(value)
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.fixed(4)?.try_into().map_err(|_| BadXdr)?,
        ))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.fixed(8)?.try_into().map_err(|_| BadXdr)?,
        ))
    }
    pub fn boolean(&mut self) -> Result<bool> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(BadXdr),
        }
    }
    pub fn opaque(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(BadXdr);
        }
        let value = self.fixed(len)?;
        if self.fixed((4 - len % 4) % 4)?.iter().any(|b| *b != 0) {
            return Err(BadXdr);
        }
        Ok(value)
    }
    pub fn string(&mut self, max: usize) -> Result<String> {
        String::from_utf8(self.opaque(max)?.to_vec()).map_err(|_| BadXdr)
    }
    pub fn bitmap(&mut self) -> Result<Vec<u32>> {
        let n = self.u32()? as usize;
        if n > 4 {
            return Err(BadXdr);
        }
        (0..n).map(|_| self.u32()).collect()
    }
}

#[derive(Default, Clone, Debug)]
pub struct Encoder(pub Vec<u8>);
impl Encoder {
    pub fn u32(&mut self, n: u32) {
        self.0.extend(n.to_be_bytes());
    }
    pub fn u64(&mut self, n: u64) {
        self.0.extend(n.to_be_bytes());
    }
    pub fn boolean(&mut self, b: bool) {
        self.u32(u32::from(b));
    }
    pub fn fixed(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub fn opaque(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.fixed(b);
        self.0.resize(self.0.len() + (4 - b.len() % 4) % 4, 0);
    }
    pub fn string(&mut self, s: &str) {
        self.opaque(s.as_bytes());
    }
    pub fn bitmap(&mut self, bits: &[u32]) {
        self.u32(bits.len() as u32);
        for b in bits {
            self.u32(*b);
        }
    }
}
pub fn bit(bits: &[u32], n: u32) -> bool {
    bits.get((n / 32) as usize)
        .is_some_and(|v| v & (1 << (n % 32)) != 0)
}
pub fn bits(indices: &[u32]) -> Vec<u32> {
    let mut out = vec![0; indices.iter().max().map_or(0, |n| (*n / 32 + 1) as usize)];
    for n in indices {
        out[(*n / 32) as usize] |= 1 << (*n % 32);
    }
    out
}

pub async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    for fragment in 0..1024 {
        let mut header = [0; 4];
        let first = r.read(&mut header[..1]).await?;
        if first == 0 {
            return if fragment == 0 {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        r.read_exact(&mut header[1..]).await?;
        let header = u32::from_be_bytes(header);
        let len = (header & 0x7fffffff) as usize;
        if len > MAX_RECORD - out.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RPC record exceeds 4 MiB",
            ));
        }
        let start = out.len();
        out.resize(start + len, 0);
        r.read_exact(&mut out[start..]).await?;
        if header & 0x80000000 != 0 {
            return Ok(Some(out));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "too many RPC fragments",
    ))
}
pub async fn write_record<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_RECORD {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    w.write_all(&(0x80000000 | bytes.len() as u32).to_be_bytes())
        .await?;
    w.write_all(bytes).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_xdr() {
        let mut w = Encoder::default();
        w.u64(u64::MAX);
        w.string("abc");
        w.boolean(true);
        let mut r = Decoder::new(&w.0);
        assert_eq!(r.u64(), Ok(u64::MAX));
        assert_eq!(r.string(3).unwrap(), "abc");
        assert_eq!(r.boolean(), Ok(true));
        assert_eq!(r.finish(), Ok(()));
        assert!(Decoder::new(&[0xff; 4]).opaque(32).is_err());
        assert!(Decoder::new(&[0, 0, 0, 2]).boolean().is_err());
        assert!(Decoder::new(&[0, 0, 0, 1, 255, 0, 0, 0]).string(1).is_err());
    }
    #[tokio::test]
    async fn fragments_and_truncation() {
        let bytes = [0, 0, 0, 2, 1, 2, 128, 0, 0, 1, 3];
        assert_eq!(
            read_record(&mut &bytes[..]).await.unwrap(),
            Some(vec![1, 2, 3])
        );
        assert!(read_record(&mut &bytes[..9]).await.is_err());
        assert_eq!(read_record(&mut &b""[..]).await.unwrap(), None);
        assert!(
            read_record(&mut &[0xff, 0xff, 0xff, 0xff][..])
                .await
                .is_err()
        );
    }
}
