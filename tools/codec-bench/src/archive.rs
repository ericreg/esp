//! Small bounded benchmark corpus format. JSON metadata followed by length-prefixed
//! codec packets; no platform endian assumptions, no external media tools required.
use crate::{Request, codecs::Packet};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub schema: u32,
    pub fixture: u32,
    pub encoder_assembly: bool,
    pub request: Request,
}
pub fn save(path: &Path, req: &Request, packets: &[(Packet, f64, usize)]) -> Result<()> {
    let mut request = req.clone();
    request.export = None;
    request.replay = None;
    let metadata = Metadata {
        schema: 1,
        fixture: 1,
        encoder_assembly: cfg!(feature = "asm"),
        request,
    };
    let header = serde_json::to_vec(&metadata)?;
    let mut file = File::create(path)?;
    file.write_all(b"ESPBEN01")?;
    file.write_all(&(header.len() as u32).to_le_bytes())?;
    file.write_all(&header)?;
    for (packet, _, _) in packets {
        file.write_all(&(packet.bytes.len() as u32).to_le_bytes())?;
        file.write_all(&[u8::from(packet.key)])?;
        file.write_all(&packet.bytes)?;
    }
    Ok(())
}
pub fn load(path: &Path) -> Result<(Metadata, Vec<Packet>)> {
    let mut file = File::open(path)?;
    ensure!(
        file.metadata()?.len() <= 257 * 1024 * 1024,
        "corpus too large"
    );
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    ensure!(&magic == b"ESPBEN01", "invalid benchmark corpus");
    let len = read_len(&mut file)?;
    ensure!(len <= 65536, "metadata too large");
    let mut header = vec![0; len];
    file.read_exact(&mut header)?;
    let meta: Metadata = serde_json::from_slice(&header)?;
    ensure!(
        meta.schema == 1 && meta.fixture == 1,
        "unsupported corpus/fixture version"
    );
    ensure!(
        (1..=600).contains(&meta.request.frames),
        "invalid corpus frame count"
    );
    let s = &meta.request.settings;
    crate::parse_size(&format!("{}x{}", s.width, s.height))?;
    ensure!(
        ["vp8", "av1"].contains(&meta.request.codec.as_str()),
        "invalid corpus codec"
    );
    ensure!(
        crate::frames::WORKLOADS.contains(&meta.request.workload.as_str()),
        "invalid corpus workload"
    );
    ensure!((1..=240).contains(&s.fps), "invalid corpus fps");
    let mut packets = vec![];
    let mut total = 0;
    for index in 0..meta.request.frames {
        let len = read_len(&mut file)?;
        total += len;
        ensure!(len > 0 && total <= 256 * 1024 * 1024, "invalid packet size");
        let mut key = [0];
        file.read_exact(&mut key)?;
        ensure!(key[0] <= 1, "invalid packet flag");
        let mut bytes = vec![0; len];
        file.read_exact(&mut bytes)?;
        packets.push(Packet {
            index,
            bytes,
            key: key[0] == 1,
        });
    }
    let mut extra = [0];
    ensure!(file.read(&mut extra)? == 0, "trailing corpus data");
    Ok((meta, packets))
}
fn read_len(file: &mut File) -> Result<usize> {
    let mut bytes = [0; 4];
    file.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as usize)
}
