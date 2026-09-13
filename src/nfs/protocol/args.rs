//! NFSv4.1/4.2 argument decoding, following RFC 7863's XDR definitions.
use super::super::xdr::{BadXdr, Decoder, MAX_IO, Result};

#[derive(Clone, Debug, Default)]
pub struct Attrs {
    pub mask: Vec<u32>,
    pub values: Vec<u8>,
}
impl Attrs {
    pub fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self {
            mask: d.bitmap()?,
            values: d.opaque(65536)?.to_vec(),
        })
    }
}
#[derive(Clone, Debug)]
pub struct Owner {
    pub client: u64,
    pub owner: Vec<u8>,
}
fn owner(d: &mut Decoder<'_>) -> Result<Owner> {
    Ok(Owner {
        client: d.u64()?,
        owner: d.opaque(1024)?.to_vec(),
    })
}
fn state(d: &mut Decoder<'_>) -> Result<[u8; 16]> {
    d.fixed(16)?.try_into().map_err(|_| BadXdr)
}
#[derive(Clone, Debug)]
pub struct Channel(pub [u32; 6]);
fn channel(d: &mut Decoder<'_>) -> Result<Channel> {
    let mut fields = [0; 6];
    for f in &mut fields {
        *f = d.u32()?;
    }
    let n = d.u32()?;
    if n > 1 {
        return Err(BadXdr);
    }
    if n == 1 {
        d.u32()?;
    }
    Ok(Channel(fields))
}
#[derive(Clone, Debug)]
pub enum Arg {
    None,
    U32(u32),
    U64(u64),
    Bool(bool),
    Name(String),
    Fh(Vec<u8>),
    Bitmap(Vec<u32>),
    Attrs(Attrs),
    State([u8; 16]),
    Close([u8; 16]),
    Commit,
    Create {
        kind: u32,
        target: Option<String>,
        name: String,
        attrs: Attrs,
    },
    Open {
        access: u32,
        deny: u32,
        owner: Owner,
        create: Option<(u32, Option<[u8; 8]>, Attrs)>,
        claim: u32,
        name: Option<String>,
    },
    Downgrade {
        state: [u8; 16],
        access: u32,
        deny: u32,
    },
    Read {
        state: [u8; 16],
        offset: u64,
        count: u32,
    },
    Write {
        state: [u8; 16],
        offset: u64,
        stable: u32,
        bytes: Vec<u8>,
    },
    Readdir {
        cookie: u64,
        verifier: [u8; 8],
        max: u32,
        attrs: Vec<u32>,
    },
    Rename(String, String),
    Setattr([u8; 16], Attrs),
    Exchange {
        verifier: [u8; 8],
        owner: Vec<u8>,
        flags: u32,
        protect: u32,
    },
    CreateSession {
        client: u64,
        seq: u32,
        flags: u32,
        fore: Channel,
        back: Channel,
    },
    Sequence {
        session: [u8; 16],
        seq: u32,
        slot: u32,
        highest: u32,
        cache: bool,
    },
    Bind {
        session: [u8; 16],
        direction: u32,
        rdma: bool,
    },
    Test(Vec<[u8; 16]>),
    Lock {
        kind: u32,
        reclaim: bool,
        offset: u64,
        length: u64,
        state: [u8; 16],
        owner: Option<Owner>,
    },
    LockTest {
        kind: u32,
        offset: u64,
        length: u64,
        owner: Owner,
    },
    Unlock {
        kind: u32,
        state: [u8; 16],
        offset: u64,
        length: u64,
    },
    Unsupported,
}
#[derive(Clone, Debug)]
pub struct Op {
    pub code: u32,
    pub arg: Arg,
}
pub fn operation(d: &mut Decoder<'_>) -> Result<Op> {
    let code = d.u32()?;
    let arg = match code {
        3 => Arg::U32(d.u32()?),
        4 => {
            d.u32()?;
            Arg::Close(state(d)?)
        }
        5 => {
            d.u64()?;
            d.u32()?;
            Arg::Commit
        }
        6 => {
            let kind = d.u32()?;
            let target = match kind {
                5 => Some(d.string(4096)?),
                3 | 4 => {
                    d.u32()?;
                    d.u32()?;
                    None
                }
                _ => None,
            };
            Arg::Create {
                kind,
                target,
                name: d.string(255)?,
                attrs: Attrs::decode(d)?,
            }
        }
        9 => Arg::Bitmap(d.bitmap()?),
        10 | 16 | 23 | 24 | 31 | 32 => Arg::None,
        11 | 15 | 27 | 28 | 33 => {
            if code == 27 {
                Arg::None
            } else {
                Arg::Name(d.string(255)?)
            }
        }
        12 => {
            let kind = d.u32()?;
            let reclaim = d.boolean()?;
            let offset = d.u64()?;
            let length = d.u64()?;
            let new = d.boolean()?;
            let (s, owner) = if new {
                d.u32()?;
                let s = state(d)?;
                d.u32()?;
                (s, Some(owner(d)?))
            } else {
                let s = state(d)?;
                d.u32()?;
                (s, None)
            };
            Arg::Lock {
                kind,
                reclaim,
                offset,
                length,
                state: s,
                owner,
            }
        }
        13 => Arg::LockTest {
            kind: d.u32()?,
            offset: d.u64()?,
            length: d.u64()?,
            owner: owner(d)?,
        },
        14 => {
            let kind = d.u32()?;
            d.u32()?;
            Arg::Unlock {
                kind,
                state: state(d)?,
                offset: d.u64()?,
                length: d.u64()?,
            }
        }
        17 | 37 => Arg::Attrs(Attrs::decode(d)?),
        18 => {
            d.u32()?;
            let access = d.u32()?;
            let deny = d.u32()?;
            let owner = owner(d)?;
            let create = match d.u32()? {
                0 => None,
                1 => {
                    let mode = d.u32()?;
                    let verifier = match mode {
                        2 | 3 => Some(d.fixed(8)?.try_into().map_err(|_| BadXdr)?),
                        0 | 1 => None,
                        _ => return Err(BadXdr),
                    };
                    let attrs = if mode == 2 {
                        Attrs::default()
                    } else {
                        Attrs::decode(d)?
                    };
                    Some((mode, verifier, attrs))
                }
                _ => return Err(BadXdr),
            };
            let claim = d.u32()?;
            let name = match claim {
                0 | 3 => Some(d.string(255)?),
                1 => {
                    d.u32()?;
                    None
                }
                2 => {
                    state(d)?;
                    Some(d.string(255)?)
                }
                4 | 6 => None,
                5 => {
                    state(d)?;
                    None
                }
                _ => return Err(BadXdr),
            };
            Arg::Open {
                access,
                deny,
                owner,
                create,
                claim,
                name,
            }
        }
        19 => Arg::Bool(d.boolean()?),
        21 => {
            let state = state(d)?;
            d.u32()?;
            Arg::Downgrade {
                state,
                access: d.u32()?,
                deny: d.u32()?,
            }
        }
        22 => Arg::Fh(d.opaque(128)?.to_vec()),
        25 => Arg::Read {
            state: state(d)?,
            offset: d.u64()?,
            count: d.u32()?,
        },
        26 => {
            let cookie = d.u64()?;
            let verifier = d.fixed(8)?.try_into().map_err(|_| BadXdr)?;
            d.u32()?;
            Arg::Readdir {
                cookie,
                verifier,
                max: d.u32()?,
                attrs: d.bitmap()?,
            }
        }
        29 => Arg::Rename(d.string(255)?, d.string(255)?),
        34 => Arg::Setattr(state(d)?, Attrs::decode(d)?),
        38 => Arg::Write {
            state: state(d)?,
            offset: d.u64()?,
            stable: d.u32()?,
            bytes: d.opaque(MAX_IO)?.to_vec(),
        },
        41 => Arg::Bind {
            session: state(d)?,
            direction: d.u32()?,
            rdma: d.boolean()?,
        },
        42 => {
            let verifier = d.fixed(8)?.try_into().map_err(|_| BadXdr)?;
            let owner = d.opaque(1024)?.to_vec();
            let flags = d.u32()?;
            let protect = d.u32()?;
            if protect != 0 {
                return Ok(Op {
                    code,
                    arg: Arg::Unsupported,
                });
            }
            let n = d.u32()?;
            if n > 1 {
                return Err(BadXdr);
            };
            for _ in 0..n {
                d.string(1024)?;
                d.string(1024)?;
                d.u64()?;
                d.u32()?;
            }
            Arg::Exchange {
                verifier,
                owner,
                flags,
                protect,
            }
        }
        43 => {
            let client = d.u64()?;
            let seq = d.u32()?;
            let flags = d.u32()?;
            let fore = channel(d)?;
            let back = channel(d)?;
            d.u32()?;
            let n = d.u32()?;
            if n > 8 {
                return Err(BadXdr);
            };
            for _ in 0..n {
                match d.u32()? {
                    0 => {}
                    1 => {
                        d.u32()?;
                        d.string(255)?;
                        d.u32()?;
                        d.u32()?;
                        let groups = d.u32()?;
                        if groups > 16 {
                            return Err(BadXdr);
                        };
                        for _ in 0..groups {
                            d.u32()?;
                        }
                    }
                    6 => {
                        d.u32()?;
                        d.opaque(1024)?;
                        d.opaque(1024)?;
                    }
                    _ => return Err(BadXdr),
                }
            }
            Arg::CreateSession {
                client,
                seq,
                flags,
                fore,
                back,
            }
        }
        44 | 45 | 8 => Arg::State(state(d)?),
        52 => Arg::U32(d.u32()?),
        53 => Arg::Sequence {
            session: state(d)?,
            seq: d.u32()?,
            slot: d.u32()?,
            highest: d.u32()?,
            cache: d.boolean()?,
        },
        55 => {
            let n = d.u32()?;
            if n > 256 {
                return Err(BadXdr);
            };
            Arg::Test((0..n).map(|_| state(d)).collect::<Result<_>>()?)
        }
        57 => Arg::U64(d.u64()?),
        58 => Arg::Bool(d.boolean()?),
        _ => Arg::Unsupported,
    };
    Ok(Op { code, arg })
}
