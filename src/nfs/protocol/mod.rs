//! NFSv4.1/4.2 over ONC RPC. Definitions follow RFCs 5531, 8881 and 7863.
//! Sessions are scoped to the authenticated ESP peer + mount identity.
mod args;
#[cfg(test)]
mod tests;
use super::{
    filesystem::{Backend, Id, NResult, change, status},
    xdr::{self, Decoder, Encoder, MAX_IO, MAX_OPS, MAX_RECORD},
};
use anyhow::{Result, bail};
use args::{Arg, Attrs, Op};
use cap_std::fs::MetadataExt;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const LEASE: Duration = Duration::from_secs(90);
const MAX_CLIENTS: usize = 64;
const MAX_SESSIONS: usize = 16;
const MAX_STATES: usize = 4096;
const SLOTS: usize = 8;
const CACHE: usize = 65536;
const ATTRIBUTES: &[u32] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 26, 27, 28, 29,
    30, 31, 33, 34, 35, 36, 37, 41, 42, 43, 44, 45, 47, 48, 50, 51, 52, 53, 54, 55, 75,
];

pub struct Server {
    inner: std::sync::Arc<Mutex<ServerState>>,
    maintenance: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.maintenance.abort();
    }
}
struct ServerState {
    fs: Backend,
    clients: HashMap<u64, Client>,
    sessions: HashMap<Id, Session>,
    opens: HashMap<[u8; 12], OpenState>,
    locks: HashMap<[u8; 12], LockState>,
    recovery: HashMap<Vec<u8>, Vec<u8>>,
    lock_recovery: HashMap<Vec<u8>, Vec<u8>>,
    grace_until: Instant,
}
struct Client {
    principal: String,
    owner: Vec<u8>,
    verifier: [u8; 8],
    last: Instant,
    seq: u32,
    create_cache: Option<([u8; 32], Encoder)>,
    reclaimed: bool,
}
struct Session {
    client: u64,
    slots: Vec<Slot>,
    max_request: usize,
    max_response: usize,
    max_cached: usize,
    max_ops: usize,
}
#[derive(Default)]
struct Slot {
    seq: u32,
    hash: Option<[u8; 32]>,
    response: Option<Vec<u8>>,
}
#[derive(Clone)]
struct OpenState {
    file: Id,
    client: u64,
    owner: Vec<u8>,
    access: u32,
    deny: u32,
    seq: u32,
    recovery: Vec<u8>,
    _descriptor: std::sync::Arc<std::fs::File>,
}
#[derive(Clone)]
struct LockState {
    open: [u8; 12],
    owner: Vec<u8>,
    seq: u32,
    ranges: Vec<Range>,
    file: std::sync::Arc<std::fs::File>,
}
#[derive(Clone)]
struct Range {
    start: u64,
    end: u64,
    write: bool,
}
struct Context<'a> {
    principal: &'a str,
    uid: u32,
    gid: u32,
    writable: bool,
    client: Option<u64>,
    current: Option<Id>,
    saved: Option<Id>,
    current_state: Option<[u8; 16]>,
    error_body: Encoder,
}
impl Context<'_> {
    fn file(&self) -> NResult<Id> {
        self.current.ok_or(10020)
    }
    fn write(&self) -> NResult<()> {
        if self.writable { Ok(()) } else { Err(30) }
    }
}

impl Server {
    pub async fn open(directory: &Path, state: &Path) -> Result<Self> {
        let fs = Backend::open(directory, state).await?;
        let recovery = fs
            .store
            .list("open")
            .await?
            .into_iter()
            .collect::<HashMap<_, _>>();
        let lock_recovery = fs.store.list("lock").await?.into_iter().collect();
        let grace_until = Instant::now()
            + if recovery.is_empty() {
                Duration::ZERO
            } else {
                LEASE
            };
        let inner = std::sync::Arc::new(Mutex::new(ServerState {
            fs,
            clients: HashMap::new(),
            sessions: HashMap::new(),
            opens: HashMap::new(),
            locks: HashMap::new(),
            recovery,
            lock_recovery,
            grace_until,
        }));
        let weak = std::sync::Arc::downgrade(&inner);
        let maintenance = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(state) = weak.upgrade() else {
                    break;
                };
                state.lock().await.expire().await;
            }
        });
        Ok(Self { inner, maintenance })
    }
    /// Handle a complete RPC record with a fixed policy for tests.
    #[cfg(test)]
    pub async fn rpc(
        &self,
        principal: &str,
        uid: u32,
        gid: u32,
        writable: bool,
        record: &[u8],
    ) -> Result<Vec<u8>> {
        self.rpc_authorized(principal, uid, gid, &|| Some(writable), record)
            .await
    }
    /// The policy is checked before every operation, including compounds that
    /// were queued before a live ACL change. None means the share was revoked.
    pub async fn rpc_authorized(
        &self,
        principal: &str,
        uid: u32,
        gid: u32,
        policy: &(impl Fn() -> Option<bool> + Sync),
        record: &[u8],
    ) -> Result<Vec<u8>> {
        let writable = policy().ok_or_else(|| anyhow::anyhow!("share access revoked"))?;
        if record.len() > MAX_RECORD {
            bail!("RPC record exceeds limit");
        }
        let mut d = Decoder::new(record);
        let xid = d
            .u32()
            .map_err(|_| anyhow::anyhow!("RPC header truncated"))?;
        let mut reply = Encoder::default();
        reply.u32(xid);
        reply.u32(1);
        reply.u32(0);
        reply.u32(0);
        reply.opaque(&[]);
        let decoded = (|| -> xdr::Result<(u32, u32, u32, u32, Option<u32>)> {
            if d.u32()? != 0 || d.u32()? != 2 {
                return Err(xdr::BadXdr);
            }
            let program = d.u32()?;
            let version = d.u32()?;
            let procedure = d.u32()?;
            let flavor = d.u32()?;
            let auth = d.opaque(400)?;
            let mut caller = None;
            if flavor == 1 {
                let mut a = Decoder::new(auth);
                a.u32()?;
                a.string(255)?;
                caller = Some(a.u32()?);
                a.u32()?;
                let groups = a.u32()?;
                if groups > 16 {
                    return Err(xdr::BadXdr);
                }
                for _ in 0..groups {
                    a.u32()?;
                }
                a.finish()?;
            }
            d.u32()?;
            d.opaque(400)?;
            Ok((program, version, procedure, flavor, caller))
        })();
        let (program, version, procedure, flavor, caller) = match decoded {
            Ok(v) => v,
            Err(_) => {
                reply.u32(4);
                return Ok(reply.0);
            }
        };
        if program != 100003 {
            reply.u32(1);
            return Ok(reply.0);
        }
        if version != 4 {
            reply.u32(2);
            reply.u32(4);
            reply.u32(4);
            return Ok(reply.0);
        }
        if procedure == 0 {
            reply.u32(0);
            return Ok(reply.0);
        }
        if procedure != 1 {
            reply.u32(3);
            return Ok(reply.0);
        }
        if flavor != 1 || caller.is_none_or(|caller| caller != 0 && caller != uid) {
            // The loopback bridge only accepts privileged source ports. The
            // kernel supplies AUTH_SYS for each local caller; do not let other
            // local users inherit this mount's ESP identity.
            let mut denied = Encoder::default();
            for value in [xid, 1, 1, 1, 5] {
                denied.u32(value);
            }
            return Ok(denied.0);
        }
        let decoded = (|| -> xdr::Result<(String, u32, Vec<Op>)> {
            let tag = d.string(1024)?;
            let minor = d.u32()?;
            let n = d.u32()? as usize;
            if n > MAX_OPS {
                return Err(xdr::BadXdr);
            }
            let mut ops = Vec::new();
            for _ in 0..n {
                let op = args::operation(&mut d)?;
                let unsupported = matches!(op.arg, Arg::Unsupported);
                ops.push(op);
                if unsupported {
                    return Ok((tag, minor, ops));
                }
            }
            d.finish()?;
            Ok((tag, minor, ops))
        })();
        let (tag, minor, ops) = match decoded {
            Ok(v) => v,
            Err(_) => {
                reply.u32(4);
                return Ok(reply.0);
            }
        };
        reply.u32(0);
        if minor != 1 && minor != 2 {
            reply.fixed(&compound(10021, &tag, 0, &[]));
            return Ok(reply.0);
        }
        let mut state = self.inner.lock().await;
        state
            .fs
            .reconcile_changes()
            .await
            .map_err(|s| anyhow::anyhow!("export reconciliation failed: NFS status {s}"))?;
        state.expire().await;
        if policy().is_none() {
            bail!("share access revoked");
        }
        let hash: [u8; 32] = Sha256::digest(&record[4..]).into();
        let mut ctx = Context {
            principal,
            uid,
            gid,
            writable,
            client: None,
            current: None,
            saved: None,
            current_state: None,
            error_body: Encoder::default(),
        };
        let mut slot_key = None;
        if let Some(op) = ops.first() {
            if let Arg::Sequence {
                session,
                seq,
                slot,
                highest,
                cache,
            } = &op.arg
            {
                let validation = (|| -> NResult<Option<Vec<u8>>> {
                    let session_data = state.sessions.get(session).ok_or(10052u32)?;
                    let client = state.clients.get(&session_data.client).ok_or(10022u32)?;
                    if client.principal != principal {
                        return Err(10082);
                    }
                    if record.len() > session_data.max_request {
                        return Err(10065);
                    }
                    if ops.len() > session_data.max_ops {
                        return Err(10070);
                    }
                    let data = session_data.slots.get(*slot as usize).ok_or(10053u32)?;
                    if *highest < *slot {
                        return Err(10077);
                    }
                    if data.hash.is_some() && data.seq == *seq {
                        if data.hash != Some(hash) {
                            return Err(10076);
                        }
                        return data.response.clone().map(Some).ok_or(10068);
                    }
                    if *seq != data.seq.wrapping_add(1) {
                        return Err(10063);
                    }
                    ctx.client = Some(session_data.client);
                    slot_key = Some((*session, *slot as usize, *seq, *cache));
                    Ok(None)
                })();
                match validation {
                    Ok(Some(bytes)) => {
                        reply.fixed(&bytes);
                        return Ok(reply.0);
                    }
                    Err(e) => {
                        let mut op = Encoder::default();
                        op.u32(53);
                        op.u32(e);
                        reply.fixed(&compound(e, &tag, 1, &op.0));
                        return Ok(reply.0);
                    }
                    _ => {}
                }
                if let Some(client) = ctx.client {
                    state.clients.get_mut(&client).unwrap().last = Instant::now();
                }
            } else if !matches!(op.code, 41 | 42 | 43 | 44 | 57) {
                let mut response = Encoder::default();
                response.u32(op.code);
                response.u32(10071);
                reply.fixed(&compound(10071, &tag, 1, &response.0));
                return Ok(reply.0);
            } else if ops.len() != 1 {
                let mut response = Encoder::default();
                response.u32(op.code);
                response.u32(10081);
                reply.fixed(&compound(10081, &tag, 1, &response.0));
                return Ok(reply.0);
            }
        }
        let max_response = slot_key
            .and_then(|(id, _, _, _)| state.sessions.get(&id).map(|s| s.max_response))
            .unwrap_or(MAX_RECORD);
        let max_cached = slot_key
            .and_then(|(id, _, _, _)| state.sessions.get(&id).map(|s| s.max_cached))
            .unwrap_or(CACHE);
        let caching = slot_key.is_some_and(|(_, _, _, cache)| cache);
        let limit = if caching {
            max_response.min(max_cached)
        } else {
            max_response
        };
        let mut results = Encoder::default();
        let mut status_code = 0;
        let mut count = 0;
        for (i, op) in ops.iter().enumerate() {
            // Reserve enough room before executing an operation with a large
            // result. Mutations never execute unless their reply can be held.
            let need = match &op.arg {
                Arg::Read { count, .. } => ((*count as usize).min(MAX_IO)) + 64,
                Arg::Readdir { max, .. } => (*max as usize).min(MAX_IO) + 32,
                Arg::Test(ids) => 12 + 4 * ids.len(),
                _ => match op.code {
                    18 => 80,
                    6 | 29 => 56,
                    53 => 44,
                    9 => 1024,
                    27 => 4108,
                    12 | 13 => 1064,
                    10 => 28,
                    4 | 14 | 21 | 38 | 41 => 32,
                    11 | 28 => 28,
                    3 | 5 | 33 | 34 | 52 => 24,
                    42 | 43 => 256,
                    _ => 8,
                },
            };
            let result = if let Some(writable) = policy() {
                ctx.writable = writable;
                if results.0.len() + ((tag.len() + 3) & !3) + 36 + need > limit {
                    Err(if caching { 10067 } else { 10066 })
                } else if op.code == 53 && i != 0 {
                    Err(10064)
                } else {
                    state.operation(op, &mut ctx, hash).await
                }
            } else {
                Err(13)
            };
            let code = if !(3..=71).contains(&op.code) {
                10044
            } else {
                op.code
            };
            results.u32(code);
            count += 1;
            match result {
                Ok(body) => {
                    results.u32(0);
                    results.fixed(&body.0)
                }
                Err(e) => {
                    results.u32(e);
                    results.fixed(&ctx.error_body.0);
                    if op.code == 34 && ctx.error_body.0.is_empty() {
                        results.bitmap(&[]);
                    }
                    status_code = e;
                    break;
                }
            }
        }
        let result = compound(status_code, &tag, count, &results.0);
        if let Some((id, slot, seq, cache)) = slot_key
            && let Some(session) = state.sessions.get_mut(&id)
        {
            let entry = &mut session.slots[slot];
            entry.seq = seq;
            entry.hash = Some(hash);
            entry.response = cache.then(|| result.clone());
        }
        reply.fixed(&result);
        Ok(reply.0)
    }
}
fn compound(status: u32, tag: &str, count: u32, ops: &[u8]) -> Vec<u8> {
    let mut e = Encoder::default();
    e.u32(status);
    e.string(tag);
    e.u32(count);
    e.fixed(ops);
    e.0
}
fn stateid(key: [u8; 12], seq: u32) -> [u8; 16] {
    let mut id = [0; 16];
    id[..4].copy_from_slice(&seq.to_be_bytes());
    id[4..].copy_from_slice(&key);
    id
}
fn change_info(e: &mut Encoder, before: u64, after: u64) {
    e.boolean(false);
    e.u64(before);
    e.u64(after);
}
fn channel(e: &mut Encoder, fields: &[u32; 6]) {
    for v in fields {
        e.u32(*v)
    }
    e.u32(0)
}
fn fileid(id: Id) -> u64 {
    u64::from_be_bytes(id[..8].try_into().unwrap())
}

impl ServerState {
    async fn lock_operation(&mut self, op: &Op, ctx: &mut Context<'_>) -> NResult<Encoder> {
        use std::os::fd::AsRawFd;
        let mut e = Encoder::default();
        let (kind, offset, length) = match &op.arg {
            Arg::Lock {
                kind,
                offset,
                length,
                ..
            }
            | Arg::LockTest {
                kind,
                offset,
                length,
                ..
            }
            | Arg::Unlock {
                kind,
                offset,
                length,
                ..
            } => (*kind, *offset, *length),
            _ => return Err(22),
        };
        if !(1..=4).contains(&kind) || length == 0 || offset > i64::MAX as u64 {
            return Err(10042);
        }
        let end = if length == u64::MAX {
            u64::MAX
        } else {
            offset.checked_add(length - 1).ok_or(10042u32)?
        };
        if end != u64::MAX && end > i64::MAX as u64 {
            return Err(10042);
        }
        let write = kind == 2 || kind == 4;
        if write && op.code != 14 {
            ctx.write()?;
        }
        let file = ctx.file()?;
        let (key, open_key, owner, reclaim) = match &op.arg {
            Arg::Lock {
                state,
                owner,
                reclaim,
                ..
            } => {
                let open = self
                    .open_key(*state, ctx, if write { 2 } else { 1 })?
                    .ok_or(10025u32)?;
                if let Some(owner) = owner {
                    if Some(owner.client) != ctx.client {
                        return Err(10022);
                    }
                    let existing = self
                        .locks
                        .iter()
                        .find(|(_, l)| l.open == open && l.owner == owner.owner)
                        .map(|(k, _)| *k);
                    (
                        existing.unwrap_or_else(|| {
                            uuid::Uuid::new_v4().as_bytes()[4..].try_into().unwrap()
                        }),
                        Some(open),
                        owner.owner.clone(),
                        *reclaim,
                    )
                } else {
                    let key: [u8; 12] = state[4..].try_into().unwrap();
                    let l = self.locks.get(&key).ok_or(10025u32)?;
                    (key, Some(open), l.owner.clone(), *reclaim)
                }
            }
            Arg::Unlock { state, .. } => {
                let open = self.open_key(*state, ctx, 0)?.ok_or(10025u32)?;
                let key = state[4..].try_into().unwrap();
                let l = self.locks.get(&key).ok_or(10025u32)?;
                (key, Some(open), l.owner.clone(), false)
            }
            Arg::LockTest { owner, .. } => {
                if Some(owner.client) != ctx.client {
                    return Err(10022);
                }
                ([0; 12], None, owner.owner.clone(), false)
            }
            _ => return Err(22),
        };
        if self.grace() && op.code != 14 && !reclaim {
            return Err(10013);
        }
        if reclaim && !self.grace() {
            return Err(10033);
        }
        if reclaim {
            let mut recovery_key = self.opens[&open_key.ok_or(10025u32)?].recovery.clone();
            let mut owner_key = Encoder::default();
            owner_key.opaque(&owner);
            recovery_key.extend(owner_key.0);
            let bytes = self.lock_recovery.get(&recovery_key).ok_or(10034u32)?;
            let mut d = Decoder::new(bytes);
            let count = d.u32().map_err(|_| 5u32)?;
            let mut covered = false;
            for _ in 0..count {
                let start = d.u64().map_err(|_| 5u32)?;
                let last = d.u64().map_err(|_| 5u32)?;
                let was_write = d.boolean().map_err(|_| 5u32)?;
                covered |= start <= offset && last >= end && was_write == write;
            }
            if !covered {
                return Err(10034);
            }
        }
        if op.code != 14 {
            for l in self.locks.values() {
                let o = self.opens.get(&l.open).ok_or(10025u32)?;
                if o.file == file
                    && (Some(o.client) != ctx.client || l.owner != owner)
                    && let Some(r) = l
                        .ranges
                        .iter()
                        .find(|r| r.start <= end && offset <= r.end && (write || r.write))
                {
                    ctx.error_body.u64(r.start);
                    ctx.error_body.u64(if r.end == u64::MAX {
                        u64::MAX
                    } else {
                        r.end - r.start + 1
                    });
                    ctx.error_body.u32(if r.write { 2 } else { 1 });
                    ctx.error_body.u64(o.client);
                    ctx.error_body.opaque(&l.owner);
                    return Err(10010);
                }
            }
        }
        if self.locks.len() >= MAX_STATES && !self.locks.contains_key(&key) && op.code == 12 {
            return Err(10018);
        }
        let own_lock = if op.code == 13 {
            self.locks.values().find(|l| {
                l.owner == owner
                    && self
                        .opens
                        .get(&l.open)
                        .is_some_and(|o| o.file == file && Some(o.client) == ctx.client)
            })
        } else {
            self.locks.get(&key)
        };
        let fd = if let Some(l) = own_lock {
            l.file.clone()
        } else {
            let access = open_key
                .and_then(|key| self.opens.get(&key))
                .map_or(if write { 2 } else { 1 }, |o| o.access);
            self.fs.pin(file, access).await?
        };
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = if op.code == 14 {
            libc::F_UNLCK as _
        } else if write {
            libc::F_WRLCK as _
        } else {
            libc::F_RDLCK as _
        };
        lock.l_whence = libc::SEEK_SET as _;
        lock.l_start = offset as _;
        lock.l_len = if end == u64::MAX {
            0
        } else {
            (end - offset + 1) as _
        };
        let command = if op.code == 13 {
            libc::F_OFD_GETLK
        } else {
            libc::F_OFD_SETLK
        };
        // No blocking fcntl: blocking NFS lock requests are retried by clients.
        let rc = unsafe { libc::fcntl(fd.as_raw_fd(), command, &mut lock) };
        if rc < 0 || op.code == 13 && lock.l_type != libc::F_UNLCK as i16 {
            let error = std::io::Error::last_os_error();
            if rc < 0 && !matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EACCES)) {
                return Err(status(error));
            }
            ctx.error_body.u64(offset);
            ctx.error_body.u64(length);
            ctx.error_body.u32(kind);
            ctx.error_body.u64(0);
            ctx.error_body.opaque(&[]);
            return Err(10010);
        }
        if op.code == 13 {
            return Ok(e);
        }
        let open = open_key.ok_or(10025u32)?;
        let l = self.locks.entry(key).or_insert(LockState {
            open,
            owner,
            seq: 0,
            ranges: Vec::new(),
            file: fd,
        });
        let mut ranges = Vec::new();
        for r in &l.ranges {
            if r.end < offset || r.start > end {
                ranges.push(r.clone());
                continue;
            }
            if r.start < offset {
                ranges.push(Range {
                    start: r.start,
                    end: offset - 1,
                    write: r.write,
                })
            }
            if r.end > end {
                ranges.push(Range {
                    start: end + 1,
                    end: r.end,
                    write: r.write,
                })
            }
        }
        if op.code == 12 {
            ranges.push(Range {
                start: offset,
                end,
                write,
            })
        }
        l.ranges = ranges;
        l.seq = l.seq.wrapping_add(1);
        let mut storage_key = self.opens[&open].recovery.clone();
        let mut encoded = Encoder::default();
        encoded.opaque(&l.owner);
        storage_key.extend(encoded.0);
        let mut data = Encoder::default();
        data.u32(l.ranges.len() as u32);
        for r in &l.ranges {
            data.u64(r.start);
            data.u64(r.end);
            data.boolean(r.write)
        }
        self.fs
            .store
            .put("lock", &storage_key, &data.0)
            .await
            .map_err(|_| 5u32)?;
        e.fixed(&stateid(key, l.seq));
        Ok(e)
    }
    async fn expire(&mut self) {
        if !self.grace() && !self.recovery.is_empty() {
            let active: HashSet<_> = self.opens.values().map(|s| s.recovery.clone()).collect();
            for key in self.recovery.keys() {
                if !active.contains(key) {
                    let _ = self.fs.store.remove("open", key).await;
                }
            }
            self.recovery.clear();
            self.lock_recovery.clear();
        }
        let expired = self
            .clients
            .iter()
            .filter(|(_, c)| c.last.elapsed() > LEASE)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in expired {
            self.clients.remove(&id);
            self.sessions.retain(|_, s| s.client != id);
            let keys = self
                .opens
                .iter()
                .filter(|(_, s)| s.client == id)
                .map(|(key, _)| *key)
                .collect::<Vec<_>>();
            for key in keys {
                if let Some(s) = self.opens.remove(&key) {
                    let _ = self.fs.store.remove("open", &s.recovery).await;
                    self.remove_lock_records(&s.recovery).await;
                }
                self.locks.retain(|_, l| l.open != key);
            }
        }
    }
    async fn remove_lock_records(&self, recovery: &[u8]) {
        if let Ok(records) = self.fs.store.list("lock").await {
            for (key, _) in records {
                if key.starts_with(recovery) {
                    let _ = self.fs.store.remove("lock", &key).await;
                }
            }
        }
    }
    fn grace(&self) -> bool {
        Instant::now() < self.grace_until
    }
    fn checked_client(&self, id: u64, ctx: &Context<'_>) -> NResult<&Client> {
        let c = self.clients.get(&id).ok_or(10022u32)?;
        if c.principal != ctx.principal {
            Err(10082)
        } else {
            Ok(c)
        }
    }
    fn open_key(
        &self,
        mut state: [u8; 16],
        ctx: &Context<'_>,
        access: u32,
    ) -> NResult<Option<[u8; 12]>> {
        if state[..4] == 1u32.to_be_bytes() && state[4..] == [0; 12] {
            state = ctx.current_state.ok_or(10025u32)?;
        }
        if state == [0; 16] || (access == 1 && state == [255; 16]) {
            if self.grace() {
                return Err(10013);
            }
            if self
                .opens
                .values()
                .any(|o| Some(o.file) == ctx.current && o.deny & access != 0)
            {
                return Err(10015);
            }
            return Ok(None);
        }
        let mut key: [u8; 12] = state[4..].try_into().unwrap();
        let seq = u32::from_be_bytes(state[..4].try_into().unwrap());
        if let Some(lock) = self.locks.get(&key) {
            if seq != 0 && seq != lock.seq {
                return Err(10024);
            }
            key = lock.open;
        }
        let open = self.opens.get(&key).ok_or(10025u32)?;
        if open.client != ctx.client.ok_or(10071u32)? || Some(open.file) != ctx.current {
            return Err(10025);
        }
        if seq != 0 && seq != open.seq && !self.locks.contains_key(&state[4..]) {
            return Err(10024);
        }
        if access != 0 && open.access & access != access {
            return Err(10038);
        }
        Ok(Some(key))
    }
    fn recovery_key(&self, client: u64, owner: &[u8], file: Id) -> NResult<Vec<u8>> {
        let c = self.clients.get(&client).ok_or(10022u32)?;
        let mut e = Encoder::default();
        e.string(&c.principal);
        e.opaque(&c.owner);
        e.opaque(owner);
        e.fixed(&file);
        Ok(e.0)
    }
    async fn operation(
        &mut self,
        op: &Op,
        ctx: &mut Context<'_>,
        hash: [u8; 32],
    ) -> NResult<Encoder> {
        let mut e = Encoder::default();
        match (&op.code, &op.arg) {
            (
                42,
                Arg::Exchange {
                    verifier,
                    owner,
                    flags,
                    protect,
                },
            ) => {
                if *protect != 0 {
                    return Err(10006);
                }
                if flags & !0x40070103 != 0 {
                    return Err(22);
                }
                let old = self
                    .clients
                    .iter()
                    .find(|(_, c)| c.principal == ctx.principal && c.owner == *owner)
                    .map(|(id, c)| (*id, c.verifier));
                let confirmed = old.is_some_and(|(_, v)| v == *verifier);
                let id = if let Some((id, v)) = old {
                    if v == *verifier {
                        id
                    } else {
                        self.clients.get_mut(&id).unwrap().last =
                            Instant::now() - LEASE - Duration::from_secs(1);
                        self.expire().await;
                        u64::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap())
                    }
                } else {
                    u64::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap())
                };
                if self.clients.len() >= MAX_CLIENTS && !self.clients.contains_key(&id) {
                    return Err(10018);
                }
                self.clients.entry(id).or_insert_with(|| Client {
                    principal: ctx.principal.into(),
                    owner: owner.clone(),
                    verifier: *verifier,
                    last: Instant::now(),
                    seq: 1,
                    create_cache: None,
                    reclaimed: false,
                });
                e.u64(id);
                e.u32(self.clients[&id].seq);
                e.u32(0x10000 | if confirmed { 0x80000000 } else { 0 });
                e.u32(0);
                e.u64(u64::from_be_bytes(self.fs.epoch));
                e.opaque(&self.fs.root_id);
                e.opaque(&self.fs.root_id);
                e.u32(0);
            }
            (
                43,
                Arg::CreateSession {
                    client,
                    seq,
                    flags,
                    fore,
                    back,
                },
            ) => {
                let c = self.checked_client(*client, ctx)?;
                if flags & !7 != 0 {
                    return Err(22);
                }
                if *seq == c.seq.wrapping_sub(1)
                    && let Some((old, response)) = &c.create_cache
                {
                    if *old == hash {
                        return Ok(response.clone());
                    }
                    return Err(10076);
                }
                if *seq != c.seq {
                    return Err(10063);
                }
                if self.sessions.len() >= MAX_SESSIONS {
                    return Err(10018);
                }
                if fore.0[1] < 1024 || fore.0[2] < 1024 || fore.0[4] < 2 || fore.0[5] == 0 {
                    return Err(10005);
                }
                let request = (fore.0[1] as usize).min(MAX_RECORD);
                let response = (fore.0[2] as usize).min(MAX_RECORD);
                let cached = (fore.0[3] as usize).min(CACHE);
                let slots = (fore.0[5] as usize).min(SLOTS);
                let id = *uuid::Uuid::new_v4().as_bytes();
                self.sessions.insert(
                    id,
                    Session {
                        client: *client,
                        slots: (0..slots).map(|_| Slot::default()).collect(),
                        max_request: request,
                        max_response: response,
                        max_cached: cached,
                        max_ops: (fore.0[4] as usize).min(MAX_OPS),
                    },
                );
                e.fixed(&id);
                e.u32(*seq);
                e.u32(0);
                channel(
                    &mut e,
                    &[
                        0,
                        request as u32,
                        response as u32,
                        cached as u32,
                        (fore.0[4] as usize).min(MAX_OPS) as u32,
                        slots as u32,
                    ],
                );
                channel(
                    &mut e,
                    &[0, back.0[1].min(4096), back.0[2].min(4096), 0, 2, 1],
                );
                let c = self.clients.get_mut(client).unwrap();
                c.seq = c.seq.wrapping_add(1);
                c.last = Instant::now();
                c.create_cache = Some((hash, e.clone()));
            }
            (
                53,
                Arg::Sequence {
                    session, seq, slot, ..
                },
            ) => {
                e.fixed(session);
                e.u32(*seq);
                e.u32(*slot);
                let s = self.sessions.get(session).ok_or(10052u32)?;
                e.u32(s.slots.len() as u32 - 1);
                e.u32(s.slots.len() as u32 - 1);
                e.u32(0);
            }
            (
                41,
                Arg::Bind {
                    session,
                    direction,
                    rdma,
                },
            ) => {
                let s = self.sessions.get(session).ok_or(10052u32)?;
                self.checked_client(s.client, ctx)?;
                if *rdma || !matches!(direction, 1 | 3) {
                    return Err(10004);
                }
                e.fixed(session);
                e.u32(1);
                e.boolean(false);
            }
            (44, Arg::State(id)) => {
                let s = self.sessions.get(id).ok_or(10052u32)?;
                self.checked_client(s.client, ctx)?;
                self.sessions.remove(id);
            }
            (57, Arg::U64(id)) => {
                self.checked_client(*id, ctx)?;
                if self.opens.values().any(|s| s.client == *id)
                    || self.sessions.values().any(|s| s.client == *id)
                {
                    return Err(10074);
                }
                self.clients.remove(id);
            }
            (58, Arg::Bool(one_fs)) => {
                if *one_fs {
                    ctx.file()?;
                }
                let client = self
                    .clients
                    .get_mut(&ctx.client.ok_or(10071u32)?)
                    .ok_or(10022u32)?;
                if client.reclaimed && !one_fs {
                    return Err(10054);
                }
                if !one_fs {
                    client.reclaimed = true;
                }
            }
            (23 | 24, _) => ctx.current = Some(self.fs.root_id),
            (22, Arg::Fh(bytes)) => {
                let id: Id = bytes.as_slice().try_into().map_err(|_| 10001u32)?;
                self.fs.metadata(id).await?;
                ctx.current = Some(id);
            }
            (10, _) => e.opaque(&ctx.file()?),
            (32, _) => ctx.saved = Some(ctx.file()?),
            (31, _) => ctx.current = Some(ctx.saved.ok_or(10016u32)?),
            (15, Arg::Name(name)) => ctx.current = Some(self.fs.lookup(ctx.file()?, name).await?),
            (16, _) => ctx.current = Some(self.fs.parent(ctx.file()?).await?),
            (19, Arg::Bool(_create)) => {
                ctx.current = Some(self.fs.open_attributes(ctx.file()?).await?)
            }
            (9, Arg::Bitmap(mask)) => e = self.attributes(ctx.file()?, mask, ctx).await?,
            (3, Arg::U32(requested)) => {
                let m = self.fs.metadata(ctx.file()?).await?;
                let supported = 0x3f;
                let mut access = if ctx.writable { 0x3f } else { 0x23 };
                if !m.is_dir() {
                    access &= !2;
                }
                if m.mode() & 0o111 == 0 {
                    access &= !32;
                }
                e.u32(requested & supported);
                e.u32(requested & access);
            }
            (33, Arg::Name(name)) => {
                self.fs.lookup(ctx.file()?, name).await?;
                e.u32(1);
                e.u32(1);
            }
            (52, Arg::U32(style)) => {
                if *style > 1 {
                    return Err(22);
                }
                ctx.file()?;
                e.u32(1);
                e.u32(1);
            }
            (
                18,
                Arg::Open {
                    access,
                    deny,
                    owner,
                    create,
                    claim,
                    name,
                },
            ) => {
                let client = ctx.client.ok_or(10071u32)?;
                if owner.client != client {
                    return Err(10022);
                }
                self.checked_client(client, ctx)?;
                let access = access & 3;
                if access == 0 || *deny > 3 {
                    return Err(22);
                }
                if access & 2 != 0 || create.is_some() {
                    ctx.write()?;
                }
                if self.grace() && *claim != 1 {
                    return Err(10013);
                }
                if !self.grace() && *claim == 1 {
                    return Err(10033);
                }
                if !matches!(claim, 0 | 1 | 4) {
                    return Err(10004);
                }
                if *claim == 1 && self.clients[&client].reclaimed {
                    return Err(10033);
                }
                if create.is_some() && *claim != 0 {
                    return Err(22);
                }
                // Resource and attribute validation must precede creation or
                // truncation. A failed OPEN must not overwrite existing data.
                if self.opens.len() >= MAX_STATES {
                    return Err(10018);
                }
                if let Some((_, _, attrs)) = create {
                    SetAttrs::decode(attrs)?;
                }
                let before = change(&self.fs.metadata(ctx.file()?).await?);
                let mut attrset = Vec::new();
                let file = if *claim == 0 {
                    let name = name.as_deref().ok_or(22u32)?;
                    match self.fs.lookup(ctx.file()?, name).await {
                        Ok(id) => {
                            if let Some((mode, verifier, attrs)) = create {
                                if *mode == 1 {
                                    return Err(17);
                                }
                                if let Some(v) = verifier
                                    && self
                                        .fs
                                        .store
                                        .get("exclusive", &id)
                                        .await
                                        .map_err(|_| 5u32)?
                                        .as_deref()
                                        != Some(&v[..])
                                {
                                    return Err(17);
                                }
                                if *mode == 0 {
                                    if self.opens.values().any(|o| {
                                        o.file == id
                                            && (o.client != client || o.owner != owner.owner)
                                            && (o.deny & access != 0 || o.access & deny != 0)
                                    }) {
                                        return Err(10015);
                                    }
                                    // UNCHECKED on an existing file only honors
                                    // truncation to zero, not mode/time changes.
                                    let settings = SetAttrs::decode(attrs)?;
                                    if settings.size == Some(0) {
                                        if access & 2 == 0 {
                                            return Err(10038);
                                        }
                                        self.fs.setattr(id, Some(0), None, None, None).await?;
                                    }
                                    attrset = attrs.mask.clone();
                                }
                            }
                            id
                        }
                        Err(2) => {
                            let (mode, verifier, attrs) = create.as_ref().ok_or(2u32)?;
                            let settings = SetAttrs::decode(attrs)?;
                            let id = self
                                .fs
                                .create(
                                    ctx.file()?,
                                    name,
                                    1,
                                    settings.mode.unwrap_or(0o666),
                                    None,
                                    true,
                                )
                                .await?;
                            self.set_attributes(id, attrs).await?;
                            attrset = attrs.mask.clone();
                            if *mode >= 2 {
                                self.fs
                                    .store
                                    .put("exclusive", &id, &verifier.unwrap())
                                    .await
                                    .map_err(|_| 5u32)?;
                            }
                            id
                        }
                        Err(s) => return Err(s),
                    }
                } else {
                    ctx.file()?
                };
                let previous_access = self
                    .opens
                    .values()
                    .find(|o| o.file == file && o.client == client && o.owner == owner.owner)
                    .map_or(0, |o| o.access);
                let descriptor = self.fs.pin(file, access | previous_access).await?;
                let recovery = self.recovery_key(client, &owner.owner, file)?;
                if *claim == 1 {
                    let previous = self.recovery.get(&recovery).ok_or(10034u32)?;
                    let mut d = Decoder::new(previous);
                    let previous_access = d.u32().map_err(|_| 5u32)?;
                    let previous_deny = d.u32().map_err(|_| 5u32)?;
                    if access & !previous_access != 0 || deny & !previous_deny != 0 {
                        return Err(10034);
                    }
                }
                if self.opens.values().any(|o| {
                    o.file == file
                        && (o.client != client || o.owner != owner.owner)
                        && ((o.deny & access != 0) || (o.access & deny != 0))
                }) {
                    return Err(10015);
                }
                let existing = self
                    .opens
                    .iter()
                    .find(|(_, s)| s.file == file && s.client == client && s.owner == owner.owner)
                    .map(|(k, _)| *k);
                if self.opens.len() >= MAX_STATES && existing.is_none() {
                    return Err(10018);
                }
                let key = existing
                    .unwrap_or_else(|| uuid::Uuid::new_v4().as_bytes()[4..].try_into().unwrap());
                let open = self.opens.entry(key).or_insert(OpenState {
                    file,
                    client,
                    owner: owner.owner.clone(),
                    access: 0,
                    deny: 0,
                    seq: 0,
                    recovery: recovery.clone(),
                    _descriptor: descriptor.clone(),
                });
                // Retain the open descriptor, including after a host-side
                // unlink, until CLOSE or lease expiry.
                open._descriptor = descriptor;
                open.access |= access;
                open.deny |= deny;
                open.seq = open.seq.wrapping_add(1);
                let sid = stateid(key, open.seq);
                let mut recovery_value = Encoder::default();
                recovery_value.u32(open.access);
                recovery_value.u32(open.deny);
                self.fs
                    .store
                    .put("open", &recovery, &recovery_value.0)
                    .await
                    .map_err(|_| 5u32)?;
                let after = change(&self.fs.metadata(ctx.file()?).await?);
                ctx.current = Some(file);
                ctx.current_state = Some(sid);
                e.fixed(&sid);
                change_info(&mut e, before, after);
                e.u32(4);
                e.bitmap(&attrset);
                e.u32(0);
            }
            (4, Arg::Close(sid)) => {
                let key = self.open_key(*sid, ctx, 0)?.ok_or(10025u32)?;
                if self
                    .locks
                    .values()
                    .any(|l| l.open == key && !l.ranges.is_empty())
                {
                    return Err(10037);
                }
                let o = self.opens.remove(&key).unwrap();
                self.locks.retain(|_, l| l.open != key);
                self.fs
                    .store
                    .remove("open", &o.recovery)
                    .await
                    .map_err(|_| 5u32)?;
                self.remove_lock_records(&o.recovery).await;
                e.fixed(&stateid(key, o.seq.wrapping_add(1)));
            }
            (
                21,
                Arg::Downgrade {
                    state,
                    access,
                    deny,
                },
            ) => {
                let key = self.open_key(*state, ctx, 0)?.ok_or(10025u32)?;
                let o = self.opens.get_mut(&key).unwrap();
                if *access == 0 || access & !o.access != 0 || deny & !o.deny != 0 {
                    return Err(22);
                }
                o.access = *access;
                o.deny = *deny;
                o.seq = o.seq.wrapping_add(1);
                let mut value = Encoder::default();
                value.u32(o.access);
                value.u32(o.deny);
                self.fs
                    .store
                    .put("open", &o.recovery, &value.0)
                    .await
                    .map_err(|_| 5u32)?;
                e.fixed(&stateid(key, o.seq));
            }
            (
                25,
                Arg::Read {
                    state,
                    offset,
                    count,
                },
            ) => {
                self.open_key(*state, ctx, 1)?;
                let (data, eof) = self.fs.read(ctx.file()?, *offset, *count as usize).await?;
                e.boolean(eof);
                e.opaque(&data);
            }
            (
                38,
                Arg::Write {
                    state,
                    offset,
                    stable,
                    bytes,
                },
            ) => {
                ctx.write()?;
                if *stable > 2 {
                    return Err(22);
                }
                self.open_key(*state, ctx, 2)?;
                let count = self.fs.write(ctx.file()?, *offset, bytes).await?;
                e.u32(count);
                e.u32(2);
                e.fixed(&self.fs.epoch);
            }
            (5, _) => {
                self.fs
                    .file(ctx.file()?, false)
                    .await?
                    .sync_all()
                    .map_err(status)?;
                e.fixed(&self.fs.epoch);
            }
            (
                6,
                Arg::Create {
                    kind,
                    target,
                    name,
                    attrs,
                },
            ) => {
                ctx.write()?;
                let settings = SetAttrs::decode(attrs)?;
                let before = change(&self.fs.metadata(ctx.file()?).await?);
                let file = self
                    .fs
                    .create(
                        ctx.file()?,
                        name,
                        *kind,
                        settings.mode.unwrap_or(0o755),
                        target.as_deref(),
                        true,
                    )
                    .await?;
                if *kind != 5 {
                    self.set_attributes(file, attrs).await?;
                }
                let after = change(&self.fs.metadata(ctx.file()?).await?);
                change_info(&mut e, before, after);
                e.bitmap(&attrs.mask);
                ctx.current = Some(file);
            }
            (28, Arg::Name(name)) => {
                ctx.write()?;
                let before = change(&self.fs.metadata(ctx.file()?).await?);
                self.fs.remove(ctx.file()?, name).await?;
                change_info(
                    &mut e,
                    before,
                    change(&self.fs.metadata(ctx.file()?).await?),
                );
            }
            (29, Arg::Rename(old, new)) => {
                ctx.write()?;
                let from = ctx.saved.ok_or(10016u32)?;
                let to = ctx.file()?;
                let a = change(&self.fs.metadata(from).await?);
                let b = change(&self.fs.metadata(to).await?);
                self.fs.rename(from, old, to, new).await?;
                change_info(&mut e, a, change(&self.fs.metadata(from).await?));
                change_info(&mut e, b, change(&self.fs.metadata(to).await?));
            }
            (11, Arg::Name(name)) => {
                ctx.write()?;
                let before = change(&self.fs.metadata(ctx.file()?).await?);
                self.fs
                    .link(ctx.saved.ok_or(10016u32)?, ctx.file()?, name)
                    .await?;
                change_info(
                    &mut e,
                    before,
                    change(&self.fs.metadata(ctx.file()?).await?),
                );
            }
            (27, _) => e.opaque(&self.fs.readlink(ctx.file()?).await?),
            (34, Arg::Setattr(sid, attrs)) => {
                ctx.write()?;
                if xdr::bit(&attrs.mask, 4) {
                    self.open_key(*sid, ctx, 2)?;
                }
                self.set_attributes(ctx.file()?, attrs).await?;
                e.bitmap(&attrs.mask);
            }
            (17 | 37, Arg::Attrs(attrs)) => {
                let actual = self.attributes(ctx.file()?, &attrs.mask, ctx).await?;
                let mut expected = Encoder::default();
                expected.bitmap(&attrs.mask);
                expected.opaque(&attrs.values);
                let same = actual.0 == expected.0;
                if op.code == 17 && same {
                    return Err(10009);
                }
                if op.code == 37 && !same {
                    return Err(10027);
                }
            }
            (
                26,
                Arg::Readdir {
                    cookie,
                    verifier,
                    max,
                    attrs,
                },
            ) => {
                let current = change(&self.fs.metadata(ctx.file()?).await?).to_be_bytes();
                if *cookie != 0 && *verifier != current {
                    return Err(10003);
                }
                let children = self.fs.children(ctx.file()?).await?;
                let start = usize::try_from(*cookie).map_err(|_| 10003u32)?;
                if start > children.len() {
                    return Err(10003);
                }
                let limit = (*max as usize).min(MAX_IO);
                if limit < 32 {
                    return Err(10005);
                }
                e.fixed(&current);
                let mut next = start;
                for (i, (name, id)) in children.iter().enumerate().skip(start) {
                    let mut entry = Encoder::default();
                    entry.boolean(true);
                    entry.u64((i + 1) as u64);
                    entry.string(name);
                    entry.fixed(&self.attributes(*id, attrs, ctx).await?.0);
                    if e.0.len() + entry.0.len() + 8 > limit {
                        if next == start {
                            return Err(10005);
                        }
                        break;
                    }
                    e.fixed(&entry.0);
                    next = i + 1;
                }
                e.boolean(false);
                e.boolean(next == children.len());
            }
            (12..=14, _) => return self.lock_operation(op, ctx).await,
            (55, Arg::Test(ids)) => {
                e.u32(ids.len() as u32);
                for id in ids {
                    let key: [u8; 12] = id[4..].try_into().unwrap();
                    let valid = self
                        .opens
                        .get(&key)
                        .is_some_and(|o| Some(o.client) == ctx.client)
                        || self.locks.get(&key).is_some_and(|l| {
                            self.opens
                                .get(&l.open)
                                .is_some_and(|o| Some(o.client) == ctx.client)
                        });
                    e.u32(if valid { 0 } else { 10025 });
                }
            }
            (45, Arg::State(sid)) => {
                let key: [u8; 12] = sid[4..].try_into().unwrap();
                if let Some(l) = self.locks.get(&key) {
                    if !l.ranges.is_empty() {
                        return Err(10037);
                    }
                    let o = self.opens.get(&l.open).ok_or(10025u32)?;
                    if Some(o.client) != ctx.client {
                        return Err(10025);
                    }
                    self.locks.remove(&key);
                } else if self.opens.contains_key(&key) {
                    return Err(10037);
                } else {
                    return Err(10025);
                }
            }
            (_, Arg::Unsupported) => {
                return Err(if (3..=71).contains(&op.code) {
                    10004
                } else {
                    10044
                });
            }
            _ => return Err(10004),
        }
        Ok(e)
    }

    async fn attributes(
        &mut self,
        id: Id,
        requested: &[u32],
        ctx: &Context<'_>,
    ) -> NResult<Encoder> {
        let m = self.fs.metadata(id).await?;
        let kind = self.fs.attribute_kind(id);
        let size = self.fs.attribute_size(id).await?.unwrap_or(m.len());
        let supported = xdr::bits(ATTRIBUTES);
        let mut mask = requested.to_vec();
        for (i, v) in mask.iter_mut().enumerate() {
            *v &= supported.get(i).copied().unwrap_or(0)
        }
        if xdr::bit(requested, 48) || xdr::bit(requested, 54) {
            return Err(22);
        }
        let space = self.fs.space().await?;
        let mut value = Encoder::default();
        for n in 0..128 {
            if !xdr::bit(&mask, n) {
                continue;
            }
            match n {
                0 => value.bitmap(&supported),
                1 => value.u32(kind.unwrap_or(if m.is_dir() {
                    2
                } else if m.is_symlink() {
                    5
                } else {
                    1
                })),
                2 => value.u32(if m.created().is_ok() { 0 } else { 2 }),
                3 => value.u64(change(&m)),
                4 => value.u64(size),
                5 | 6 | 9 | 15 | 17 | 18 | 26 | 34 => value.boolean(true),
                7 => value.boolean(self.fs.named_attributes(id).await),
                16 => value.boolean(false),
                8 => {
                    value.u64(fileid(self.fs.root_id));
                    value.u64(0)
                }
                10 => value.u32(90),
                11 | 13 => value.u32(0),
                19 => value.opaque(&id),
                20 | 55 => value.u64(fileid(id)),
                21 | 22 => value.u64(space.4),
                23 => value.u64(space.3),
                27 => value.u64(i64::MAX as u64),
                28 => value.u32(65535),
                29 => value.u32(255),
                30 | 31 => value.u64(MAX_IO as u64),
                33 => value.u32((m.mode() & 0o777) & if ctx.writable { 0o777 } else { 0o555 }),
                35 => value.u32(m.nlink().min(u32::MAX as u64) as u32),
                36 => value.string(&ctx.uid.to_string()),
                37 => value.string(&ctx.gid.to_string()),
                41 => {
                    value.u32(0);
                    value.u32(0)
                }
                42 => value.u64(space.2),
                43 => value.u64(space.1),
                44 => value.u64(space.0),
                45 => value.u64(m.blocks().saturating_mul(512)),
                47 => {
                    value.u64(m.atime() as u64);
                    value.u32(m.atime_nsec() as u32)
                }
                50 => {
                    let (s, n) = m
                        .created()
                        .ok()
                        .map(|t| super::filesystem::timestamp(t.into_std()))
                        .unwrap_or((m.ctime() as u64, m.ctime_nsec() as u32));
                    value.u64(s);
                    value.u32(n)
                }
                51 => {
                    value.u64(0);
                    value.u32(1)
                }
                52 => {
                    value.u64(m.ctime() as u64);
                    value.u32(m.ctime_nsec() as u32)
                }
                53 => {
                    value.u64(m.mtime() as u64);
                    value.u32(m.mtime_nsec() as u32)
                }
                75 => value.bitmap(&xdr::bits(&[4, 33])),
                _ => return Err(10032),
            }
        }
        while mask.last() == Some(&0) {
            mask.pop();
        }
        let mut e = Encoder::default();
        e.bitmap(&mask);
        e.opaque(&value.0);
        Ok(e)
    }
    async fn set_attributes(&mut self, id: Id, attrs: &Attrs) -> NResult<()> {
        let a = SetAttrs::decode(attrs)?;
        self.fs.setattr(id, a.size, a.mode, a.atime, a.mtime).await
    }
}

#[derive(Default)]
struct SetAttrs {
    size: Option<u64>,
    mode: Option<u32>,
    atime: Option<Option<(i64, u32)>>,
    mtime: Option<Option<(i64, u32)>>,
}
impl SetAttrs {
    fn decode(attrs: &Attrs) -> NResult<Self> {
        let mut out = Self::default();
        let mut d = Decoder::new(&attrs.values);
        for n in 0..128 {
            if !xdr::bit(&attrs.mask, n) {
                continue;
            }
            match n {
                4 => out.size = Some(d.u64().map_err(|_| 10036u32)?),
                33 => out.mode = Some(d.u32().map_err(|_| 10036u32)?),
                48 | 54 => {
                    let how = d.u32().map_err(|_| 10036u32)?;
                    let time = match how {
                        0 => None,
                        1 => {
                            let s = d.u64().map_err(|_| 10036u32)? as i64;
                            let n = d.u32().map_err(|_| 10036u32)?;
                            if n >= 1_000_000_000 {
                                return Err(22);
                            }
                            Some((s, n))
                        }
                        _ => return Err(22),
                    };
                    if n == 48 {
                        out.atime = Some(time)
                    } else {
                        out.mtime = Some(time)
                    }
                }
                36 | 37 => return Err(1),
                _ => return Err(10032),
            }
        }
        d.finish().map_err(|_| 10036u32)?;
        Ok(out)
    }
}
