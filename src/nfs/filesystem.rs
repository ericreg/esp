//! Descriptor-relative export backend. cap-std confines all pathname operations
//! to the opened root on Linux and macOS, including intermediate symlinks.
use super::{
    store::Store,
    xdr::{Decoder, Encoder},
};
use anyhow::{Context, Result, bail};
use cap_std::fs::{Dir, Metadata, MetadataExt, OpenOptions, OpenOptionsExt};
mod xattrs;
use notify::Watcher;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{FileExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub type Id = [u8; 16];
pub type NResult<T> = std::result::Result<T, u32>;
pub fn status(e: std::io::Error) -> u32 {
    match e.raw_os_error() {
        Some(libc::EPERM) => 1,
        Some(libc::ENOENT) => 2,
        Some(libc::EACCES) => 13,
        Some(libc::EEXIST) => 17,
        Some(libc::EXDEV) => 18,
        Some(libc::ENOTDIR) => 20,
        Some(libc::EISDIR) => 21,
        Some(libc::EINVAL) => 22,
        Some(libc::EFBIG) => 27,
        Some(libc::ENOSPC) => 28,
        Some(libc::EROFS) => 30,
        Some(libc::EMLINK) => 31,
        Some(libc::ENAMETOOLONG) => 63,
        Some(libc::ENOTEMPTY) => 66,
        Some(libc::EDQUOT) => 69,
        Some(libc::ELOOP) => 10029,
        Some(libc::ENOTSUP) => 10004,
        #[cfg(target_os = "linux")]
        Some(libc::ENODATA) => 2,
        #[cfg(target_os = "macos")]
        Some(libc::ENOATTR) => 2,
        _ => 5,
    }
}
pub fn name(value: &str) -> NResult<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\0')
    {
        Err(10041)
    } else if value.len() > 255 {
        Err(63)
    } else {
        Ok(())
    }
}
#[derive(Clone, Debug)]
struct Entry {
    id: Id,
    identity: Vec<u8>,
    paths: Vec<PathBuf>,
}
impl Entry {
    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::default();
        e.opaque(&self.identity);
        e.u32(self.paths.len() as u32);
        for path in &self.paths {
            e.opaque(path.as_os_str().as_bytes());
        }
        e.0
    }
    fn decode(id: &[u8], bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let identity = d
            .opaque(64)
            .map_err(|_| anyhow::anyhow!("invalid file identity"))?
            .to_vec();
        let n = d.u32().map_err(|_| anyhow::anyhow!("invalid path count"))?;
        if n > 65536 {
            bail!("too many file links");
        }
        let mut paths = Vec::new();
        for _ in 0..n {
            let bytes = d
                .opaque(4096)
                .map_err(|_| anyhow::anyhow!("invalid stored path"))?;
            let path = PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec()));
            if path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                bail!("unsafe stored NFS path");
            }
            paths.push(path);
        }
        d.finish()
            .map_err(|_| anyhow::anyhow!("invalid handle metadata"))?;
        Ok(Self {
            id: id.try_into()?,
            identity,
            paths,
        })
    }
}

pub struct Backend {
    pub store: Store,
    root: Dir,
    entries: HashMap<Id, Entry>,
    identities: HashMap<Vec<u8>, Id>,
    virtuals: HashMap<Id, Attribute>,
    open_files: HashMap<Id, Vec<(std::sync::Weak<fs::File>, u32)>>,
    identity_pins: HashMap<Vec<u8>, cap_std::fs::File>,
    _watcher: notify::RecommendedWatcher,
    changed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    last_scan: std::time::Instant,
    pub root_id: Id,
    pub epoch: [u8; 8],
}
#[derive(Clone)]
struct Attribute {
    base: Id,
    name: Option<String>,
}
impl Backend {
    pub async fn open(path: &Path, state: &Path) -> Result<Self> {
        let root = Dir::open_ambient_dir(path, cap_std::ambient_authority())
            .context("cannot open export directory")?;
        let store = Store::open(state).await?;
        let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = changed.clone();
        let mut watcher = notify::RecommendedWatcher::new(
            move |event: notify::Result<notify::Event>| {
                if event.is_err()
                    || event.is_ok_and(|e| {
                        matches!(
                            e.kind,
                            notify::EventKind::Create(_)
                                | notify::EventKind::Remove(_)
                                | notify::EventKind::Modify(notify::event::ModifyKind::Name(_))
                        )
                    })
                {
                    signal.store(true, std::sync::atomic::Ordering::Release);
                }
            },
            notify::Config::default().with_follow_symlinks(false),
        )?;
        watcher
            .watch(path, notify::RecursiveMode::Recursive)
            .context("cannot watch export directory")?;
        let epoch = uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap();
        let mut backend = Self {
            store,
            root,
            entries: HashMap::new(),
            identities: HashMap::new(),
            virtuals: HashMap::new(),
            open_files: HashMap::new(),
            identity_pins: HashMap::new(),
            _watcher: watcher,
            changed,
            last_scan: std::time::Instant::now(),
            root_id: [0; 16],
            epoch,
        };
        for (key, value) in backend.store.list("handle").await? {
            let e = Entry::decode(&key, &value)?;
            backend.identities.insert(e.identity.clone(), e.id);
            backend.entries.insert(e.id, e);
        }
        for (key, value) in backend.store.list("attribute").await? {
            let mut d = Decoder::new(&value);
            let base = d
                .fixed(16)
                .map_err(|_| anyhow::anyhow!("invalid attribute handle"))?
                .try_into()?;
            let name = d
                .string(255)
                .map_err(|_| anyhow::anyhow!("invalid attribute name"))?;
            if !name.is_empty() {
                xattrs::validate(&name).map_err(|_| anyhow::anyhow!("invalid attribute name"))?;
            }
            backend.virtuals.insert(
                key.as_slice().try_into()?,
                Attribute {
                    base,
                    name: (!name.is_empty()).then_some(name),
                },
            );
        }
        backend.root_id = backend
            .remember(Path::new("."))
            .await
            .map_err(|e| anyhow::anyhow!("cannot index export root: NFS status {e}"))?;
        backend.reconcile().await?;
        Ok(backend)
    }
    fn identity(&self, m: &Metadata) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(m.dev().to_be_bytes());
        out.extend(m.ino().to_be_bytes());
        match m
            .created()
            .ok()
            .and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok())
        {
            Some(t) => {
                out.extend(t.as_secs().to_be_bytes());
                out.extend(t.subsec_nanos().to_be_bytes());
            }
            // No trustworthy creation timestamp: do not reuse handles after a
            // restart, which could alias an unrelated recycled inode.
            None => {
                out.extend(self.epoch);
            }
        }
        out
    }
    async fn remember(&mut self, path: &Path) -> NResult<Id> {
        let metadata = self.root.symlink_metadata(path).map_err(status)?;
        let identity = self.identity(&metadata);
        #[cfg(target_os = "linux")]
        if metadata.created().is_err() && !self.identity_pins.contains_key(&identity) {
            // A pinned inode cannot be recycled while this daemon runs. On
            // filesystems without birth times, epoch-scoped handles go stale
            // after restart rather than ever aliasing a recycled inode.
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW);
            let pin = self.root.open_with(path, &options).map_err(status)?;
            if self.identity(&pin.metadata().map_err(status)?) != identity {
                return Err(70);
            }
            self.identity_pins.insert(identity.clone(), pin);
        }
        if !metadata.is_file() && !metadata.is_dir() && !metadata.is_symlink() {
            return Err(10007);
        }
        let id = self
            .identities
            .get(&identity)
            .copied()
            .unwrap_or_else(|| *uuid::Uuid::new_v4().as_bytes());
        if self.entries.len() >= 1_000_000 && !self.entries.contains_key(&id) {
            return Err(10018);
        }
        let entry = self.entries.entry(id).or_insert_with(|| Entry {
            id,
            identity: identity.clone(),
            paths: Vec::new(),
        });
        if !entry.paths.iter().any(|p| p == path) {
            entry.paths.push(path.into());
            self.store
                .put("handle", &id, &entry.encode())
                .await
                .map_err(|_| 5u32)?;
        }
        self.identities.insert(identity, id);
        Ok(id)
    }
    async fn reconcile(&mut self) -> Result<()> {
        let mut pending = vec![PathBuf::from(".")];
        let mut seen = 0;
        while let Some(path) = pending.pop() {
            seen += 1;
            if seen > 1_000_000 {
                bail!("export exceeds one million filesystem objects");
            }
            match self.remember(&path).await {
                Ok(_) => {}
                Err(13 | 10007 | 2) => continue,
                Err(s) => bail!("export scan failed: NFS status {s}"),
            }
            if self.root.symlink_metadata(&path)?.is_dir() {
                let entries = match self.root.read_dir(&path) {
                    Ok(e) => e,
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue,
                    Err(e) => return Err(e.into()),
                };
                for entry in entries {
                    pending.push(path.join(entry?.file_name()));
                }
            }
            if seen % 256 == 0 {
                tokio::task::yield_now().await;
            }
        }
        Ok(())
    }
    pub async fn reconcile_changes(&mut self) -> NResult<()> {
        if self.last_scan.elapsed() >= std::time::Duration::from_millis(250)
            && self
                .changed
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.reconcile().await.map_err(|_| 5u32)?;
            self.last_scan = std::time::Instant::now();
        }
        Ok(())
    }
    pub async fn path(&mut self, id: Id) -> NResult<PathBuf> {
        for attempt in 0..2 {
            let entry = self.entries.get(&id).ok_or(10001u32)?;
            for path in &entry.paths {
                if let Ok(m) = self.root.symlink_metadata(path)
                    && self.identity(&m) == entry.identity
                {
                    return Ok(path.clone());
                }
            }
            if attempt == 0 {
                self.reconcile().await.map_err(|_| 5u32)?;
            }
        }
        Err(70)
    }
    pub async fn metadata(&mut self, id: Id) -> NResult<Metadata> {
        if let Some(attr) = self.virtuals.get(&id).cloned() {
            if let Some(name) = &attr.name {
                let fd = self.attribute_file(attr.base).await?;
                xattrs::get(&fd, name)?;
            }
            return Box::pin(self.metadata(attr.base)).await;
        }
        if let Some(f) = self.pinned(id, 0) {
            return Ok(Metadata::from_just_metadata(f.metadata().map_err(status)?));
        }
        let path = self.path(id).await?;
        self.root.symlink_metadata(path).map_err(status)
    }
    pub async fn lookup(&mut self, parent: Id, child: &str) -> NResult<Id> {
        name(child)?;
        if let Some(attr) = self.virtuals.get(&parent).cloned() {
            if attr.name.is_some() {
                return Err(20);
            }
            let fd = self.attribute_file(attr.base).await?;
            xattrs::get(&fd, child)?;
            return self.attribute_handle(attr.base, Some(child)).await;
        }
        let parent = self.path(parent).await?;
        if !self
            .root
            .symlink_metadata(&parent)
            .map_err(status)?
            .is_dir()
        {
            return Err(20);
        }
        self.remember(&parent.join(child)).await
    }
    pub async fn parent(&mut self, id: Id) -> NResult<Id> {
        if let Some(attr) = self.virtuals.get(&id).cloned() {
            return if attr.name.is_some() {
                self.attribute_handle(attr.base, None).await
            } else {
                Ok(attr.base)
            };
        }
        if id == self.root_id {
            return Err(2);
        }
        let path = self.path(id).await?;
        self.remember(path.parent().unwrap_or(Path::new("."))).await
    }
    pub async fn file(&mut self, id: Id, write: bool) -> NResult<fs::File> {
        self.file_access(id, if write { 2 } else { 1 }).await
    }
    fn pinned(&self, id: Id, access: u32) -> Option<std::sync::Arc<fs::File>> {
        self.open_files.get(&id)?.iter().find_map(|(f, mode)| {
            if mode & access == access {
                f.upgrade()
            } else {
                None
            }
        })
    }
    pub async fn pin(&mut self, id: Id, access: u32) -> NResult<std::sync::Arc<fs::File>> {
        let file = std::sync::Arc::new(self.file_access(id, access).await?);
        let entries = self.open_files.entry(id).or_default();
        entries.retain(|(f, _)| f.strong_count() != 0);
        entries.push((std::sync::Arc::downgrade(&file), access));
        Ok(file)
    }
    async fn file_access(&mut self, id: Id, access: u32) -> NResult<fs::File> {
        if let Some(attr) = self.virtuals.get(&id).cloned() {
            if attr.name.is_none() {
                return Err(21);
            }
            let fd = self.attribute_file(attr.base).await?;
            xattrs::get(&fd, attr.name.as_deref().unwrap())?;
            return Ok(fd);
        }
        if let Some(f) = self.pinned(id, access) {
            return f.try_clone().map_err(status);
        }
        let path = self.path(id).await?;
        let m = self.root.symlink_metadata(&path).map_err(status)?;
        if m.is_dir() {
            return Err(21);
        }
        if !m.is_file() {
            return Err(10029);
        }
        let mut options = OpenOptions::new();
        options
            .read(access & 1 != 0)
            .write(access & 2 != 0)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let f = self.root.open_with(&path, &options).map_err(status)?;
        // Validate the object again after open so replacement cannot redirect a
        // filehandle to a different file or a special device.
        let actual = f.metadata().map_err(status)?;
        if !actual.is_file() || self.identity(&actual) != self.entries[&id].identity {
            return Err(70);
        }
        Ok(f.into_std())
    }
    pub async fn read(&mut self, id: Id, offset: u64, count: usize) -> NResult<(Vec<u8>, bool)> {
        if let Some(attr) = self.virtuals.get(&id).cloned() {
            let fd = self.attribute_file(attr.base).await?;
            let bytes = xattrs::get(&fd, attr.name.as_deref().ok_or(21u32)?)?;
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            let end = start
                .saturating_add(count.min(super::xdr::MAX_IO))
                .min(bytes.len());
            return Ok((bytes[start..end].to_vec(), end == bytes.len()));
        }
        if offset > i64::MAX as u64 {
            return Err(22);
        }
        let f = self.file(id, false).await?;
        let mut data = vec![0; count.min(super::xdr::MAX_IO)];
        let len = f.read_at(&mut data, offset).map_err(status)?;
        data.truncate(len);
        Ok((
            data,
            offset.saturating_add(len as u64) >= f.metadata().map_err(status)?.len(),
        ))
    }
    pub async fn write(&mut self, id: Id, offset: u64, data: &[u8]) -> NResult<u32> {
        if let Some(attr) = self.virtuals.get(&id).cloned() {
            let end = offset
                .checked_add(data.len() as u64)
                .filter(|n| *n <= xattrs::MAX as u64)
                .ok_or(27u32)? as usize;
            let fd = self.attribute_file(attr.base).await?;
            let name = attr.name.as_deref().ok_or(21u32)?;
            let mut bytes = xattrs::get(&fd, name)?;
            bytes.resize(bytes.len().max(end), 0);
            bytes[offset as usize..end].copy_from_slice(data);
            xattrs::set(&fd, name, &bytes, false)?;
            fd.sync_all().map_err(status)?;
            return Ok(data.len() as u32);
        }
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|n| n > i64::MAX as u64)
        {
            return Err(27);
        }
        let f = self.file(id, true).await?;
        f.write_all_at(data, offset).map_err(status)?;
        f.sync_all().map_err(status)?;
        Ok(data.len() as u32)
    }
    pub async fn create(
        &mut self,
        parent: Id,
        child: &str,
        kind: u32,
        mode: u32,
        target: Option<&str>,
        exclusive: bool,
    ) -> NResult<Id> {
        name(child)?;
        if let Some(attr) = self.virtuals.get(&parent).cloned() {
            if attr.name.is_some() {
                return Err(20);
            }
            if kind != 1 {
                return Err(10007);
            }
            let fd = self.attribute_file(attr.base).await?;
            xattrs::set(&fd, child, &[], exclusive)?;
            fd.sync_all().map_err(status)?;
            return self.attribute_handle(attr.base, Some(child)).await;
        }
        let parent_path = self.path(parent).await?;
        let path = parent_path.join(child);
        match kind {
            1 => {
                let mut opts = OpenOptions::new();
                opts.write(true)
                    .create(true)
                    .create_new(exclusive)
                    .mode(mode & 0o777)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                let f = self.root.open_with(&path, &opts).map_err(status)?;
                if !f.metadata().map_err(status)?.is_file() {
                    return Err(10007);
                }
                f.sync_all().map_err(status)?;
            }
            2 => {
                self.root.create_dir(&path).map_err(status)?;
                self.root
                    .set_permissions(
                        &path,
                        cap_std::fs::Permissions::from_std(fs::Permissions::from_mode(
                            mode & 0o777,
                        )),
                    )
                    .map_err(status)?;
            }
            5 => {
                self.root
                    .symlink_contents(target.ok_or(22u32)?, &path)
                    .map_err(status)?;
            }
            _ => return Err(10007),
        }
        self.sync_dir(&parent_path)?;
        self.remember(&path).await
    }
    pub async fn remove(&mut self, parent: Id, child: &str) -> NResult<()> {
        name(child)?;
        if let Some(attr) = self.virtuals.get(&parent).cloned() {
            if attr.name.is_some() {
                return Err(20);
            }
            let fd = self.attribute_file(attr.base).await?;
            xattrs::remove(&fd, child)?;
            return fd.sync_all().map_err(status);
        }
        let p = self.path(parent).await?;
        let path = p.join(child);
        let m = self.root.symlink_metadata(&path).map_err(status)?;
        if m.is_dir() {
            self.root.remove_dir(&path).map_err(status)?;
        } else {
            self.root.remove_file(&path).map_err(status)?;
        }
        self.sync_dir(&p)
    }
    pub async fn rename(&mut self, from: Id, old: &str, to: Id, new: &str) -> NResult<()> {
        // Native xattrs provide atomic value replacement, not atomic rename.
        if self.virtuals.contains_key(&from) || self.virtuals.contains_key(&to) {
            return Err(10004);
        }
        name(old)?;
        name(new)?;
        let from = self.path(from).await?;
        let to = self.path(to).await?;
        let old_path = from.join(old);
        let new_path = to.join(new);
        self.root
            .rename(&old_path, &self.root, &new_path)
            .map_err(status)?;
        self.sync_dir(&from)?;
        self.sync_dir(&to)?;
        for entry in self.entries.values_mut() {
            let mut changed = false;
            for path in &mut entry.paths {
                if let Ok(suffix) = path.strip_prefix(&old_path) {
                    *path = new_path.join(suffix);
                    changed = true;
                }
            }
            if changed {
                self.store
                    .put("handle", &entry.id, &entry.encode())
                    .await
                    .map_err(|_| 5u32)?;
            }
        }
        Ok(())
    }
    pub async fn link(&mut self, source: Id, parent: Id, child: &str) -> NResult<()> {
        if self.virtuals.contains_key(&source) || self.virtuals.contains_key(&parent) {
            return Err(10004);
        }
        name(child)?;
        let source = self.path(source).await?;
        let parent = self.path(parent).await?;
        let dest = parent.join(child);
        if !self
            .root
            .symlink_metadata(&source)
            .map_err(status)?
            .is_file()
        {
            return Err(1);
        }
        self.root
            .hard_link(source, &self.root, &dest)
            .map_err(status)?;
        self.sync_dir(&parent)?;
        self.remember(&dest).await?;
        Ok(())
    }
    pub async fn readlink(&mut self, id: Id) -> NResult<Vec<u8>> {
        let path = self.path(id).await?;
        Ok(self
            .root
            .read_link_contents(path)
            .map_err(status)?
            .into_os_string()
            .into_vec())
    }
    pub async fn children(&mut self, id: Id) -> NResult<Vec<(String, Id)>> {
        if let Some(attr) = self.virtuals.get(&id).cloned() {
            if attr.name.is_some() {
                return Err(20);
            }
            let fd = self.attribute_file(attr.base).await?;
            let mut entries = Vec::new();
            for name in xattrs::list(&fd)? {
                entries.push((
                    name.clone(),
                    self.attribute_handle(attr.base, Some(&name)).await?,
                ));
            }
            return Ok(entries);
        }
        let path = self.path(id).await?;
        let entries = self.root.read_dir(&path).map_err(status)?;
        let mut names = Vec::new();
        for entry in entries {
            if names.len() > 65536 {
                return Err(10018);
            }
            let name = entry
                .map_err(status)?
                .file_name()
                .into_string()
                .map_err(|_| 10041u32)?;
            names.push(name);
        }
        names.sort();
        let mut out = Vec::new();
        for name in names {
            match self.remember(&path.join(&name)).await {
                Ok(id) => out.push((name, id)),
                Err(10007 | 2) => {}
                Err(s) => return Err(s),
            }
        }
        Ok(out)
    }
    pub async fn setattr(
        &mut self,
        id: Id,
        size: Option<u64>,
        mode: Option<u32>,
        atime: Option<Option<(i64, u32)>>,
        mtime: Option<Option<(i64, u32)>>,
    ) -> NResult<()> {
        if let Some(attr) = self.virtuals.get(&id).cloned() {
            if atime.is_some() || mtime.is_some() {
                return Err(10004);
            }
            // Attribute permissions are inherited from the containing file.
            let fd = self.attribute_file(attr.base).await?;
            if let Some(size) = size {
                if size > xattrs::MAX as u64 {
                    return Err(27);
                }
                let name = attr.name.as_deref().ok_or(21u32)?;
                let mut bytes = xattrs::get(&fd, name)?;
                bytes.resize(size as usize, 0);
                xattrs::set(&fd, name, &bytes, false)?;
                fd.sync_all().map_err(status)?;
            }
            return Ok(());
        }
        let m = self.metadata(id).await?;
        if m.is_symlink() {
            return Err(10004);
        }
        let f = if m.is_dir() {
            let path = self.path(id).await?;
            self.directory_file(&path)?
        } else {
            self.file(id, size.is_some()).await?
        };
        if let Some(size) = size {
            if size > i64::MAX as u64 {
                return Err(27);
            }
            f.set_len(size).map_err(status)?;
        }
        if let Some(mode) = mode {
            f.set_permissions(fs::Permissions::from_mode(mode & 0o777))
                .map_err(status)?;
        }
        if atime.is_some() || mtime.is_some() {
            let convert = |t: Option<Option<(i64, u32)>>| -> libc::timespec {
                match t {
                    None => libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_OMIT,
                    },
                    Some(None) => libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_NOW,
                    },
                    Some(Some((s, n))) => libc::timespec {
                        tv_sec: s as _,
                        tv_nsec: n as _,
                    },
                }
            };
            let times = [convert(atime), convert(mtime)];
            if unsafe { libc::futimens(f.as_raw_fd(), times.as_ptr()) } != 0 {
                return Err(status(std::io::Error::last_os_error()));
            }
        }
        f.sync_all().map_err(status)
    }
    pub async fn open_attributes(&mut self, id: Id) -> NResult<Id> {
        if self.virtuals.contains_key(&id) {
            return Err(22);
        }
        let fd = self.attribute_file(id).await?;
        xattrs::list(&fd)?;
        self.attribute_handle(id, None).await
    }
    pub async fn named_attributes(&mut self, id: Id) -> bool {
        if self.virtuals.contains_key(&id) {
            return false;
        }
        match self.attribute_file(id).await {
            Ok(fd) => xattrs::list(&fd).is_ok(),
            Err(_) => false,
        }
    }
    pub fn attribute_kind(&self, id: Id) -> Option<u32> {
        self.virtuals
            .get(&id)
            .map(|a| if a.name.is_some() { 9 } else { 8 })
    }
    pub async fn attribute_size(&mut self, id: Id) -> NResult<Option<u64>> {
        if let Some(attr) = self.virtuals.get(&id).cloned() {
            let size = if let Some(name) = attr.name {
                xattrs::get(&self.attribute_file(attr.base).await?, &name)?.len() as u64
            } else {
                0
            };
            Ok(Some(size))
        } else {
            Ok(None)
        }
    }
    async fn attribute_file(&mut self, id: Id) -> NResult<fs::File> {
        let m = Box::pin(self.metadata(id)).await?;
        if m.is_dir() {
            let path = self.path(id).await?;
            self.directory_file(&path)
        } else {
            Box::pin(self.file(id, false)).await
        }
    }
    async fn attribute_handle(&mut self, base: Id, name: Option<&str>) -> NResult<Id> {
        if let Some(name) = name {
            xattrs::validate(name)?;
        }
        let mut data = Encoder::default();
        data.fixed(&base);
        data.string(name.unwrap_or(""));
        let id: Id = Sha256::digest(&data.0)[..16].try_into().unwrap();
        if !self.virtuals.contains_key(&id) {
            if self.virtuals.len() >= 65536 {
                return Err(10018);
            }
            self.store
                .put("attribute", &id, &data.0)
                .await
                .map_err(|_| 5u32)?;
            self.virtuals.insert(
                id,
                Attribute {
                    base,
                    name: name.map(str::to_owned),
                },
            );
        }
        Ok(id)
    }
    fn sync_dir(&self, path: &Path) -> NResult<()> {
        self.directory_file(path)?.sync_all().map_err(status)
    }
    fn directory_file(&self, path: &Path) -> NResult<fs::File> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
        Ok(self
            .root
            .open_with(path, &options)
            .map_err(status)?
            .into_std())
    }
    // statvfs integer widths differ between Linux and macOS.
    #[allow(clippy::unnecessary_cast)]
    pub async fn space(&mut self) -> NResult<(u64, u64, u64, u64, u64)> {
        let f = self.root.try_clone().map_err(status)?.into_std_file();
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
        if unsafe { libc::fstatvfs(f.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
            return Err(status(std::io::Error::last_os_error()));
        }
        let s = unsafe { stats.assume_init() };
        let unit = s.f_frsize as u64;
        Ok((
            (s.f_blocks as u64).saturating_mul(unit),
            (s.f_bfree as u64).saturating_mul(unit),
            (s.f_bavail as u64).saturating_mul(unit),
            s.f_files as u64,
            s.f_ffree as u64,
        ))
    }
}
pub fn change(m: &Metadata) -> u64 {
    (m.ctime() as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(m.ctime_nsec() as u64)
}
pub fn timestamp(t: SystemTime) -> (u64, u32) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs(), d.subsec_nanos())
}
