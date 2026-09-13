//! Persistent loopback listeners and narrowly scoped OS mount helpers.
use super::*;
use std::os::{
    fd::{AsRawFd, FromRawFd, OwnedFd},
    unix::ffi::OsStrExt,
};
use tokio::net::TcpListener;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub id: String,
    pub network: String,
    pub peer: EndpointId,
    pub share: String,
    pub name: String,
    pub mountpoint: PathBuf,
    pub port: u16,
    pub uid: u32,
    pub gid: u32,
    pub access: Access,
    pub created: bool,
    #[serde(default)]
    pub last_error: Option<String>,
}
impl Registration {
    pub fn validate(&self) -> Result<()> {
        for id in [&self.id, &self.network, &self.share] {
            Uuid::parse_str(id)?;
        }
        if self.port < 1024 || !self.mountpoint.is_absolute() {
            bail!("invalid mount registration");
        }
        validate_name(&self.name)?;
        Ok(())
    }
}

#[derive(Default)]
pub struct Listeners {
    tasks: HashMap<String, tokio::task::JoinHandle<()>>,
    restorations: HashMap<String, tokio::task::JoinHandle<()>>,
    errors: Arc<std::sync::Mutex<HashMap<String, String>>>,
}
impl Listeners {
    pub fn stop(&mut self) {
        for (_, task) in self.tasks.drain() {
            task.abort();
        }
        for (_, task) in self.restorations.drain() {
            task.abort();
        }
    }
}
impl Drop for Listeners {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn listen(
    reg: &Registration,
    runtime: &networks::Runtime,
) -> Result<tokio::task::JoinHandle<()>> {
    reg.validate()?;
    #[cfg(target_os = "linux")]
    {
        let first: u16 = fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")?
            .trim()
            .parse()?;
        if first < 1024 {
            bail!(
                "secure NFS mounting requires net.ipv4.ip_unprivileged_port_start >= 1024; otherwise other local users can impersonate the kernel client"
            );
        }
    }
    let listener = TcpListener::bind(("127.0.0.1", reg.port))
        .await
        .context("cannot bind registered NFS port")?;
    let (reg, actor, endpoint) = (reg.clone(), runtime.actor.clone(), runtime.endpoint.clone());
    Ok(tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept(), if tasks.len() < 8 => {
                    let Ok((mut tcp, source)) = accepted else { break; };
                    // Only a privileged kernel NFS client may enter this local
                    // bridge. AUTH_SYS alone would let another local user
                    // impersonate the mount owner on an unprivileged port.
                    if source.port() >= 1024 { continue; }
                    let (reg, actor, endpoint) = (reg.clone(), actor.clone(), endpoint.clone());
                    tasks.spawn(async move {
                        let result = async {
                            let mut tunnel = open(&endpoint, &actor, &reg.peer.to_string(), Some(reg.share.clone()), reg.id.clone(), reg.uid, reg.gid).await?;
                            let (mut r, mut w) = tcp.split();
                            let upload = async { io::copy(&mut r, &mut tunnel.send).await?; tunnel.send.finish()?; Ok::<_,anyhow::Error>(()) };
                            let download = async { io::copy(&mut tunnel.recv, &mut w).await?; w.shutdown().await?; Ok::<_,anyhow::Error>(()) };
                            tokio::select! {
                                result = async { tokio::try_join!(upload, download)?; Ok::<_, anyhow::Error>(()) } => result,
                                _ = tunnel.active.cancelled() => Err(anyhow!("NFS peer revoked or network removed")),
                            }
                        }.await;
                        if let Err(e) = result { warn!(mount = %reg.id, error = %e, "NFS tunnel ended; kernel client may reconnect"); }
                    });
                },
                _ = tasks.join_next(), if !tasks.is_empty() => {},
            }
        }
    }))
}

pub async fn restore(manager: &mut networks::Manager) {
    for registration in manager.global.mounts.clone() {
        let result = match manager.runtime(&registration.network) {
            Ok(r) => listen(&registration, r).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(task) => {
                manager.mounts.tasks.insert(registration.id.clone(), task);
                if !is_mounted(&registration.mountpoint).unwrap_or(true) {
                    let errors = manager.mounts.errors.clone();
                    manager.mounts.restorations.insert(registration.id.clone(),tokio::spawn(async move {
                        let result = async {
                            prepare_directory(&registration.mountpoint)?;
                            elevate_with_prompt(&Helper::Mount { registration: registration.clone() }, false).await
                        }.await;
                        if let Err(e) = result {
                            errors.lock().unwrap().insert(registration.id, format!("automatic remount failed: {e:#}; rerun esp mount to authorize it"));
                        }
                    }));
                }
            }
            Err(e) => {
                manager
                    .mounts
                    .errors
                    .lock()
                    .unwrap()
                    .insert(registration.id.clone(), format!("{e:#}"));
            }
        }
    }
}
pub async fn add(
    manager: &mut networks::Manager,
    registration: Registration,
) -> Result<serde_json::Value> {
    registration.validate()?;
    if registration.uid != unsafe { libc::geteuid() }
        || registration.gid != unsafe { libc::getegid() }
    {
        bail!("mount owner must match the ESP daemon user");
    }
    if manager.global.mounts.len() >= 100 {
        bail!("at most 100 persistent mounts are supported");
    }
    if manager.global.mounts.iter().any(|r| {
        r.id == registration.id
            || r.mountpoint == registration.mountpoint
            || r.port == registration.port
    }) {
        bail!("mount or port already registered");
    }
    let runtime = manager.runtime(&registration.network)?;
    let cfg = runtime
        .actor
        .request(|respond| ConfigActorCommand::Snapshot { respond })
        .await?;
    cfg.ensure_active()?;
    cfg.resolve_peer(&registration.peer.to_string())?;
    let task = listen(&registration, runtime).await?;
    let path = manager.store.root.join(CONFIG_FILE);
    let mut global = networks::GlobalConfig::load(&path)?;
    global.mounts.push(registration.clone());
    if let Err(e) = global.save(&path) {
        task.abort();
        return Err(e);
    }
    manager.global = global;
    manager.mounts.tasks.insert(registration.id.clone(), task);
    Ok(serde_json::to_value(registration)?)
}
pub async fn remove(manager: &mut networks::Manager, id: &str) -> Result<serde_json::Value> {
    if let Some(task) = manager.mounts.restorations.get(id)
        && !task.is_finished()
    {
        bail!("mount restoration is in progress; retry unmount when it finishes");
    }
    let registration = manager
        .global
        .mounts
        .iter()
        .find(|r| r.id == id)
        .context("mount is not registered")?;
    if is_mounted(&registration.mountpoint)? {
        bail!("unmount the filesystem before removing its listener");
    }
    let path = manager.store.root.join(CONFIG_FILE);
    let mut global = networks::GlobalConfig::load(&path)?;
    global.mounts.retain(|r| r.id != id);
    global.save(&path)?;
    manager.global = global;
    if let Some(task) = manager.mounts.tasks.remove(id) {
        task.abort();
    }
    manager.mounts.errors.lock().unwrap().remove(id);
    manager.mounts.restorations.remove(id);
    Ok(serde_json::json!({"unmounted": id}))
}
pub async fn ensure_listener(
    manager: &mut networks::Manager,
    id: &str,
) -> Result<serde_json::Value> {
    let registration = manager
        .global
        .mounts
        .iter()
        .find(|r| r.id == id)
        .context("mount is not registered")?
        .clone();
    if manager
        .mounts
        .restorations
        .get(id)
        .is_some_and(|task| !task.is_finished())
    {
        bail!("automatic mount restoration is still in progress; retry shortly");
    }
    if !manager
        .mounts
        .tasks
        .get(id)
        .is_some_and(|task| !task.is_finished())
    {
        let runtime = manager.runtime(&registration.network)?;
        let task = listen(&registration, runtime).await?;
        manager.mounts.tasks.insert(id.into(), task);
    }
    manager.mounts.errors.lock().unwrap().remove(id);
    Ok(serde_json::json!({"listener":"ready","id":id}))
}
pub fn offline_remove(store: &networks::Store, id: &str) -> Result<serde_json::Value> {
    let path = store.root.join(CONFIG_FILE);
    let mut cfg = networks::GlobalConfig::load(&path)?;
    let registration = cfg
        .mounts
        .iter()
        .find(|r| r.id == id)
        .context("mount is not registered")?;
    if is_mounted(&registration.mountpoint)? {
        bail!("unmount the filesystem before removing its registration");
    }
    cfg.mounts.retain(|r| r.id != id);
    cfg.save(&path)?;
    Ok(serde_json::json!({"unmounted":id}))
}
pub fn offline_report(store: &networks::Store) -> Result<serde_json::Value> {
    let cfg = networks::GlobalConfig::load(&store.root.join(CONFIG_FILE))?;
    report_rows(&cfg.mounts, None)
}
pub fn report(manager: &networks::Manager) -> Result<serde_json::Value> {
    report_rows(&manager.global.mounts, Some(&manager.mounts))
}
fn report_rows(
    registrations: &[Registration],
    listeners: Option<&Listeners>,
) -> Result<serde_json::Value> {
    let mounts: Vec<_> = registrations
        .iter()
        .map(|r| {
            let mut value = serde_json::to_value(r).expect("registration serialization");
            let mounted = is_mounted(&r.mountpoint).unwrap_or(false);
            let listening =
                listeners.is_some_and(|l| l.tasks.get(&r.id).is_some_and(|t| !t.is_finished()));
            value["state"] = serde_json::json!(if mounted && listening {
                "mounted"
            } else if mounted {
                "disconnected"
            } else {
                "needs_mount"
            });
            value["last_error"] = serde_json::json!(if mounted && listening {
                None
            } else {
                listeners
                    .and_then(|l| l.errors.lock().unwrap().get(&r.id).cloned())
                    .or(r.last_error.clone())
            });
            value
        })
        .collect();
    Ok(serde_json::json!({"mounts": mounts}))
}

pub async fn mount(
    network: &str,
    target: &str,
    name: &str,
    destination: Option<PathBuf>,
) -> Result<serde_json::Value> {
    let store = networks::Store::local()?;
    let cfg = store.select(network)?;
    let peer = cfg.resolve_peer(target)?.clone();
    start(&cfg).await?;
    let list = call(Local::List {
        network: cfg.network_id.clone(),
        peer: Some(peer.node_id.to_string()),
    })
    .await?;
    let share = list["shares"]
        .as_array()
        .context("invalid share listing")?
        .iter()
        .find(|s| s["name"].as_str() == Some(name) || s["id"].as_str() == Some(name))
        .context("share is unavailable or access is denied")?;
    let name = share["name"].as_str().context("missing share name")?;
    validate_name(name)?;
    let destination = destination.unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("esp")
            .join(component(
                cfg.network_policy
                    .admin_label
                    .as_deref()
                    .unwrap_or(&cfg.network_id),
            ))
            .join(format!("{}-{}", component(&peer.name), peer.connection_id))
            .join(name)
    });
    let destination = std::path::absolute(destination)?;
    let global = networks::GlobalConfig::load(&store.root.join(CONFIG_FILE))?;
    if let Some(existing) = global.mounts.iter().find(|r| r.mountpoint == destination) {
        if existing.network != cfg.network_id
            || existing.peer != peer.node_id
            || Some(existing.share.as_str()) != share["id"].as_str()
        {
            bail!("destination is registered to another share");
        }
        // Never direct the kernel to a registered port that ESP failed to bind
        // (for example because another process occupied it after a restart).
        call(Local::EnsureMount {
            id: existing.id.clone(),
        })
        .await?;
        if !is_mounted(&destination)? {
            prepare_directory(&destination)?;
            elevate(&Helper::Mount {
                registration: existing.clone(),
            })
            .await?;
        }
        return Ok(serde_json::to_value(existing)?);
    }
    let created = prepare_directory(&destination)?;
    let reserve = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = reserve.local_addr()?.port();
    drop(reserve);
    let registration = Registration {
        id: Uuid::new_v4().to_string(),
        network: cfg.network_id,
        peer: peer.node_id,
        share: share["id"].as_str().context("missing share id")?.into(),
        name: name.into(),
        mountpoint: destination,
        port,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        access: serde_json::from_value(share["access"].clone())?,
        created,
        last_error: None,
    };
    if let Err(e) = call(Local::AddMount {
        registration: registration.clone(),
    })
    .await
    {
        if created {
            let _ = fs::remove_dir(&registration.mountpoint);
        }
        return Err(e);
    }
    if let Err(e) = elevate(&Helper::Mount {
        registration: registration.clone(),
    })
    .await
    {
        let _ = call(Local::RemoveMount {
            id: registration.id.clone(),
        })
        .await;
        if created {
            let _ = fs::remove_dir(&registration.mountpoint);
        }
        return Err(e);
    }
    Ok(serde_json::to_value(registration)?)
}
pub async fn unmount(path: &Path, force: bool) -> Result<serde_json::Value> {
    let path = std::path::absolute(path)?;
    let store = networks::Store::local()?;
    let global = networks::GlobalConfig::load(&store.root.join(CONFIG_FILE))?;
    let registration = global
        .mounts
        .iter()
        .find(|r| r.mountpoint == path)
        .context("mount is not registered with ESP")?
        .clone();
    if is_mounted(&path)? {
        elevate(&Helper::Unmount {
            registration: registration.clone(),
            force,
        })
        .await?;
    }
    if let Ok(cfg) = store.load(&registration.network) {
        start(&cfg).await?;
    }
    let value = call(Local::RemoveMount {
        id: registration.id,
    })
    .await?;
    if registration.created {
        match fs::remove_dir(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(value)
}
fn component(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if out.is_empty() { "peer".into() } else { out }
}
fn prepare_directory(path: &Path) -> Result<bool> {
    let existed = path.try_exists()?;
    let mut current = PathBuf::new();
    for part in path.components() {
        if matches!(part, std::path::Component::ParentDir) {
            bail!("mount destination cannot contain '..'");
        }
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("mount destination contains a symlink or non-directory"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(&current)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    if is_mounted(path)? || fs::read_dir(path)?.next().is_some() {
        bail!("mount destination must be empty and not already mounted");
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        bail!("mount destination must be owned by this user with mode 0700");
    }
    Ok(!existed)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Helper {
    Mount {
        registration: Registration,
    },
    Unmount {
        registration: Registration,
        force: bool,
    },
}
async fn elevate(request: &Helper) -> Result<()> {
    elevate_with_prompt(request, true).await
}
async fn elevate_with_prompt(request: &Helper, prompt: bool) -> Result<()> {
    let executable = std::env::current_exe()?;
    let mut command = if unsafe { libc::geteuid() } == 0 {
        tokio::process::Command::new(executable)
    } else {
        let mut c = tokio::process::Command::new("sudo");
        if !prompt {
            c.arg("-n");
        }
        c.arg("--").arg(executable);
        c
    };
    let status = command
        .kill_on_drop(true)
        .arg("mount-helper")
        .arg(serde_json::to_string(request)?)
        .status()
        .await
        .context("could not run privileged mount helper")?;
    if !status.success() {
        bail!(
            "mount helper failed ({status}); the kernel NFS client and mount privileges are required"
        );
    }
    Ok(())
}
pub fn privileged(request: &str) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("mount helper requires root");
    }
    let request: Helper = serde_json::from_str(request)?;
    let registration = match &request {
        Helper::Mount { registration } | Helper::Unmount { registration, .. } => registration,
    };
    registration.validate()?;
    if let Some(uid) = std::env::var_os("SUDO_UID")
        && uid.to_str().and_then(|s| s.parse::<u32>().ok()) != Some(registration.uid)
    {
        bail!("mount owner does not match sudo caller");
    }
    if let Helper::Unmount {
        registration,
        force,
    } = &request
    {
        // Do not stat or open a hard-mounted NFS root here: either can wait
        // indefinitely for an offline server, preventing even forced unmount.
        if !is_mounted(&registration.mountpoint)? {
            bail!("destination is not mounted");
        }
        return unmount_os(&registration.mountpoint, *force);
    }
    // Reopen the destination without following any path-component symlinks.
    let destination = open_directory(&registration.mountpoint)?;
    let metadata = destination.metadata()?;
    if metadata.uid() != registration.uid {
        bail!("mount destination owner changed");
    }
    match request {
        Helper::Mount { registration } => {
            if metadata.mode() & 0o077 != 0
                || is_mounted(&registration.mountpoint)?
                || fs::read_dir(&registration.mountpoint)?.next().is_some()
            {
                bail!("unsafe or occupied mount destination");
            }
            mount_os(&registration, &destination)
        }
        Helper::Unmount { .. } => unreachable!("handled before opening the destination"),
    }
}
fn open_directory(path: &Path) -> Result<fs::File> {
    let mut dir = fs::File::open("/")?;
    for part in path.components() {
        match part {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                let name = std::ffi::CString::new(name.as_bytes())?;
                // SAFETY: valid NUL-terminated name and an owned live dirfd.
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                dir = unsafe { fs::File::from_raw_fd(fd) };
            }
            _ => bail!("mount destination must be an absolute path without '..'"),
        }
    }
    Ok(dir)
}

#[cfg(target_os = "linux")]
fn mount_os(r: &Registration, destination: &fs::File) -> Result<()> {
    let fsname = c"nfs";
    // SAFETY: kernel mount API receives valid descriptors and C strings. Every
    // returned descriptor is immediately wrapped for cleanup on error.
    let fd = unsafe { libc::syscall(libc::SYS_fsopen, fsname.as_ptr(), 1u32) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("fsopen(nfs): kernel NFS support is required");
    }
    let context = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let port = r.port.to_string();
    for (key, value) in [
        ("source", "127.0.0.1:/"),
        ("addr", "127.0.0.1"),
        ("vers", "4.2"),
        ("proto", "tcp"),
        ("port", port.as_str()),
        ("sec", "sys"),
        ("nconnect", "1"),
        ("rsize", "1048576"),
        ("wsize", "1048576"),
    ] {
        let (key, value) = (std::ffi::CString::new(key)?, std::ffi::CString::new(value)?);
        if unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                context.as_raw_fd(),
                1u32,
                key.as_ptr(),
                value.as_ptr(),
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error()).context("configure NFS mount");
        }
    }
    for key in [c"hard", c"nosharecache", c"resvport"] {
        if unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                context.as_raw_fd(),
                0u32,
                key.as_ptr(),
                std::ptr::null::<u8>(),
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    if unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            6u32,
            std::ptr::null::<u8>(),
            std::ptr::null::<u8>(),
            0,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("create NFS mount");
    }
    // nosuid and nodev; server enforces read-only so an access update remains live.
    let fd = unsafe { libc::syscall(libc::SYS_fsmount, context.as_raw_fd(), 1u32, 2u32 | 4u32) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mount = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    if unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount.as_raw_fd(),
            c"".as_ptr(),
            destination.as_raw_fd(),
            c"".as_ptr(),
            0x4u32 | 0x40u32,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("attach NFS mount to destination");
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn mount_os(r: &Registration, _destination: &fs::File) -> Result<()> {
    let status = std::process::Command::new("/sbin/mount_nfs")
        .args([
            "-o",
            &format!("vers=4.1,tcp,port={},hard,resvport,nosuid,nodev", r.port),
            "127.0.0.1:/",
        ])
        .arg(&r.mountpoint)
        .status()?;
    if !status.success() {
        bail!("macOS mount_nfs failed: {status}");
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn mount_os(_: &Registration, _: &fs::File) -> Result<()> {
    bail!("ESP NFS mounts support Linux and macOS")
}
fn unmount_os(path: &Path, force: bool) -> Result<()> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    #[cfg(target_os = "linux")]
    let rc = unsafe { libc::umount2(path.as_ptr(), if force { libc::MNT_FORCE } else { 0 }) };
    #[cfg(target_os = "macos")]
    let rc = unsafe { libc::unmount(path.as_ptr(), if force { libc::MNT_FORCE } else { 0 }) };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let rc = -1;
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("unmount failed; mount and registration retained");
    }
    Ok(())
}
pub fn is_mounted(path: &Path) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let text = fs::read_to_string("/proc/self/mountinfo")?;
        let escaped = path
            .to_string_lossy()
            .replace('\\', "\\134")
            .replace(' ', "\\040")
            .replace('\t', "\\011")
            .replace('\n', "\\012");
        Ok(text
            .lines()
            .any(|l| l.split_whitespace().nth(4) == Some(escaped.as_str())))
    }
    #[cfg(target_os = "macos")]
    {
        let mut entries: *mut libc::statfs = std::ptr::null_mut();
        let count = unsafe { libc::getmntinfo(&mut entries, libc::MNT_NOWAIT) };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        for i in 0..count as usize {
            let name = unsafe { std::ffi::CStr::from_ptr((*entries.add(i)).f_mntonname.as_ptr()) };
            if name.to_bytes() == path.as_os_str().as_bytes() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = path;
        bail!("unsupported mount platform")
    }
}
