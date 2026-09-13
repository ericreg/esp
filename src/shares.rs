//! Network-scoped shares, authenticated NFS setup, and local command dispatch.
use super::*;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell, watch};

pub mod mounts;
pub const ALPN: &[u8] = b"esp/nfs/cbor/1";
const MAX_SHARES: usize = 100;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    #[default]
    Ro,
    Rw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub access: Access,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<EndpointId>>,
}
impl Share {
    pub fn allows(&self, peer: EndpointId) -> bool {
        self.peers
            .as_ref()
            .is_none_or(|peers| peers.contains(&peer))
    }
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Publish a directory; read-only for all network peers by default.
    Share {
        network: String,
        share: String,
        mountpoint: PathBuf,
        #[arg(long, value_enum, default_value = "ro")]
        access: Access,
        #[arg(long, value_delimiter = ',', num_args = 1, action = clap::ArgAction::Append)]
        peers: Option<Vec<String>>,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// Stop sharing a directory in this network.
    Unshare {
        network: String,
        share: String,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// List local shares, or accessible shares on a peer.
    Shares {
        network: String,
        peer: Option<String>,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// Mount a peer's share, creating a destination directory if necessary.
    Mount {
        network: String,
        peer: String,
        share: String,
        mountpoint: Option<PathBuf>,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// Unmount and forget a registered share.
    Unmount {
        mountpoint: PathBuf,
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// List persistent mount registrations and their current state.
    Mounts {
        #[command(flatten)]
        output: output::Arguments,
    },
    #[command(hide = true)]
    MountHelper { request: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Update {
    Put {
        name: String,
        path: PathBuf,
        access: Access,
        peers: Option<Vec<String>>,
    },
    Remove {
        name: String,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Local {
    Update {
        network: String,
        update: Update,
    },
    List {
        network: String,
        peer: Option<String>,
    },
    AddMount {
        registration: mounts::Registration,
    },
    RemoveMount {
        id: String,
    },
    EnsureMount {
        id: String,
    },
    Mounts,
}

pub fn validate(shares: &[Share]) -> Result<()> {
    if shares.len() > MAX_SHARES {
        bail!("at most {MAX_SHARES} shares per network are supported");
    }
    let mut names = HashSet::new();
    let mut ids = HashSet::new();
    for share in shares {
        validate_name(&share.name)?;
        validate_network_id(&share.id)?;
        if !names.insert(&share.name) || !ids.insert(&share.id) {
            bail!("duplicate share name or UUID");
        }
        if !share.path.is_absolute() {
            bail!("share paths must be absolute");
        }
        if let Some(peers) = &share.peers {
            if peers.is_empty() || peers.len() > ABSOLUTE_MAX_KNOWN_PEERS {
                bail!("share peer allowlist must contain 1–1000 peers");
            }
            if peers.iter().collect::<HashSet<_>>().len() != peers.len() {
                bail!("duplicate peer in share allowlist");
            }
        }
    }
    Ok(())
}
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        bail!(
            "share names must be 1–64 ASCII letters, digits, '.', '_' or '-' (excluding '.' and '..')"
        );
    }
    Ok(())
}
pub fn apply(cfg: &mut Config, update: Update) -> Result<serde_json::Value> {
    cfg.ensure_active()?;
    match update {
        Update::Put {
            name,
            path,
            access,
            peers,
        } => {
            validate_name(&name)?;
            let path = fs::canonicalize(path).context("share directory does not exist")?;
            if !path.is_dir() {
                bail!("share source must be a directory");
            }
            let peers = peers
                .map(|names| -> Result<Vec<_>> {
                    let mut ids = Vec::new();
                    for name in names {
                        let peer = cfg.resolve_peer(&name)?;
                        if is_node_revoked(cfg, peer.node_id) {
                            bail!("peer {name:?} has been revoked");
                        }
                        if !ids.contains(&peer.node_id) {
                            ids.push(peer.node_id);
                        }
                    }
                    ids.sort();
                    Ok(ids)
                })
                .transpose()?;
            let id = cfg
                .shares
                .iter()
                .find(|s| s.name == name)
                .map(|s| s.id.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            let share = Share {
                id,
                name: name.clone(),
                path,
                access,
                peers,
            };
            let mut next = cfg.shares.clone();
            next.retain(|s| s.name != name);
            next.push(share.clone());
            next.sort_by(|a, b| a.name.cmp(&b.name));
            validate(&next)?;
            cfg.shares = next;
            Ok(serde_json::json!({"network_id": cfg.network_id, "share": share}))
        }
        Update::Remove { name } => {
            let share = cfg
                .shares
                .iter()
                .find(|s| s.name == name)
                .cloned()
                .ok_or_else(|| anyhow!("no share named {name:?}"))?;
            cfg.shares.retain(|s| s.id != share.id);
            Ok(serde_json::json!({"network_id": cfg.network_id, "unshared": share.name}))
        }
    }
}

pub fn offline(store: &networks::Store, request: Local) -> Result<serde_json::Value> {
    match request {
        Local::Update { network, update } => {
            let mut cfg = store.load(&network)?;
            let report = apply(&mut cfg, update)?;
            cfg.save(&store.path(&network)?)?;
            Ok(report)
        }
        Local::List {
            network,
            peer: None,
        } => local_report(&store.load(&network)?),
        Local::Mounts => mounts::offline_report(store),
        Local::RemoveMount { id } => mounts::offline_remove(store, &id),
        _ => bail!("command requires a running ESP transport"),
    }
}
fn local_report(cfg: &Config) -> Result<serde_json::Value> {
    cfg.ensure_active()?;
    let shares: Vec<_> = cfg
        .shares
        .iter()
        .map(|s| {
            let mut value = serde_json::to_value(s).expect("share serialization");
            value["available"] = serde_json::json!(s.path.is_dir());
            value["audience"] = match &s.peers {
                None => serde_json::json!("all peers"),
                Some(peers) => serde_json::json!(peers.iter().map(|id| serde_json::json!({"node_id":id,"name":cfg.peer_by_id(*id).map(|p| p.name.clone())})).collect::<Vec<_>>()),
            };
            value
        })
        .collect();
    Ok(serde_json::json!({"network_id": cfg.network_id, "shares": shares}))
}
pub async fn manager(manager: &mut networks::Manager, request: Local) -> Result<serde_json::Value> {
    match request {
        Local::Update { network, update } => {
            manager
                .runtime(&network)?
                .actor
                .request(|respond| ConfigActorCommand::Shares { update, respond })
                .await
        }
        Local::List { network, peer } => {
            let runtime = manager.runtime(&network)?;
            match peer {
                Some(peer) => remote_list(&runtime.endpoint, &runtime.actor, &peer).await,
                None => local_report(
                    &runtime
                        .actor
                        .request(|respond| ConfigActorCommand::Snapshot { respond })
                        .await?,
                ),
            }
        }
        Local::AddMount { registration } => mounts::add(manager, registration).await,
        Local::RemoveMount { id } => mounts::remove(manager, &id).await,
        Local::EnsureMount { id } => mounts::ensure_listener(manager, &id).await,
        Local::Mounts => mounts::report(manager),
    }
}
async fn call(request: Local) -> Result<serde_json::Value> {
    networks::call(networks::Request::Files {
        request: serde_json::to_string(&request)?,
    })
    .await?
    .json()
}
async fn start(cfg: &Config) -> Result<()> {
    let store = networks::Store::local()?;
    let _connection = transport::connect_or_start(
        &local_control_socket_path()?,
        &store.path(&cfg.network_id)?,
        &std::env::current_exe()?,
    )
    .await?;
    Ok(())
}
pub async fn execute(command: Commands) -> Result<()> {
    match command {
        Commands::Share {
            network,
            share,
            mountpoint,
            access,
            peers,
            output,
        } => {
            let store = networks::Store::local()?;
            let cfg = store.select(&network)?;
            let value = call(Local::Update {
                network: cfg.network_id.clone(),
                update: Update::Put {
                    name: share,
                    path: fs::canonicalize(mountpoint)?,
                    access,
                    peers,
                },
            })
            .await?;
            start(&cfg).await?;
            output.resolve_from_config()?.print(&value)
        }
        Commands::Unshare {
            network,
            share,
            output,
        } => {
            let cfg = networks::Store::local()?.select(&network)?;
            output.resolve_from_config()?.print(
                &call(Local::Update {
                    network: cfg.network_id,
                    update: Update::Remove { name: share },
                })
                .await?,
            )
        }
        Commands::Shares {
            network,
            peer,
            output,
        } => {
            let cfg = networks::Store::local()?.select(&network)?;
            if peer.is_some() {
                start(&cfg).await?;
            }
            output.resolve_from_config()?.print(
                &call(Local::List {
                    network: cfg.network_id,
                    peer,
                })
                .await?,
            )
        }
        Commands::Mount {
            network,
            peer,
            share,
            mountpoint,
            output,
        } => output
            .resolve_from_config()?
            .print(&mounts::mount(&network, &peer, &share, mountpoint).await?),
        Commands::Unmount {
            mountpoint,
            force,
            output,
        } => output
            .resolve_from_config()?
            .print(&mounts::unmount(&mountpoint, force).await?),
        Commands::Mounts { output } => output
            .resolve_from_config()?
            .print(&call(Local::Mounts).await?),
        Commands::MountHelper { .. } => {
            bail!("mount helper must be dispatched before loading a profile")
        }
    }
}

type Backend = Arc<OnceCell<Arc<nfs::Server>>>;
pub struct Runtime {
    path: PathBuf,
    shares: watch::Sender<Vec<Share>>,
    servers: Mutex<HashMap<(String, PathBuf, String), Backend>>,
}
impl Runtime {
    pub fn new(path: PathBuf, cfg: &Config) -> Self {
        Self {
            path,
            shares: watch::channel(cfg.shares.clone()).0,
            servers: Mutex::new(HashMap::new()),
        }
    }
    pub fn update(&self, cfg: &Config) {
        self.shares.send_replace(if cfg.ensure_active().is_ok() {
            cfg.shares.clone()
        } else {
            Vec::new()
        });
    }
    pub fn has_shares(&self) -> bool {
        !self.shares.borrow().is_empty()
    }
    pub async fn server(&self, share: &Share) -> Result<Arc<nfs::Server>> {
        let incarnation = root_identity(&share.path)?;
        let cell = self
            .servers
            .lock()
            .await
            .entry((share.id.clone(), share.path.clone(), incarnation.clone()))
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();
        let parent = self.path.parent().context("invalid network config path")?;
        let profile = if parent.file_name().is_some_and(|p| p == "networks") {
            parent.parent().context("invalid profile path")?
        } else {
            parent
        };
        let state = profile.join("nfs");
        ensure_state_dir(&state)?;
        let state = state.join(
            self.path
                .file_stem()
                .context("invalid network config file")?,
        );
        ensure_state_dir(&state)?;
        let state = state.join(&share.id);
        ensure_state_dir(&state)?;
        // Replacing a share's path invalidates its old handles without
        // competing with in-flight sessions for the same database lock.
        let mut hasher = Sha256::new();
        hasher.update(share.path.as_os_str().as_encoded_bytes());
        hasher.update(incarnation.as_bytes());
        let digest = hasher.finalize();
        let state = state.join(
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        Ok(cell
            .get_or_try_init(|| async {
                Ok::<_, anyhow::Error>(Arc::new(nfs::Server::open(&share.path, &state).await?))
            })
            .await?
            .clone())
    }
}
fn root_identity(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).context("share directory is unavailable")?;
    if !metadata.is_dir() {
        bail!("share root is no longer a directory");
    }
    Ok(format!(
        "{}:{}:{:?}",
        metadata.dev(),
        metadata.ino(),
        metadata.created().ok()
    ))
}

#[derive(Encode, Decode)]
#[cbor(array)]
struct Setup {
    #[n(0)]
    hello: Hello,
    #[n(1)]
    share: Option<String>,
    #[n(2)]
    mount: String,
    #[n(3)]
    uid: u32,
    #[n(4)]
    gid: u32,
}

pub async fn receive(conn: Connection, actor: ConfigActorHandle, presence: Uuid) -> Result<()> {
    let (mut send, mut recv) = timeout(TCP_PROXY_SETUP_TIMEOUT, conn.accept_bi()).await??;
    let setup = timeout(TCP_PROXY_SETUP_TIMEOUT, async {
        let request: Setup =
            read_cbor_frame(&mut recv, MAX_CONTROL_MESSAGE_LEN, "NFS setup").await?;
        if request.hello.membership.is_none() || request.hello.invite_proof.is_some() {
            bail!("NFS requires established membership");
        }
        let peer = conn.remote_id();
        actor
            .control_sync(peer, request.hello.clone(), None)
            .await?;
        actor.connected(peer, presence).await?;
        let available = actor.files.shares.borrow().clone();
        if let Some(name) = &request.share {
            Uuid::parse_str(&request.mount).context("invalid mount identifier")?;
            let share = available
                .iter()
                .find(|s| (s.id == *name || s.name == *name) && s.allows(peer))
                .cloned()
                .ok_or_else(|| anyhow!("share unavailable or access denied"))?;
            Ok::<_, anyhow::Error>((request, Some(share), serde_json::Value::Null))
        } else {
            let shares: Vec<_> = available
                .iter()
                .filter(|s| s.allows(peer))
                .map(|s| serde_json::json!({"id": s.id, "name": s.name, "access": s.access}))
                .collect();
            Ok((request, None, serde_json::json!({"shares": shares})))
        }
    })
    .await
    .context("NFS setup timed out")
    .and_then(|r| r);
    let (request, share, listing) = match setup {
        Ok(v) => v,
        Err(e) => {
            write_cbor_frame(
                &mut send,
                &LocalProxyResponse::Error(format!("{e:#}")),
                MAX_CONTROL_MESSAGE_LEN,
                "NFS setup error",
            )
            .await?;
            finish_control_send(&mut send).await?;
            return Ok(());
        }
    };
    let incarnation = share.as_ref().map(|s| root_identity(&s.path)).transpose()?;
    let server = match &share {
        Some(s) => match actor.files.server(s).await {
            Ok(server) => Some(server),
            Err(e) => {
                write_cbor_frame(
                    &mut send,
                    &LocalProxyResponse::Error(format!("{e:#}")),
                    MAX_CONTROL_MESSAGE_LEN,
                    "NFS backend error",
                )
                .await?;
                finish_control_send(&mut send).await?;
                return Ok(());
            }
        },
        None => None,
    };
    write_cbor_frame(
        &mut send,
        &LocalProxyResponse::Ready,
        MAX_CONTROL_MESSAGE_LEN,
        "NFS ready",
    )
    .await?;
    if let (Some(share), Some(server)) = (share, server) {
        let mut changes = actor.files.shares.subscribe();
        let identity = format!("{}:{}", conn.remote_id(), request.mount);
        let incarnation = incarnation.context("missing share root identity")?;
        let policy = || {
            if root_identity(&share.path).ok().as_ref() != Some(&incarnation) {
                return None;
            }
            actor
                .files
                .shares
                .borrow()
                .iter()
                .find(|s| s.id == share.id && s.path == share.path && s.allows(conn.remote_id()))
                .map(|s| s.access == Access::Rw)
        };
        loop {
            // Keep a partially consumed RPC record alive across policy updates.
            let read = nfs::xdr::read_record(&mut recv);
            tokio::pin!(read);
            let record = loop {
                if policy().is_none() {
                    break None;
                }
                tokio::select! {
                    record = &mut read => break record?,
                    changed = changes.changed() => { if changed.is_err() { break None; } },
                }
            };
            let Some(record) = record else {
                break;
            };
            let response = server
                .rpc_authorized(&identity, request.uid, request.gid, &policy, &record)
                .await?;
            nfs::xdr::write_record(&mut send, &response).await?;
        }
    } else {
        write_cbor_frame(
            &mut send,
            &listing.to_string(),
            MAX_CONTROL_MESSAGE_LEN,
            "NFS share listing",
        )
        .await?;
    }
    finish_control_send(&mut send).await?;
    Ok(())
}

pub struct Tunnel {
    pub _conn: CloseConnectionOnDrop,
    pub send: SendStream,
    pub recv: RecvStream,
    pub active: ActiveConnectionGuard,
}
pub(super) async fn open(
    endpoint: &Endpoint,
    actor: &ConfigActorHandle,
    target: &str,
    share: Option<String>,
    mount: String,
    uid: u32,
    gid: u32,
) -> Result<Tunnel> {
    let cfg = actor
        .request(|respond| ConfigActorCommand::Snapshot { respond })
        .await?;
    let peer = cfg.resolve_peer(target)?.clone();
    let mut active = actor.register_connection(peer.node_id).await?;
    let result = tokio::select! {
        result = timeout(LOCAL_CONTROL_SETUP_TIMEOUT, async {
            let conn = CloseConnectionOnDrop(endpoint.connect(peer.node_id, ALPN).await?);
            let (mut send, mut recv) = conn.0.open_bi().await?;
            write_cbor_frame(&mut send, &Setup { hello: actor.hello().await?, share, mount, uid, gid }, MAX_CONTROL_MESSAGE_LEN, "NFS setup").await?;
            match read_cbor_frame(&mut recv, MAX_CONTROL_MESSAGE_LEN, "NFS ready").await? {
                LocalProxyResponse::Ready => {}, LocalProxyResponse::Error(e) => bail!(e),
            }
            Ok::<_,anyhow::Error>((conn,send,recv))
        }) => result??,
        _ = active.cancelled() => bail!("NFS peer revoked"),
    };
    active.connected().await?;
    Ok(Tunnel {
        _conn: result.0,
        send: result.1,
        recv: result.2,
        active,
    })
}
pub(super) async fn remote_list(
    endpoint: &Endpoint,
    actor: &ConfigActorHandle,
    peer: &str,
) -> Result<serde_json::Value> {
    let mut tunnel = open(endpoint, actor, peer, None, String::new(), 0, 0).await?;
    let json: String = timeout(
        TCP_PROXY_SETUP_TIMEOUT,
        read_cbor_frame(&mut tunnel.recv, MAX_CONTROL_MESSAGE_LEN, "NFS share list"),
    )
    .await??;
    Ok(serde_json::from_str(&json)?)
}
