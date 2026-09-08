//! Global preferences, UUID-indexed storage, and the shared daemon lifecycle.
use super::*;
use std::{io::IsTerminal, sync::Arc};
use tokio::sync::{Mutex, Notify, watch};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
#[cbor(array)]
pub struct TransportOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[n(0)]
    pub ports: Option<Vec<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[n(1)]
    pub max_connections_per_peer: Option<usize>,
}
impl TransportOverrides {
    pub(super) fn validate(&self) -> Result<()> {
        if let Some(ports) = &self.ports {
            validate_ports(ports)?;
        }
        if self.max_connections_per_peer == Some(0) {
            bail!("max_connections_per_peer must be positive");
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct TransportSettings {
    pub ports: Vec<u16>,
    pub max_connections_per_peer: usize,
}
impl Default for TransportSettings {
    fn default() -> Self {
        Self {
            ports: vec![22],
            max_connections_per_peer: 8,
        }
    }
}
fn validate_ports(ports: &[u16]) -> Result<()> {
    if ports.contains(&0) {
        bail!("port must be between 1 and 65535");
    }
    Ok(())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GlobalConfig {
    pub version: u8,
    #[serde(default)]
    pub format: output::FormatConfig,
    #[serde(default)]
    pub transport: TransportSettings,
}
impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            version: 3,
            format: output::FormatConfig::default(),
            transport: TransportSettings::default(),
        }
    }
}
impl GlobalConfig {
    pub(super) fn parse(text: &str) -> Result<Self> {
        let header: serde_yaml::Value = serde_yaml::from_str(text)?;
        if header.get("version").and_then(serde_yaml::Value::as_u64) != Some(3) {
            bail!(
                "unsupported esp config version; version 3 requires a coordinated upgrade and new networks (existing state has not been modified)"
            );
        }
        let cfg: Self = serde_yaml::from_str(text).context("invalid global esp configuration")?;
        validate_ports(&cfg.transport.ports)?;
        if cfg.transport.max_connections_per_peer == 0 {
            bail!("max_connections_per_peer must be positive");
        }
        Ok(cfg)
    }
    pub(super) fn load(path: &Path) -> Result<Self> {
        match read_private_config(path) {
            Ok(text) => Self::parse(&text),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(Self::default())
            }
            Err(e) => Err(e),
        }
    }
    pub(super) fn save(&self, path: &Path) -> Result<()> {
        write_private_config(path, serde_yaml::to_string(self)?.as_bytes())
    }
}

pub(super) fn effective_transport(
    global: &GlobalConfig,
    network: &TransportOverrides,
    flags: &TransportOverrides,
    serving: bool,
) -> Result<TransportSettings> {
    network.validate()?;
    flags.validate()?;
    Ok(TransportSettings {
        ports: if serving {
            flags
                .ports
                .clone()
                .or_else(|| network.ports.clone())
                .unwrap_or_else(|| global.transport.ports.clone())
        } else {
            Vec::new()
        },
        max_connections_per_peer: flags
            .max_connections_per_peer
            .or(network.max_connections_per_peer)
            .unwrap_or(global.transport.max_connections_per_peer),
    })
}

#[derive(Clone)]
pub(super) struct Store {
    pub(super) root: PathBuf,
}
impl Store {
    pub(super) fn local() -> Result<Self> {
        Ok(Self { root: esp_dir()? })
    }
    pub(super) fn prepare(&self) -> Result<GlobalConfig> {
        ensure_state_dir(&self.root)?;
        validate_private_dir_permissions(&self.root, &fs::symlink_metadata(&self.root)?)?;
        let path = self.root.join(CONFIG_FILE);
        let cfg = GlobalConfig::load(&path)?;
        if !path.try_exists()? {
            cfg.save(&path)?;
        }
        ensure_state_dir(&self.root.join("networks"))?;
        validate_private_dir_permissions(
            &self.root.join("networks"),
            &fs::symlink_metadata(self.root.join("networks"))?,
        )?;
        Ok(cfg)
    }
    pub(super) fn path(&self, id: &str) -> Result<PathBuf> {
        validate_network_id(id)?;
        if Uuid::parse_str(id)?.to_string() != id {
            bail!("network UUID must be canonical");
        }
        Ok(self.root.join("networks").join(format!("{id}.yml")))
    }
    fn paths(&self) -> Result<Vec<PathBuf>> {
        let dir = self.root.join("networks");
        if !dir.try_exists()? {
            return Ok(Vec::new());
        }
        validate_state_dir(&dir, &fs::symlink_metadata(&dir)?)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "yml") {
                paths.push(path);
            }
        }
        paths.sort();
        Ok(paths)
    }
    pub(super) fn load(&self, id: &str) -> Result<Config> {
        let cfg = Config::load(&self.path(id)?)?;
        if cfg.network_id != id {
            bail!("network file name does not match its signed UUID");
        }
        Ok(cfg)
    }
    pub(super) fn select(&self, label: &str) -> Result<Config> {
        GlobalConfig::load(&self.root.join(CONFIG_FILE))?;
        let label = normalize_network_label(label)?;
        let mut found = None;
        for path in self.paths()? {
            // Broken networks remain visible in status but do not disable healthy ones.
            if let Ok(cfg) = Config::load(&path) {
                if cfg.destruction.is_none()
                    && cfg.network_policy.admin_label.as_deref() == Some(&label)
                {
                    if found.is_some() {
                        bail!("duplicate local network label {label:?}");
                    }
                    if path != self.path(&cfg.network_id)? {
                        bail!("network file name does not match its signed UUID");
                    }
                    found = Some(cfg);
                }
            }
        }
        found.ok_or_else(|| anyhow!("no local network named {label:?}"))
    }
    fn label_available(&self, label: &str) -> Result<bool> {
        // Fail closed on unreadable state during creation, rather than risking a collision.
        for path in self.paths()? {
            let cfg = Config::load(&path)?;
            if cfg.destruction.is_none() && cfg.network_policy.admin_label.as_deref() == Some(label)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn init(&self, label: &str, max_peers: usize) -> Result<Config> {
        let label = normalize_network_label(label)?;
        validate_max_known_peers(max_peers)?;
        if !self.label_available(&label)? {
            return self.select(&label);
        }
        let cfg = create_creator_config(
            &label,
            &SecretKey::generate(),
            Uuid::new_v4().to_string(),
            default_connection_name(),
            generate_connection_id(),
            max_peers,
        )?;
        cfg.save(&self.path(&cfg.network_id)?)?;
        Ok(cfg)
    }
    async fn join(&self, code: &str) -> Result<Config> {
        let invite = Invite::decode(code)?;
        if self.path(&invite.network_id)?.try_exists()? {
            let cfg = self.load(&invite.network_id)?;
            cfg.ensure_active()?;
            bail!("network is already joined");
        }
        if !self.label_available(&invite.network_label)? {
            bail!(
                "network label {:?} is already used locally",
                invite.network_label
            );
        }
        // The manager mutex (or offline transport lock) reserves this label through redemption.
        let mut cfg = pending_config(&invite);
        let inviter = cfg.peers[0].clone();
        timeout(
            Duration::from_secs(30),
            sync_joined_config_once(&mut cfg, &inviter),
        )
        .await
        .context("join timed out")??;
        if cfg.network_policy.admin_label.as_deref() != Some(&invite.network_label) {
            bail!("invitation label does not match signed network policy");
        }
        save_completed_join(&self.path(&cfg.network_id)?, &cfg)?;
        Ok(cfg)
    }
}
fn pending_config(invite: &Invite) -> Config {
    Config {
        version: 3,
        transport: TransportOverrides::default(),
        destruction: None,
        network_id: invite.network_id.clone(),
        secret_key: encode_secret_key(&SecretKey::generate()),
        network_policy: pending_join_network_policy(
            &invite.network_id,
            invite.creator_node_id,
            &invite.network_label,
        ),
        creator_node_id: invite.creator_node_id,
        invite_proof: Some(InviteProof {
            invite_id: invite.invite_id.clone(),
            invite_secret: invite.invite_secret.clone(),
        }),
        membership: None,
        memberships: Vec::new(),
        name: default_connection_name(),
        connection_id: generate_connection_id(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: vec![Peer {
            node_id: invite.inviter_node_id,
            name: String::new(),
            connection_id: String::new(),
        }],
        revocations: Vec::new(),
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub(super) enum Request {
    #[n(30)]
    Network {
        #[n(0)]
        id: String,
        #[n(1)]
        request: LocalControlRequest,
    },
    #[n(31)]
    Status {
        #[n(0)]
        id: Option<String>,
        #[n(1)]
        peers: bool,
    },
    #[n(32)]
    Init {
        #[n(0)]
        label: String,
        #[n(1)]
        max_peers: usize,
    },
    #[n(33)]
    Join {
        #[n(0)]
        code: String,
    },
    #[n(34)]
    Destroy {
        #[n(0)]
        id: String,
        #[n(1)]
        global: bool,
    },
    #[n(35)]
    Promote {
        #[n(0)]
        flags: TransportOverrides,
    },
}
#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub(super) enum Response {
    #[n(30)]
    Network(#[n(0)] LocalControlResponse),
    #[n(31)]
    Report(#[n(0)] String),
    #[n(32)]
    Error(#[n(0)] String),
}
impl Response {
    fn report(value: serde_json::Value) -> Self {
        Self::Report(value.to_string())
    }
    pub(super) fn json(self) -> Result<serde_json::Value> {
        match self {
            Self::Report(json) => Ok(serde_json::from_str(&json)?),
            Self::Error(e) => bail!(e),
            _ => bail!("unexpected manager response"),
        }
    }
    pub(super) fn network(self) -> Result<LocalControlOk> {
        match self {
            Self::Network(r) => r.into_result(),
            Self::Error(e) => bail!(e),
            _ => bail!("unexpected network response"),
        }
    }
}

pub(super) struct Runtime {
    pub(super) actor: ConfigActorHandle,
    pub(super) endpoint: Endpoint,
    settings: watch::Sender<TransportSettings>,
    tasks: tokio::task::JoinSet<()>,
}
impl Runtime {
    async fn start(path: PathBuf, cfg: Config, settings: TransportSettings) -> Result<Self> {
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(cfg.secret_key()?)
            .alpns(vec![
                CONTROL_ALPN.to_vec(),
                TCP_ALPN.to_vec(),
                destruction::ALPN.to_vec(),
            ])
            .relay_mode(RelayMode::Default)
            .bind()
            .await?;
        Ok(Self::attach(path, cfg, settings, endpoint))
    }
    pub(super) fn attach(
        path: PathBuf,
        cfg: Config,
        settings: TransportSettings,
        endpoint: Endpoint,
    ) -> Self {
        if cfg.destruction.is_some() {
            endpoint.set_alpns(vec![destruction::ALPN.to_vec()]);
        }
        let actor = spawn_config_actor(path, cfg);
        let (settings, receiver) = watch::channel(settings);
        let mut tasks = tokio::task::JoinSet::new();
        let (ep, ac) = (endpoint.clone(), actor.clone());
        tasks.spawn(async move {
            if let Err(e) = run_acceptor_dynamic(ep, ac, receiver).await {
                warn!(error = %e, "network acceptor stopped");
            }
        });
        tasks.spawn(destruction::retry(endpoint.clone(), actor.clone()));
        Self {
            actor,
            endpoint,
            settings,
            tasks,
        }
    }
    pub(super) async fn stop(mut self) {
        let _ = self
            .actor
            .request(|respond| ConfigActorCommand::Stop { respond })
            .await;
        self.endpoint.close().await;
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}
struct Entry {
    runtime: Option<Runtime>,
    error: Option<String>,
}
pub(super) struct Manager {
    store: Store,
    global: GlobalConfig,
    flags: TransportOverrides,
    serving: bool,
    entries: HashMap<String, Entry>,
}
impl Manager {
    pub(super) async fn start(
        store: Store,
        serving: bool,
        flags: TransportOverrides,
    ) -> Result<Self> {
        let global = store.prepare()?;
        let mut manager = Self {
            store,
            global,
            flags,
            serving,
            entries: HashMap::new(),
        };
        for path in manager.store.paths()? {
            let id = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            manager.add(&id).await;
        }
        Ok(manager)
    }
    async fn add(&mut self, id: &str) {
        if self.entries.get(id).is_some_and(|e| e.runtime.is_some()) {
            return;
        }
        let result = async {
            let cfg = self.store.load(id)?;
            let settings =
                effective_transport(&self.global, &cfg.transport, &self.flags, self.serving)?;
            Runtime::start(self.store.path(id)?, cfg, settings).await
        }
        .await;
        self.entries.insert(
            id.into(),
            match result {
                Ok(runtime) => Entry {
                    runtime: Some(runtime),
                    error: None,
                },
                Err(e) => Entry {
                    runtime: None,
                    error: Some(format!("{e:#}")),
                },
            },
        );
    }
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) async fn replace_runtime(&mut self, id: &str, runtime: Runtime) {
        if let Some(entry) = self.entries.remove(id) {
            if let Some(old) = entry.runtime {
                old.stop().await;
            }
        }
        self.entries.insert(
            id.into(),
            Entry {
                runtime: Some(runtime),
                error: None,
            },
        );
    }
    pub(super) fn runtime(&self, id: &str) -> Result<&Runtime> {
        let entry = self
            .entries
            .get(id)
            .ok_or_else(|| anyhow!("network is no longer configured"))?;
        entry.runtime.as_ref().ok_or_else(|| {
            anyhow!(
                "{}",
                entry.error.as_deref().unwrap_or("network is unavailable")
            )
        })
    }
    pub(super) async fn promote(&mut self, flags: TransportOverrides) -> Result<()> {
        if self.serving {
            bail!("an esp foreground daemon is already running");
        }
        flags.validate()?;
        let global = GlobalConfig::load(&self.store.root.join(CONFIG_FILE))?;
        let mut settings = Vec::new();
        for (id, entry) in &self.entries {
            if entry.runtime.is_some() {
                settings.push((
                    id.clone(),
                    effective_transport(&global, &self.store.load(id)?.transport, &flags, true)?,
                ));
            }
        }
        for (id, settings) in settings {
            self.runtime(&id)?.settings.send_replace(settings);
        }
        self.flags = flags;
        self.global = global;
        self.serving = true;
        Ok(())
    }
    pub(super) async fn status(&self, id: Option<&str>, peers: bool) -> Result<serde_json::Value> {
        let mut networks = Vec::new();
        for (key, entry) in &self.entries {
            if id.is_some_and(|id| id != key) {
                continue;
            }
            if let Some(runtime) = &entry.runtime {
                let cfg = match runtime
                    .actor
                    .request(|respond| ConfigActorCommand::Snapshot { respond })
                    .await
                {
                    Ok(cfg) => cfg,
                    Err(error) => {
                        networks.push(serde_json::json!({"network_id": key, "network_label": self.store.load(key).ok().and_then(|cfg| cfg.network_policy.admin_label).unwrap_or_else(|| key.clone()), "transport": "error", "error": error.to_string()}));
                        continue;
                    }
                };
                if cfg.destruction.is_some() {
                    continue;
                }
                let report = runtime.actor.status().await?;
                let closed = runtime.endpoint.is_closed();
                let mut value = status_value(
                    &self.store.path(key)?,
                    &cfg,
                    &report,
                    if closed { "error" } else { "running" },
                    peers,
                    id.is_some(),
                    closed.then_some("network endpoint stopped"),
                );
                if id.is_some() {
                    value["transport_settings"] =
                        serde_json::json!(runtime.settings.borrow().clone());
                }
                networks.push(value);
            } else {
                let cfg = self.store.load(key).ok();
                networks.push(serde_json::json!({ "network_id": key, "network_label": cfg.as_ref().and_then(|c| c.network_policy.admin_label.clone()).unwrap_or_else(|| key.clone()), "transport": "error", "error": entry.error }));
            }
        }
        status_container(
            networks,
            id,
            if self.serving {
                "serving"
            } else {
                "outgoing_only"
            },
        )
    }
    pub(super) async fn lifecycle(&mut self, request: Request) -> Result<Response> {
        match request {
            Request::Init { label, max_peers } => {
                let cfg = self.store.init(&label, max_peers)?;
                self.global = GlobalConfig::load(&self.store.root.join(CONFIG_FILE))?;
                self.add(&cfg.network_id).await;
                Ok(Response::report(identity_report(&self.store, &cfg)?))
            }
            Request::Join { code } => {
                let cfg = self.store.join(&code).await?;
                self.global = GlobalConfig::load(&self.store.root.join(CONFIG_FILE))?;
                self.add(&cfg.network_id).await;
                Ok(Response::report(join_report(
                    &self.store.path(&cfg.network_id)?,
                    &cfg,
                )?))
            }
            Request::Destroy { id, global } => {
                let cfg = self.store.load(&id)?;
                cfg.ensure_active()?;
                if global {
                    if !self.serving {
                        bail!("global destruction requires a serving daemon");
                    }
                    self.runtime(&id)?
                        .actor
                        .request(|respond| ConfigActorCommand::Destroy {
                            certificate: None,
                            respond,
                        })
                        .await?;
                } else {
                    if let Some(entry) = self.entries.remove(&id) {
                        if let Some(runtime) = entry.runtime {
                            runtime.stop().await;
                        }
                    }
                    fs::remove_file(self.store.path(&id)?)?;
                    sync_parent_dir(&self.store.root.join("networks"))?;
                }
                Ok(Response::report(
                    serde_json::json!({ "network_id": id, "network_label": cfg.network_policy.admin_label, "destruction": if global { "recorded" } else { "removed_locally" }, "delivery_pending": global && !cfg.peers.is_empty() }),
                ))
            }
            Request::Status { id, peers } => {
                Ok(Response::report(self.status(id.as_deref(), peers).await?))
            }
            _ => bail!("invalid lifecycle request"),
        }
    }
    pub(super) async fn stop(&mut self) {
        for (_, entry) in self.entries.drain() {
            if let Some(runtime) = entry.runtime {
                runtime.stop().await;
            }
        }
    }
}

fn identity_report(store: &Store, cfg: &Config) -> Result<serde_json::Value> {
    Ok(
        serde_json::json!({ "esp_config": store.path(&cfg.network_id)?.display().to_string(), "network_id": cfg.network_id, "network_label": cfg.network_policy.admin_label, "name": cfg.name, "connection_id": cfg.connection_id, "node_id": cfg.secret_key()?.public().to_string(), "next_step": format!("run `esp invite {} \"name\"` to create an invite", shell_quote(cfg.network_policy.admin_label.as_deref().unwrap_or_default())) }),
    )
}
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
pub(super) fn status_value(
    path: &Path,
    cfg: &Config,
    report: &StatusReport,
    transport: &str,
    peers: bool,
    detailed: bool,
    error: Option<&str>,
) -> serde_json::Value {
    let mut value = if detailed {
        serde_json::to_value(report).expect("status serialization")
    } else {
        serde_json::json!({ "network_id": cfg.network_id, "network_label": cfg.network_policy.admin_label, "connected_peers": report.connected_peers })
    };
    value["role"] = serde_json::json!(cfg.local_membership_role());
    value["transport"] = serde_json::json!(transport);
    value["peer_count"] = serde_json::json!(cfg.peers.len());
    if detailed {
        value["config"] = serde_json::json!(path.display().to_string());
        value["transport_settings"] = serde_json::json!(cfg.transport);
    }
    if peers {
        value["peers"] = serde_json::json!(cfg.peers);
    }
    if let Some(error) = error {
        value["error"] = serde_json::json!(error);
    }
    value
}
fn status_container(
    mut networks: Vec<serde_json::Value>,
    id: Option<&str>,
    daemon: &str,
) -> Result<serde_json::Value> {
    networks.sort_by(|a, b| {
        a["network_label"]
            .as_str()
            .cmp(&b["network_label"].as_str())
    });
    if id.is_some() {
        return networks
            .pop()
            .ok_or_else(|| anyhow!("network is no longer active"));
    }
    Ok(serde_json::json!({ "daemon": daemon, "networks": networks }))
}
pub(super) fn offline_status(
    store: &Store,
    id: Option<&str>,
    peers: bool,
) -> Result<serde_json::Value> {
    let mut networks = Vec::new();
    for path in store.paths()? {
        let key = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if id.is_some_and(|id| id != key) {
            continue;
        }
        match store.load(&key) {
            Ok(cfg) if cfg.destruction.is_none() => networks.push(status_value(&path, &cfg, &status_report_from_config(&cfg)?, "not_running", peers, id.is_some(), None)),
            Ok(_) => {},
            Err(e) => networks.push(serde_json::json!({ "network_id": key, "network_label": key, "transport": "error", "error": format!("{e:#}") })),
        }
    }
    status_container(networks, id, "not_running")
}

pub(super) async fn dispatch_network(
    actor: ConfigActorHandle,
    endpoint: Endpoint,
    request: LocalControlRequest,
) -> Result<LocalControlOk> {
    match request {
        LocalControlRequest::Admin { request } => Ok(LocalControlOk::Admin {
            report: actor
                .request(|respond| ConfigActorCommand::Admin { request, respond })
                .await?,
        }),
        LocalControlRequest::Status => Ok(LocalControlOk::Status {
            report: actor.status().await?,
        }),
        LocalControlRequest::Rename { name } => {
            let identity = actor.rename(name).await?;
            Ok(LocalControlOk::Renamed {
                name: identity.name,
                connection_id: identity.connection_id,
            })
        }
        LocalControlRequest::IssueInvite { name, ports, role } => Ok(LocalControlOk::Invite {
            code: actor.issue_invite(name, ports, role).await?.code,
        }),
        LocalControlRequest::Revoke { target } => {
            let mut report = actor.revoke(target).await?;
            spawn_control_sync_broadcast(endpoint, actor, std::mem::take(&mut report.peers));
            Ok(LocalControlOk::Revoked { report })
        }
        LocalControlRequest::UpdatePolicy {
            max_peers,
            network_label,
        } => {
            let mut report = actor
                .update_policy_with_label(max_peers, network_label)
                .await?;
            spawn_control_sync_broadcast(endpoint, actor, std::mem::take(&mut report.peers));
            Ok(LocalControlOk::PolicyUpdated { report })
        }
        LocalControlRequest::Proxy { .. } => bail!("proxy requires a streaming connection"),
    }
}

#[cfg(unix)]
pub(super) async fn send(request: &Request) -> Result<Option<Response>> {
    send_to(&local_control_socket_path()?, request).await
}
#[cfg(unix)]
pub(super) async fn send_to(socket: &Path, request: &Request) -> Result<Option<Response>> {
    let mut stream = match UnixStream::connect(socket).await {
        Ok(s) => s,
        Err(e) if is_local_control_unavailable(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    timeout(Duration::from_secs(45), async {
        write_cbor_frame(
            &mut stream,
            request,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "version 3 local request",
        )
        .await?;
        read_cbor_frame(
            &mut stream,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "version 3 local response (stop older esp transports before upgrading)",
        )
        .await
        .map(Some)
    })
    .await
    .context("local manager request timed out")?
}
#[cfg(not(unix))]
pub(super) async fn send(_request: &Request) -> Result<Option<Response>> {
    bail!("esp requires Unix sockets");
}

#[cfg(unix)]
async fn call(request: Request) -> Result<Response> {
    let store = Store::local()?;
    // Validate old versions before creating or mutating any network state.
    GlobalConfig::load(&store.root.join(CONFIG_FILE))?;
    ensure_state_dir(&store.root)?;
    timeout(Duration::from_secs(60), async {
        loop {
            if let Some(response) = send(&request).await? {
                return Ok(response);
            }
            if let Some(_lock) = transport::try_lock(&local_control_socket_path()?)? {
                store.prepare()?;
                return offline(&store, request).await;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("timed out waiting for network lifecycle lock")?
}
#[cfg(not(unix))]
async fn call(_request: Request) -> Result<Response> {
    bail!("esp requires Unix sockets");
}

async fn offline(store: &Store, request: Request) -> Result<Response> {
    match request {
        Request::Init { label, max_peers } => Ok(Response::report(identity_report(
            store,
            &store.init(&label, max_peers)?,
        )?)),
        Request::Join { code } => {
            let cfg = store.join(&code).await?;
            Ok(Response::report(join_report(
                &store.path(&cfg.network_id)?,
                &cfg,
            )?))
        }
        Request::Status { id, peers } => Ok(Response::report(offline_status(
            store,
            id.as_deref(),
            peers,
        )?)),
        Request::Destroy { id, global } => {
            if global {
                bail!("global destruction requires an active serving daemon");
            }
            let cfg = store.load(&id)?;
            cfg.ensure_active()?;
            fs::remove_file(store.path(&id)?)?;
            sync_parent_dir(&store.root.join("networks"))?;
            Ok(Response::report(
                serde_json::json!({ "network_id": id, "network_label": cfg.network_policy.admin_label, "destruction": "removed_locally" }),
            ))
        }
        Request::Network { id, request } => {
            let mut cfg = store.load(&id)?;
            cfg.ensure_active()?;
            let result = match request {
                LocalControlRequest::Rename { name } => {
                    cfg.name = normalize_connection_name(&name)?;
                    LocalControlOk::Renamed {
                        name: cfg.name.clone(),
                        connection_id: cfg.connection_id.clone(),
                    }
                }
                LocalControlRequest::IssueInvite { name, ports, role } => LocalControlOk::Invite {
                    code: cfg.issue_invite(&name, &ports, role)?.code,
                },
                LocalControlRequest::Revoke { target } => LocalControlOk::Revoked {
                    report: cfg.issue_revocation(&target)?,
                },
                LocalControlRequest::UpdatePolicy {
                    max_peers,
                    network_label,
                } => LocalControlOk::PolicyUpdated {
                    report: cfg.issue_network_policy_with_label(max_peers, network_label)?,
                },
                LocalControlRequest::Status => {
                    return Ok(Response::Network(LocalControlResponse::ok(
                        LocalControlOk::Status {
                            report: status_report_from_config(&cfg)?,
                        },
                    )));
                }
                LocalControlRequest::Admin { request } => {
                    return Ok(Response::Network(LocalControlResponse::ok(
                        LocalControlOk::Admin {
                            report: admin::respond(&cfg, &HashMap::new(), request)?,
                        },
                    )));
                }
                _ => bail!("command requires a daemon"),
            };
            cfg.save(&store.path(&id)?)?;
            Ok(Response::Network(LocalControlResponse::ok(result)))
        }
        _ => bail!("command requires a daemon"),
    }
}

#[cfg(unix)]
async fn handle(
    mut stream: UnixStream,
    manager: Arc<Mutex<Manager>>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let request: Request = timeout(
        LOCAL_CONTROL_SETUP_TIMEOUT,
        read_cbor_frame(
            &mut stream,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "version 3 manager request",
        ),
    )
    .await??;
    if let Request::Promote { flags } = request {
        let result = manager.lock().await.promote(flags).await;
        let accepted = result.is_ok();
        let response = match result {
            Ok(()) => Response::report(serde_json::json!({ "daemon": "serving" })),
            Err(e) => Response::Error(e.to_string()),
        };
        // Ownership is transferred before replying. Even a failed reply must stop the helper.
        let result = async {
            write_cbor_frame(
                &mut stream,
                &response,
                MAX_LOCAL_CONTROL_MESSAGE_LEN,
                "promotion response",
            )
            .await?;
            if accepted {
                let mut byte = [0];
                let _ = stream.read(&mut byte).await;
            }
            Ok(())
        }
        .await;
        if accepted {
            shutdown.notify_one();
        }
        return result;
    }
    if let Request::Network { id, request } = request {
        let runtime = {
            let manager = manager.lock().await;
            manager
                .runtime(&id)
                .map(|r| (r.actor.clone(), r.endpoint.clone()))
        };
        if let LocalControlRequest::Proxy { target, port } = request {
            return match runtime {
                Ok((actor, endpoint)) => {
                    handle_local_proxy_connection(stream, actor, endpoint, target, port).await
                }
                Err(e) => {
                    write_cbor_frame(
                        &mut stream,
                        &LocalProxyResponse::Error(e.to_string()),
                        MAX_LOCAL_CONTROL_MESSAGE_LEN,
                        "proxy error",
                    )
                    .await
                }
            };
        }
        let result = match runtime {
            Ok((actor, endpoint)) => dispatch_network(actor, endpoint, request).await,
            Err(e) => Err(e),
        };
        let response = match result {
            Ok(ok) => Response::Network(LocalControlResponse::ok(ok)),
            Err(e) => Response::Error(format!("{e:#}")),
        };
        return write_cbor_frame(
            &mut stream,
            &response,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "network response",
        )
        .await;
    }
    let result = manager.lock().await.lifecycle(request).await;
    let response = match result {
        Ok(r) => r,
        Err(e) => Response::Error(format!("{e:#}")),
    };
    write_cbor_frame(
        &mut stream,
        &response,
        MAX_LOCAL_CONTROL_MESSAGE_LEN,
        "manager response",
    )
    .await
}

#[cfg(unix)]
pub(super) async fn serve(
    listener: UnixListener,
    store: Store,
    serving: bool,
    flags: TransportOverrides,
    idle_duration: Duration,
) -> Result<()> {
    let manager = Arc::new(Mutex::new(Manager::start(store, serving, flags).await?));
    serve_manager(listener, manager, idle_duration).await
}

#[cfg(unix)]
pub(super) async fn serve_manager(
    listener: UnixListener,
    manager: Arc<Mutex<Manager>>,
    idle_duration: Duration,
) -> Result<()> {
    let shutdown = Arc::new(Notify::new());
    let mut sessions = tokio::task::JoinSet::new();
    let idle = tokio::time::sleep(idle_duration);
    tokio::pin!(idle);
    let signal = shutdown_signal();
    tokio::pin!(signal);
    let result = loop {
        tokio::select! {
            _ = shutdown.notified() => break Ok(()),
            result = &mut signal => break result,
            accepted = listener.accept(), if sessions.len() < 128 => {
                match accepted {
                    Ok((stream, _)) => { let (manager, shutdown) = (manager.clone(), shutdown.clone()); sessions.spawn(async move { if let Err(e) = handle(stream, manager, shutdown).await { warn!(error = %e, "manager request failed"); } }); },
                    Err(e) => break Err(e.into()),
                }
            }
            _ = sessions.join_next(), if !sessions.is_empty() => { idle.as_mut().reset(tokio::time::Instant::now() + idle_duration); }
            _ = &mut idle, if sessions.is_empty() => {
                if !manager.lock().await.serving { break Ok(()); }
                idle.as_mut().reset(tokio::time::Instant::now() + idle_duration);
            }
        }
    };
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    manager.lock().await.stop().await;
    result
}

#[cfg(unix)]
async fn daemon(flags: TransportOverrides) -> Result<()> {
    let store = Store::local()?;
    ensure_state_dir(&store.root)?;
    flags.validate()?;
    let socket = local_control_socket_path()?;
    if let Some(mut lock) = transport::try_lock(&socket)? {
        store.prepare()?;
        lock.set_len(0)?;
        writeln!(lock, "{}", std::process::id())?;
        let (listener, _guard) = prepare_local_control_socket()?;
        return serve(listener, store, true, flags, PROXY_TRANSPORT_IDLE_TIMEOUT).await;
    }
    // A concurrent startup may own the lock before binding the socket.
    let mut stream = timeout(Duration::from_secs(30), async {
        loop {
            match UnixStream::connect(&socket).await {
                Ok(s) => return Ok::<_, anyhow::Error>(s),
                Err(e) if is_local_control_unavailable(&e) => {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(e) => return Err(e.into()),
            }
        }
    })
    .await
    .context("daemon startup timed out")??;
    write_cbor_frame(
        &mut stream,
        &Request::Promote { flags },
        MAX_LOCAL_CONTROL_MESSAGE_LEN,
        "daemon promotion",
    )
    .await?;
    let response: Response = timeout(
        Duration::from_secs(30),
        read_cbor_frame(
            &mut stream,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "daemon promotion response",
        ),
    )
    .await??;
    response.json()?;
    let mut byte = [0];
    tokio::select! { result = shutdown_signal() => result?, result = stream.read(&mut byte) => { result?; } }
    drop(stream);
    // Do not return while the promoted process still owns any network sessions.
    timeout(Duration::from_secs(15), async {
        loop {
            if transport::try_lock(&socket)?.is_some() {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("promoted daemon did not shut down")?
}
#[cfg(not(unix))]
async fn daemon(_flags: TransportOverrides) -> Result<()> {
    bail!("esp requires Unix sockets");
}

#[cfg(unix)]
pub(super) async fn request_proxy(
    mut stream: UnixStream,
    id: String,
    target: String,
    port: u16,
) -> Result<UnixStream> {
    timeout(Duration::from_secs(20), async {
        write_cbor_frame(
            &mut stream,
            &Request::Network {
                id,
                request: LocalControlRequest::Proxy { target, port },
            },
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "network proxy request",
        )
        .await?;
        let response: LocalProxyResponse = read_cbor_frame(
            &mut stream,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "network proxy response",
        )
        .await?;
        match response {
            LocalProxyResponse::Ready => Ok(()),
            LocalProxyResponse::Error(e) => bail!(e),
        }
    })
    .await
    .context("local proxy setup timed out")??;
    Ok(stream)
}

fn confirm_destroy(label: &str, global: bool, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("destroy requires --yes when input is not an interactive terminal");
    }
    eprint!(
        "{} network {label:?}? y/n ",
        if global {
            "Permanently destroy for every member"
        } else {
            "Remove locally"
        }
    );
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        bail!("destruction cancelled");
    }
    Ok(())
}
fn print_status(value: serde_json::Value, output: output::Options) -> Result<()> {
    println!("{}", status_output::render(&value, output)?);
    Ok(())
}
async fn scoped(label: &str, request: LocalControlRequest) -> Result<LocalControlOk> {
    let cfg = Store::local()?.select(label)?;
    call(Request::Network {
        id: cfg.network_id,
        request,
    })
    .await?
    .network()
}

pub(super) async fn execute(command: Command) -> Result<()> {
    GlobalConfig::load(&config_path()?)?;
    match command {
        Command::Init {
            network_label,
            max_peers,
            output,
        } => {
            let output = output.resolve_from_config()?;
            output.print(
                &call(Request::Init {
                    label: network_label,
                    max_peers,
                })
                .await?
                .json()?,
            )
        }
        Command::Join { invite, output } => {
            let output = output.resolve_from_config()?;
            output.print(&call(Request::Join { code: invite }).await?.json()?)
        }
        Command::Destroy {
            network,
            global,
            yes,
            output,
        } => {
            let output = output.resolve_from_config()?;
            let cfg = Store::local()?.select(&network)?;
            confirm_destroy(&network, global, yes)?;
            output.print(
                &call(Request::Destroy {
                    id: cfg.network_id,
                    global,
                })
                .await?
                .json()?,
            )
        }
        Command::Status {
            network,
            output,
            peers,
        } => {
            let output = output.resolve_from_config()?;
            let id = network
                .map(|n| Store::local()?.select(&n).map(|cfg| cfg.network_id))
                .transpose()?;
            print_status(call(Request::Status { id, peers }).await?.json()?, output)
        }
        Command::Rename {
            network,
            name,
            output,
        } => {
            let output = output.resolve_from_config()?;
            match scoped(&network, LocalControlRequest::Rename { name }).await? {
                LocalControlOk::Renamed {
                    name,
                    connection_id,
                } => print_identity(
                    &HostIdentity {
                        name,
                        connection_id,
                    },
                    output,
                ),
                _ => bail!("unexpected rename response"),
            }
        }
        Command::Invite {
            network,
            name,
            ports,
            role,
            output,
        } => {
            let output = output.resolve_from_config()?;
            let host = normalize_connection_name(&name)?;
            match scoped(
                &network,
                LocalControlRequest::IssueInvite { name, ports, role },
            )
            .await?
            {
                LocalControlOk::Invite { code } => output.print(&serde_json::json!({
                    "invite_code": code,
                    "next_step": format!(
                        "Copy this join code and run it on the host “{host}” with the command\n\nesp join {code}"
                    ),
                })),
                _ => bail!("unexpected invite response"),
            }
        }
        Command::Revoke {
            network,
            target,
            output,
        } => {
            let output = output.resolve_from_config()?;
            match scoped(&network, LocalControlRequest::Revoke { target }).await? {
                LocalControlOk::Revoked { report } => print_revocation_report(&report, output),
                _ => bail!("unexpected revoke response"),
            }
        }
        Command::Policy {
            network,
            max_peers,
            output,
        } => {
            let output = output.resolve_from_config()?;
            match scoped(
                &network,
                LocalControlRequest::UpdatePolicy {
                    max_peers,
                    network_label: None,
                },
            )
            .await?
            {
                LocalControlOk::PolicyUpdated { report } => print_policy_report(&report, output),
                _ => bail!("unexpected policy response"),
            }
        }
        Command::Daemon {
            ports,
            max_connections_per_peer,
        } => {
            daemon(TransportOverrides {
                ports,
                max_connections_per_peer: max_connections_per_peer.map(NonZeroUsize::get),
            })
            .await
        }
        #[cfg(unix)]
        Command::ProxyTransport => transport::run().await,
        Command::Proxy {
            network,
            target,
            port,
        } => {
            #[cfg(unix)]
            {
                let store = Store::local()?;
                let cfg = store.select(&network)?;
                let stream = transport::open_proxy(
                    &local_control_socket_path()?,
                    &store.path(&cfg.network_id)?,
                    &std::env::current_exe()?,
                    target,
                    port,
                )
                .await?;
                proxy_stdio(io::stdin(), io::stdout(), stream).await
            }
            #[cfg(not(unix))]
            {
                let _ = (network, target, port);
                bail!("esp requires Unix sockets");
            }
        }
        Command::Admin { network } => admin::run(network).await,
    }
}
