use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint, EndpointId, RelayMode, SecretKey, Signature,
    endpoint::{Connection, VarInt, presets},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot},
    time::timeout,
};
use tracing::{info, warn};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

const CONTROL_ALPN: &[u8] = b"esp/control/0";
const TCP_ALPN: &[u8] = b"esp/tcp/0";
const CONFIG_FILE: &str = ".esp.yml";
const LOCAL_CONTROL_SOCKET_FILE: &str = ".esp.sock";

#[cfg(unix)]
const CONFIG_FILE_MODE: u32 = 0o600;
pub const DEFAULT_ALLOWED_PORT: u16 = 22;
const MAX_PROXY_REQUEST_LEN: usize = 64 * 1024 - 1;
const MAX_CONTROL_MESSAGE_LEN: usize = 64 * 1024 - 1;
const MAX_LOCAL_CONTROL_MESSAGE_LEN: usize = 64 * 1024 - 1;
const CONFIG_ACTOR_QUEUE: usize = 64;
pub const MAX_SHARED_PEERS: usize = 100;
const GRACEFUL_CLOSE: VarInt = VarInt::from_u32(0);
const INVITE_VERSION: u8 = 2;
const MEMBERSHIP_CERTIFICATE_VERSION: u8 = 2;
const MEMBERSHIP_SIGNATURE_CONTEXT: &str = "esp/membership/2";
const CONNECTION_ID_ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[derive(Parser, Debug)]
#[command(about = "A tiny iroh-backed SSH transport proxy")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create ~/.esp.yml if needed.
    Init,
    /// Join an esp network from an invite code.
    Join {
        /// Invite code printed by the creator.
        invite: String,
    },
    /// Run the TCP proxy daemon. This is also the default command.
    Daemon {
        /// Localhost ports peers may connect to through this daemon.
        #[arg(long, value_delimiter = ',', default_value = "22")]
        ports: Vec<u16>,
    },
    /// Proxy stdio to localhost:PORT on a peer over iroh.
    Proxy {
        /// Peer name or six-character connection id from the esp config.
        target: String,
        /// TCP port to connect to on the peer's localhost.
        port: u16,
    },
    /// Rename this host in esp.
    Rename { name: String },
    /// Print a fresh invite code for the configured network.
    Invite {
        /// Localhost ports this invited peer may connect to on esp daemons.
        #[arg(long, value_delimiter = ',', default_value = "22")]
        ports: Vec<u16>,
    },
    /// Print local esp information.
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: u8,
    pub network_id: String,
    pub secret_key: String,
    #[serde(default)]
    pub creator_node_id: Option<EndpointId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_proof: Option<InviteProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<MembershipCertificate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memberships: Vec<MembershipCertificate>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub connection_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invites: Vec<IssuedInvite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub node_id: EndpointId,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub connection_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedInvite {
    pub invite_id: String,
    pub secret_hash: String,
    pub allowed_ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct InviteCode {
    pub invite_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub version: u8,
    pub network_id: String,
    pub invite_id: String,
    pub invite_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_node_id: Option<EndpointId>,
    pub inviter_node_id: EndpointId,
    #[serde(default)]
    pub inviter_name: String,
    #[serde(default)]
    pub inviter_connection_id: String,
    pub allowed_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub membership_chain: Vec<MembershipCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteProof {
    pub invite_id: String,
    pub invite_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipCertificate {
    pub version: u8,
    pub network_id: String,
    pub subject_node_id: EndpointId,
    pub subject_connection_id: String,
    pub allowed_ports: Vec<u16>,
    pub issuer_node_id: EndpointId,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Hello {
    network_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    connection_id: String,
    #[serde(default)]
    invite_proof: Option<InviteProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    membership: Option<MembershipCertificate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    memberships: Vec<MembershipCertificate>,
    #[serde(default)]
    peers: Vec<Peer>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ControlResponse {
    hello: Hello,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    granted_membership: Option<MembershipCertificate>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TcpProxyRequest {
    network_id: String,
    #[serde(default)]
    requester_name: String,
    #[serde(default)]
    requester_connection_id: String,
    #[serde(default)]
    invite_proof: Option<InviteProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    membership: Option<MembershipCertificate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    memberships: Vec<MembershipCertificate>,
    #[serde(default)]
    peers: Vec<Peer>,
    port: u16,
}

#[derive(Debug, Clone)]
struct HostIdentity {
    name: String,
    connection_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatusReport {
    network_id: String,
    name: String,
    connection_id: String,
    node_id: EndpointId,
    invites: Vec<String>,
    peers: Vec<Peer>,
}

#[derive(Clone)]
struct ConfigActorHandle {
    sender: mpsc::Sender<ConfigActorCommand>,
}

enum ConfigActorCommand {
    Status {
        respond: oneshot::Sender<Result<StatusReport>>,
    },
    Rename {
        name: String,
        respond: oneshot::Sender<Result<HostIdentity>>,
    },
    IssueInvite {
        allowed_ports: Vec<u16>,
        respond: oneshot::Sender<Result<InviteCode>>,
    },
    ControlSync {
        node_id: EndpointId,
        remote: Hello,
        expected_peer: Option<Peer>,
        respond: oneshot::Sender<Result<ControlResponse>>,
    },
    ProxyRequest {
        node_id: EndpointId,
        request: TcpProxyRequest,
        respond: oneshot::Sender<Result<Peer>>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
enum LocalControlRequest {
    Status,
    Rename { name: String },
    IssueInvite { ports: Vec<u16> },
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalControlResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<StatusReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renamed: Option<LocalRenameReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invite_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalRenameReport {
    name: String,
    connection_id: String,
}

#[derive(Debug)]
enum LocalControlOk {
    Status { report: StatusReport },
    Renamed { name: String, connection_id: String },
    Invite { code: String },
}

impl LocalControlResponse {
    fn ok(ok: LocalControlOk) -> Self {
        match ok {
            LocalControlOk::Status { report } => Self {
                error: None,
                status: Some(report),
                renamed: None,
                invite_code: None,
            },
            LocalControlOk::Renamed {
                name,
                connection_id,
            } => Self {
                error: None,
                status: None,
                renamed: Some(LocalRenameReport {
                    name,
                    connection_id,
                }),
                invite_code: None,
            },
            LocalControlOk::Invite { code } => Self {
                error: None,
                status: None,
                renamed: None,
                invite_code: Some(code),
            },
        }
    }

    fn err(error: String) -> Self {
        Self {
            error: Some(error),
            status: None,
            renamed: None,
            invite_code: None,
        }
    }

    fn into_result(self) -> Result<LocalControlOk> {
        if let Some(error) = self.error {
            bail!(error);
        }
        match (self.status, self.renamed, self.invite_code) {
            (Some(report), None, None) => Ok(LocalControlOk::Status { report }),
            (None, Some(renamed), None) => Ok(LocalControlOk::Renamed {
                name: renamed.name,
                connection_id: renamed.connection_id,
            }),
            (None, None, Some(code)) => Ok(LocalControlOk::Invite { code }),
            _ => bail!("invalid local esp control response"),
        }
    }
}

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Daemon {
        ports: vec![DEFAULT_ALLOWED_PORT],
    }) {
        Command::Init => init().await,
        Command::Join { invite } => join(&invite).await,
        Command::Daemon { ports } => daemon(ports).await,
        Command::Proxy { target, port } => proxy(target, port).await,
        Command::Rename { name } => rename(&name).await,
        Command::Invite { ports } => print_invite(&ports).await,
        Command::Status => status().await,
    }
}

async fn init() -> Result<()> {
    let path = config_path()?;
    if path.exists()
        && let Some(report) = request_daemon_status().await?
    {
        print_init_report(&path, &report);
        return Ok(());
    }

    let mut cfg = if path.exists() {
        Config::load(&path)?
    } else {
        let secret_key = SecretKey::generate();
        let cfg = Config {
            version: 1,
            network_id: Uuid::new_v4().to_string(),
            secret_key: encode_secret_key(&secret_key),
            creator_node_id: Some(secret_key.public()),
            invite_proof: None,
            membership: None,
            memberships: Vec::new(),
            name: default_connection_name(),
            connection_id: generate_connection_id(),
            invites: Vec::new(),
            peers: Vec::new(),
        };
        cfg.save(&path)?;
        cfg
    };
    cfg.ensure_local_config()?;
    cfg.save(&path)?;

    let report = status_report_from_config(&cfg)?;
    print_init_report(&path, &report);
    Ok(())
}

async fn join(invite_code: &str) -> Result<()> {
    let path = config_path()?;
    if path.exists() {
        bail!(
            "{} already exists; delete it first to leave the current esp network",
            path.display()
        );
    }

    let invite = Invite::decode(invite_code)?;
    let invite_allowed_ports = normalize_allowed_ports(&invite.allowed_ports)?;
    let secret_key = SecretKey::generate();
    let creator_node_id = invite.creator_node_id.unwrap_or(invite.inviter_node_id);
    let mut connection_id = generate_connection_id();
    while !invite.inviter_connection_id.is_empty() && connection_id == invite.inviter_connection_id
    {
        connection_id = generate_connection_id();
    }
    let cfg = Config {
        version: 1,
        network_id: invite.network_id,
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: Some(creator_node_id),
        invite_proof: Some(InviteProof {
            invite_id: invite.invite_id,
            invite_secret: invite.invite_secret,
        }),
        membership: None,
        memberships: invite.membership_chain.clone(),
        name: default_connection_name(),
        connection_id,
        invites: Vec::new(),
        peers: vec![Peer {
            node_id: invite.inviter_node_id,
            name: invite.inviter_name,
            connection_id: invite.inviter_connection_id,
        }],
    };
    cfg.save(&path)?;

    println!("esp config: {}", path.display());
    println!("name: {}", cfg.name);
    println!("connection id: {}", cfg.connection_id);
    println!("node id: {}", secret_key.public());
    println!("peer: {}", cfg.peers[0].display_name());
    println!("allowed ports: {}", format_ports(&invite_allowed_ports));

    match sync_joined_peer_once(&path, &cfg.peers[0]).await {
        Ok(()) => println!("join sync: complete"),
        Err(err) => println!("join sync: skipped ({err})"),
    }
    Ok(())
}

async fn rename(name: &str) -> Result<()> {
    if let Some(identity) = request_daemon_rename(name).await? {
        print_identity(&identity);
        return Ok(());
    }

    let path = config_path()?;
    let mut cfg = Config::load(&path)?;
    cfg.name = normalize_connection_name(name)?;
    cfg.save(&path)?;
    let identity = host_identity_from_config(&cfg);
    print_identity(&identity);
    Ok(())
}

async fn print_invite(ports: &[u16]) -> Result<()> {
    let allowed_ports = normalize_allowed_ports(ports)?;
    if let Some(code) = request_daemon_invite(&allowed_ports).await? {
        println!("{code}");
        return Ok(());
    }

    let path = config_path()?;
    let mut cfg = Config::load(&path)?;
    let invite = cfg.issue_invite(&allowed_ports)?;
    cfg.save(&path)?;
    println!("{}", invite.code);
    Ok(())
}

async fn status() -> Result<()> {
    let path = config_path()?;
    if let Some(report) = request_daemon_status().await? {
        print_status_report(&path, &report);
        return Ok(());
    }

    let cfg = Config::load(&path)?;
    let report = status_report_from_config(&cfg)?;
    print_status_report(&path, &report);
    Ok(())
}

async fn request_daemon_status() -> Result<Option<StatusReport>> {
    let Some(response) = send_local_control_request(LocalControlRequest::Status).await? else {
        return Ok(None);
    };
    match response {
        LocalControlOk::Status { report } => Ok(Some(report)),
        _ => bail!("daemon returned unexpected response to status request"),
    }
}

async fn request_daemon_rename(name: &str) -> Result<Option<HostIdentity>> {
    let Some(response) = send_local_control_request(LocalControlRequest::Rename {
        name: name.to_string(),
    })
    .await?
    else {
        return Ok(None);
    };
    match response {
        LocalControlOk::Renamed {
            name,
            connection_id,
        } => Ok(Some(HostIdentity {
            name,
            connection_id,
        })),
        _ => bail!("daemon returned unexpected response to rename request"),
    }
}

async fn request_daemon_invite(ports: &[u16]) -> Result<Option<String>> {
    let Some(response) = send_local_control_request(LocalControlRequest::IssueInvite {
        ports: ports.to_vec(),
    })
    .await?
    else {
        return Ok(None);
    };
    match response {
        LocalControlOk::Invite { code } => Ok(Some(code)),
        _ => bail!("daemon returned unexpected response to invite request"),
    }
}

async fn send_local_control_request(
    request: LocalControlRequest,
) -> Result<Option<LocalControlOk>> {
    #[cfg(unix)]
    {
        let path = local_control_socket_path()?;
        send_local_control_request_to_path(&path, request).await
    }

    #[cfg(not(unix))]
    {
        drop(request);
        Ok(None)
    }
}

#[cfg(unix)]
async fn send_local_control_request_to_path(
    path: &Path,
    request: LocalControlRequest,
) -> Result<Option<LocalControlOk>> {
    let mut stream = match UnixStream::connect(path).await {
        Ok(stream) => stream,
        Err(err) if is_local_control_unavailable(&err) => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to connect to {}", path.display()));
        }
    };
    timeout(Duration::from_secs(5), async {
        write_yaml_frame(
            &mut stream,
            &request,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "local esp control request",
        )
        .await?;

        let response: LocalControlResponse = read_yaml_frame(
            &mut stream,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "local esp control response",
        )
        .await?;
        response.into_result().map(Some)
    })
    .await
    .context("timed out waiting for local esp control response")?
}

#[cfg(unix)]
fn is_local_control_unavailable(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

fn host_identity_from_config(cfg: &Config) -> HostIdentity {
    HostIdentity {
        name: cfg.name.clone(),
        connection_id: cfg.connection_id.clone(),
    }
}

fn status_report_from_config(cfg: &Config) -> Result<StatusReport> {
    Ok(StatusReport {
        network_id: cfg.network_id.clone(),
        name: cfg.name.clone(),
        connection_id: cfg.connection_id.clone(),
        node_id: cfg.secret_key()?.public(),
        invites: cfg
            .invites
            .iter()
            .map(|invite| invite.invite_id.clone())
            .collect(),
        peers: cfg.peers.clone(),
    })
}

fn print_init_report(path: &Path, report: &StatusReport) {
    println!("esp config: {}", path.display());
    println!("name: {}", report.name);
    println!("connection id: {}", report.connection_id);
    println!("node id: {}", report.node_id);
    println!("run `esp invite` to create an invite");
}

fn print_identity(identity: &HostIdentity) {
    println!("name: {}", identity.name);
    println!("connection id: {}", identity.connection_id);
}

fn print_status_report(path: &Path, report: &StatusReport) {
    println!("esp config: {}", path.display());
    println!("network: {}", report.network_id);
    println!("name: {}", report.name);
    println!("connection id: {}", report.connection_id);
    println!("node id: {}", report.node_id);
    for invite in &report.invites {
        println!("issued invite: {invite}");
    }
    for peer in &report.peers {
        println!("peer: {} {}", peer.display_name(), peer.node_id);
    }
}

async fn daemon(allowed_ports: Vec<u16>) -> Result<()> {
    let allowed_ports = normalize_allowed_ports(&allowed_ports)?;
    #[cfg(unix)]
    let (local_control_listener, _local_control_socket) =
        prepare_local_control_socket().context("failed to start local esp control")?;

    let path = config_path()?;
    let cfg = Config::load(&path)?;
    let secret_key = cfg.secret_key()?;
    let actor = spawn_config_actor(path, cfg);
    #[cfg(unix)]
    let local_control_task = spawn_local_control_server(local_control_listener, actor.clone());

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![CONTROL_ALPN.to_vec(), TCP_ALPN.to_vec()])
        .relay_mode(RelayMode::Default)
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;

    info!(node_id = %endpoint.id(), "esp endpoint bound");
    endpoint.online().await;
    info!(addr = ?endpoint.addr(), "esp endpoint online");

    info!(ports = ?allowed_ports, "esp TCP proxy port allowlist active");
    let accept_result = run_acceptor(endpoint.clone(), actor, allowed_ports).await;
    #[cfg(unix)]
    local_control_task.abort();
    accept_result?;
    endpoint.close().await;
    Ok(())
}

#[cfg(unix)]
struct LocalControlSocket {
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for LocalControlSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn prepare_local_control_socket() -> Result<(UnixListener, LocalControlSocket)> {
    let path = local_control_socket_path()?;
    let listener = bind_local_control_socket(&path)?;
    let guard = LocalControlSocket { path: path.clone() };
    info!(path = %path.display(), "local esp control socket listening");
    Ok((listener, guard))
}

#[cfg(unix)]
fn spawn_local_control_server(
    listener: UnixListener,
    actor: ConfigActorHandle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_local_control_server(listener, actor))
}

#[cfg(unix)]
fn local_control_socket_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(LOCAL_CONTROL_SOCKET_FILE))
}

#[cfg(unix)]
fn bind_local_control_socket(path: &Path) -> Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                bail!(
                    "{} is a symlink; refusing to use it as esp control socket",
                    path.display()
                );
            }
            if !file_type.is_socket() {
                bail!("{} exists and is not a socket", path.display());
            }
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => bail!(
                    "esp daemon already appears to be running at {}",
                    path.display()
                ),
                Err(err) if is_local_control_unavailable(&err) => {
                    fs::remove_file(path)
                        .with_context(|| format!("failed to remove stale {}", path.display()))?;
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("failed to inspect {}", path.display()));
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }

    let listener =
        UnixListener::bind(path).with_context(|| format!("failed to bind {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(CONFIG_FILE_MODE))
        .with_context(|| format!("failed to set private permissions on {}", path.display()))?;
    Ok(listener)
}

#[cfg(unix)]
async fn run_local_control_server(listener: UnixListener, actor: ConfigActorHandle) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let actor = actor.clone();
                tokio::spawn(async move {
                    match timeout(
                        Duration::from_secs(15),
                        handle_local_control_connection(stream, actor),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            warn!(error = %err, "local esp control request failed");
                        }
                        Err(_) => {
                            warn!("local esp control request timed out");
                        }
                    }
                });
            }
            Err(err) => {
                warn!(error = %err, "local esp control listener failed");
                return;
            }
        }
    }
}

#[cfg(unix)]
async fn handle_local_control_connection(
    mut stream: UnixStream,
    actor: ConfigActorHandle,
) -> Result<()> {
    let result = match read_yaml_frame(
        &mut stream,
        MAX_LOCAL_CONTROL_MESSAGE_LEN,
        "local esp control request",
    )
    .await
    {
        Ok(LocalControlRequest::Status) => actor
            .status()
            .await
            .map(|report| LocalControlOk::Status { report }),
        Ok(LocalControlRequest::Rename { name }) => {
            actor
                .rename(name)
                .await
                .map(|identity| LocalControlOk::Renamed {
                    name: identity.name,
                    connection_id: identity.connection_id,
                })
        }
        Ok(LocalControlRequest::IssueInvite { ports }) => actor
            .issue_invite(ports)
            .await
            .map(|invite| LocalControlOk::Invite { code: invite.code }),
        Err(err) => Err(err),
    };
    let response = match result {
        Ok(ok) => LocalControlResponse::ok(ok),
        Err(err) => LocalControlResponse::err(err.to_string()),
    };
    write_yaml_frame(
        &mut stream,
        &response,
        MAX_LOCAL_CONTROL_MESSAGE_LEN,
        "local esp control response",
    )
    .await?;
    stream
        .shutdown()
        .await
        .context("failed to finish local esp control response")?;
    Ok(())
}

async fn sync_joined_peer_once(path: &Path, inviter: &Peer) -> Result<()> {
    let cfg = Config::load(path)?;
    let secret_key = cfg.secret_key()?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Default)
        .bind()
        .await
        .context("failed to bind iroh endpoint for join sync")?;

    let result = async {
        let conn = endpoint
            .connect(inviter.node_id, CONTROL_ALPN)
            .await
            .with_context(|| format!("failed to connect to inviter {}", inviter.node_id))?;
        sync_control_client(&conn, path, inviter).await?;
        conn.close(GRACEFUL_CLOSE, b"synced");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    endpoint.close().await;
    result
}

async fn run_acceptor(
    endpoint: Endpoint,
    actor: ConfigActorHandle,
    allowed_ports: Vec<u16>,
) -> Result<()> {
    info!("accepting esp control and TCP proxy connections");
    while let Some(incoming) = endpoint.accept().await {
        let actor = actor.clone();
        let allowed_ports = allowed_ports.clone();
        tokio::spawn(async move {
            let accepting = match incoming.accept() {
                Ok(accepting) => accepting,
                Err(err) => {
                    warn!(error = %err, "failed to accept incoming esp connection");
                    return;
                }
            };
            let remote_addr = accepting.remote_addr();

            match accepting.await {
                Ok(conn) => {
                    let alpn = conn.alpn().to_vec();
                    info!(
                        peer = %conn.remote_id(),
                        remote_addr = ?remote_addr,
                        alpn = %String::from_utf8_lossy(&alpn),
                        "accepted esp connection"
                    );
                    let result = if alpn == CONTROL_ALPN {
                        handle_control_connection(conn, actor).await
                    } else if alpn == TCP_ALPN {
                        handle_tcp_proxy_connection(conn, actor, &allowed_ports).await
                    } else {
                        conn.close(GRACEFUL_CLOSE, b"unknown alpn");
                        Ok(())
                    };
                    if let Err(err) = result {
                        warn!(error = %err, "esp connection stopped");
                    }
                }
                Err(err) => warn!(error = %err, "incoming esp connection failed"),
            }
        });
    }
    Ok(())
}

async fn handle_control_connection(conn: Connection, actor: ConfigActorHandle) -> Result<()> {
    sync_control_server(&conn, actor).await?;
    conn.close(GRACEFUL_CLOSE, b"synced");
    Ok(())
}

async fn sync_control_client(conn: &Connection, path: &Path, expected_peer: &Peer) -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let mut cfg = Config::load(path)?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open esp control stream")?;
        write_control_hello(&mut send, &hello_from_config(&cfg)).await?;
        send.finish()
            .context("failed to finish esp control send stream")?;

        let response = read_control_response(&mut recv).await?;
        let remote = response.hello;
        let peer = validate_peer_report(&cfg, conn.remote_id(), &remote, Some(expected_peer))?;
        let remote_memberships = memberships_from_hello(&remote);
        remember_control_peer(
            path,
            &mut cfg,
            peer.clone(),
            true,
            remote.invite_proof.as_ref(),
            remote.membership.as_ref(),
            &remote_memberships,
        )?;
        remember_advertised_peers_with_memberships(
            path,
            &mut cfg,
            &peer,
            remote.peers,
            remote_memberships.clone(),
        )?;
        if let Some(grant) = response.granted_membership {
            remember_local_membership_grant(path, &mut cfg, grant, &remote_memberships)?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("timed out waiting for esp control sync")?
}

async fn sync_control_server(conn: &Connection, actor: ConfigActorHandle) -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .context("failed to accept esp control stream")?;
        let remote = read_control_hello(&mut recv).await?;
        let response = actor.control_sync(conn.remote_id(), remote, None).await?;
        write_control_response(&mut send, &response).await?;
        send.finish()
            .context("failed to finish esp control send stream")?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("timed out waiting for esp control sync")?
}

fn spawn_config_actor(path: PathBuf, cfg: Config) -> ConfigActorHandle {
    let (sender, receiver) = mpsc::channel(CONFIG_ACTOR_QUEUE);
    tokio::spawn(run_config_actor(path, cfg, receiver));
    ConfigActorHandle { sender }
}

async fn run_config_actor(
    path: PathBuf,
    mut cfg: Config,
    mut receiver: mpsc::Receiver<ConfigActorCommand>,
) {
    while let Some(command) = receiver.recv().await {
        match command {
            ConfigActorCommand::Status { respond } => {
                let _ = respond.send(status_report_from_config(&cfg));
            }
            ConfigActorCommand::Rename { name, respond } => {
                let result = commit_config_change(&path, &mut cfg, |next| {
                    next.name = normalize_connection_name(&name)?;
                    Ok((host_identity_from_config(next), true))
                });
                let _ = respond.send(result);
            }
            ConfigActorCommand::IssueInvite {
                allowed_ports,
                respond,
            } => {
                let result = commit_config_change(&path, &mut cfg, |next| {
                    let invite = next.issue_invite(&allowed_ports)?;
                    Ok((invite, true))
                });
                let _ = respond.send(result);
            }
            ConfigActorCommand::ControlSync {
                node_id,
                remote,
                expected_peer,
                respond,
            } => {
                let result = commit_config_change(&path, &mut cfg, |next| {
                    apply_control_sync(next, node_id, remote, expected_peer)
                });
                let _ = respond.send(result);
            }
            ConfigActorCommand::ProxyRequest {
                node_id,
                request,
                respond,
            } => {
                let result = commit_config_change(&path, &mut cfg, |next| {
                    apply_proxy_request(next, node_id, request)
                });
                let _ = respond.send(result);
            }
        }
    }
}

fn commit_config_change<T>(
    path: &Path,
    cfg: &mut Config,
    apply: impl FnOnce(&mut Config) -> Result<(T, bool)>,
) -> Result<T> {
    let mut next = cfg.clone();
    let (output, changed) = apply(&mut next)?;
    if changed {
        next.save(path)?;
    }
    *cfg = next;
    Ok(output)
}

impl ConfigActorHandle {
    async fn status(&self) -> Result<StatusReport> {
        self.request(|respond| ConfigActorCommand::Status { respond })
            .await
    }

    async fn rename(&self, name: String) -> Result<HostIdentity> {
        self.request(|respond| ConfigActorCommand::Rename { name, respond })
            .await
    }

    async fn issue_invite(&self, allowed_ports: Vec<u16>) -> Result<InviteCode> {
        self.request(|respond| ConfigActorCommand::IssueInvite {
            allowed_ports,
            respond,
        })
        .await
    }

    async fn control_sync(
        &self,
        node_id: EndpointId,
        remote: Hello,
        expected_peer: Option<Peer>,
    ) -> Result<ControlResponse> {
        self.request(|respond| ConfigActorCommand::ControlSync {
            node_id,
            remote,
            expected_peer,
            respond,
        })
        .await
    }

    async fn proxy_request(&self, node_id: EndpointId, request: TcpProxyRequest) -> Result<Peer> {
        self.request(|respond| ConfigActorCommand::ProxyRequest {
            node_id,
            request,
            respond,
        })
        .await
    }

    async fn request<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T>>) -> ConfigActorCommand,
    ) -> Result<T> {
        let (respond, receive) = oneshot::channel();
        self.sender
            .send(build(respond))
            .await
            .map_err(|_| anyhow!("config actor stopped"))?;
        receive.await.context("config actor dropped response")?
    }
}

fn apply_control_sync(
    cfg: &mut Config,
    node_id: EndpointId,
    remote: Hello,
    expected_peer: Option<Peer>,
) -> Result<(ControlResponse, bool)> {
    let peer = validate_peer_report(cfg, node_id, &remote, expected_peer.as_ref())?;
    let remote_memberships = memberships_from_hello(&remote);
    let (granted_membership, mut changed) = remember_control_peer_in_config(
        cfg,
        peer.clone(),
        expected_peer.is_some(),
        remote.invite_proof.as_ref(),
        remote.membership.as_ref(),
        &remote_memberships,
    )?;
    changed |= remember_advertised_peers_in_config(cfg, &peer, remote.peers, remote_memberships)?;
    let response = ControlResponse {
        hello: hello_from_config(cfg),
        granted_membership,
    };
    Ok((response, changed))
}

fn apply_proxy_request(
    cfg: &mut Config,
    node_id: EndpointId,
    request: TcpProxyRequest,
) -> Result<(Peer, bool)> {
    let expected = cfg.peer_by_id(node_id).cloned();
    let reported = Hello {
        network_id: request.network_id,
        name: request.requester_name,
        connection_id: request.requester_connection_id,
        invite_proof: request.invite_proof,
        membership: request.membership,
        memberships: request.memberships,
        peers: Vec::new(),
    };
    let peer = validate_peer_report(cfg, node_id, &reported, expected.as_ref())?;
    let remote_memberships = memberships_from_hello(&reported);
    let requested_port = request.port;
    let mut changed = remember_proxy_peer_in_config(
        cfg,
        peer.clone(),
        reported.membership.as_ref(),
        &remote_memberships,
        requested_port,
    )?;
    changed |= remember_advertised_peers_in_config(cfg, &peer, request.peers, remote_memberships)?;
    Ok((peer, changed))
}

fn validate_peer_report(
    cfg: &Config,
    node_id: EndpointId,
    remote: &Hello,
    expected_peer: Option<&Peer>,
) -> Result<Peer> {
    if remote.network_id != cfg.network_id {
        bail!("peer joined a different esp network");
    }
    if !is_valid_connection_id(&remote.connection_id) {
        bail!("peer reported invalid connection id");
    }
    let remote_name = normalize_connection_name(&remote.name)?;
    if let Some(peer) = expected_peer {
        if node_id != peer.node_id {
            bail!("peer node id {}, expected {}", node_id, peer.node_id);
        }
        if peer.has_identity() && remote.connection_id != peer.connection_id {
            bail!(
                "peer connection id {}, expected {}",
                remote.connection_id,
                peer.connection_id
            );
        }
        return Ok(Peer {
            node_id,
            name: remote_name,
            connection_id: remote.connection_id.clone(),
        });
    }
    Ok(Peer {
        node_id,
        name: remote_name,
        connection_id: remote.connection_id.clone(),
    })
}

fn remember_control_peer(
    path: &Path,
    cfg: &mut Config,
    peer: Peer,
    was_expected: bool,
    invite_proof: Option<&InviteProof>,
    direct_membership: Option<&MembershipCertificate>,
    extra_memberships: &[MembershipCertificate],
) -> Result<Option<MembershipCertificate>> {
    let (granted_membership, changed) = remember_control_peer_in_config(
        cfg,
        peer,
        was_expected,
        invite_proof,
        direct_membership,
        extra_memberships,
    )?;
    if changed {
        cfg.save(path)?;
    }
    Ok(granted_membership)
}

fn remember_control_peer_in_config(
    cfg: &mut Config,
    peer: Peer,
    was_expected: bool,
    invite_proof: Option<&InviteProof>,
    direct_membership: Option<&MembershipCertificate>,
    extra_memberships: &[MembershipCertificate],
) -> Result<(Option<MembershipCertificate>, bool)> {
    let verified_membership =
        verified_membership_for_peer(cfg, &peer, direct_membership, extra_memberships)?;
    let mut changed = false;
    if let Some(membership) = verified_membership.as_ref() {
        changed |= insert_membership(cfg, membership.clone())?;
        changed |= insert_peer(cfg, peer)?;
        return Ok((None, changed));
    }

    let Some(granted_membership) = consume_invite_and_issue_membership(cfg, &peer, invite_proof)?
    else {
        if was_expected || cfg.peer_by_id(peer.node_id).is_some() {
            bail!(
                "rejecting peer {} without a valid membership certificate",
                peer.node_id
            );
        }
        bail!(
            "rejecting unknown peer {} without invite or valid membership",
            peer.node_id
        );
    };
    changed = true;

    info!(peer = %peer.node_id, "remembering invited peer");
    changed |= insert_membership(cfg, granted_membership.clone())?;
    changed |= insert_peer(cfg, peer)?;
    Ok((Some(granted_membership), changed))
}

fn remember_proxy_peer_in_config(
    cfg: &mut Config,
    peer: Peer,
    direct_membership: Option<&MembershipCertificate>,
    extra_memberships: &[MembershipCertificate],
    port: u16,
) -> Result<bool> {
    let verified_membership =
        verified_membership_for_peer(cfg, &peer, direct_membership, extra_memberships)?;
    let Some(membership) = verified_membership else {
        bail!(
            "rejecting peer {} without a valid membership certificate",
            peer.node_id
        );
    };
    ensure_membership_allows_port(&peer, &membership, port)?;

    let mut changed = false;
    changed |= insert_membership(cfg, membership)?;
    changed |= insert_peer(cfg, peer)?;
    Ok(changed)
}

pub fn remember_advertised_peers(
    path: &Path,
    cfg: &mut Config,
    remote_peer: &Peer,
    advertised_peers: Vec<Peer>,
) -> Result<()> {
    remember_advertised_peers_with_memberships(path, cfg, remote_peer, advertised_peers, Vec::new())
}

fn remember_advertised_peers_with_memberships(
    path: &Path,
    cfg: &mut Config,
    remote_peer: &Peer,
    advertised_peers: Vec<Peer>,
    advertised_memberships: Vec<MembershipCertificate>,
) -> Result<()> {
    if remember_advertised_peers_in_config(
        cfg,
        remote_peer,
        advertised_peers,
        advertised_memberships,
    )? {
        cfg.save(path)?;
    }
    Ok(())
}

fn remember_advertised_peers_in_config(
    cfg: &mut Config,
    remote_peer: &Peer,
    advertised_peers: Vec<Peer>,
    advertised_memberships: Vec<MembershipCertificate>,
) -> Result<bool> {
    ensure_shared_list_size("peers", advertised_peers.len())?;
    ensure_shared_list_size("memberships", advertised_memberships.len())?;

    let mut changed = false;
    for membership in &advertised_memberships {
        if verify_membership_chain(cfg, membership, &advertised_memberships).is_ok() {
            changed |= insert_membership(cfg, membership.clone())?;
        }
    }

    for peer in advertised_peers {
        if peer.node_id == remote_peer.node_id {
            continue;
        }
        let membership = verified_membership_for_peer(cfg, &peer, None, &advertised_memberships)?;
        if let Some(membership) = membership {
            changed |= insert_membership(cfg, membership)?;
        } else {
            bail!("advertised peer {} has no valid membership", peer.node_id);
        }
        if insert_peer(cfg, peer)? {
            changed = true;
        }
    }
    Ok(changed)
}

fn insert_peer(cfg: &mut Config, peer: Peer) -> Result<bool> {
    let local_node_id = cfg.secret_key()?.public();
    if !peer.has_identity() {
        bail!("peer {} has no connection identity", peer.node_id);
    }
    if peer.node_id == local_node_id {
        if peer.connection_id != cfg.connection_id {
            bail!(
                "local node id was advertised with different connection id {}",
                peer.connection_id
            );
        }
        return Ok(false);
    }
    if peer.connection_id == cfg.connection_id {
        bail!(
            "connection id {} belongs to this host and peer {}",
            peer.connection_id,
            peer.node_id
        );
    }
    if let Some(existing) = cfg.peer_by_id(peer.node_id) {
        if existing.has_identity() && existing.connection_id != peer.connection_id {
            bail!(
                "peer {} changed connection id from {} to {}",
                peer.node_id,
                existing.connection_id,
                peer.connection_id
            );
        }
        let existing = cfg
            .peers
            .iter_mut()
            .find(|existing| existing.node_id == peer.node_id)
            .expect("peer_by_id found this peer");
        let changed = existing.name != peer.name || existing.connection_id != peer.connection_id;
        existing.name = peer.name;
        existing.connection_id = peer.connection_id;
        return Ok(changed);
    }
    if let Some(existing) = cfg.peer_by_connection_id(&peer.connection_id) {
        bail!(
            "connection id {} belongs to {}, not {}",
            peer.connection_id,
            existing.node_id,
            peer.node_id
        );
    }
    info!(
        peer = %peer.node_id,
        peer_id = %peer.connection_id,
        peer_name = %peer.name,
        "remembering esp peer"
    );
    cfg.peers.push(peer);
    cfg.peers
        .sort_by(|left, right| left.connection_id.cmp(&right.connection_id));
    Ok(true)
}

async fn proxy(target: String, port: u16) -> Result<()> {
    let cfg = Config::load(&config_path()?)?;
    let peer = cfg.resolve_peer(&target)?.clone();
    let secret_key = cfg.secret_key()?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(RelayMode::Default)
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;

    let conn = endpoint
        .connect(peer.node_id, TCP_ALPN)
        .await
        .with_context(|| format!("failed to connect to esp peer {}", peer.node_id))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("failed to open TCP proxy stream")?;
    let request = TcpProxyRequest {
        network_id: cfg.network_id.clone(),
        requester_name: cfg.name.clone(),
        requester_connection_id: cfg.connection_id.clone(),
        invite_proof: None,
        membership: cfg.membership.clone(),
        memberships: cfg.shared_memberships(),
        peers: cfg.peers.clone(),
        port,
    };
    write_proxy_request(&mut send, &request).await?;

    let mut stdin_to_peer = tokio::spawn(async move {
        let mut stdin = io::stdin();
        io::copy(&mut stdin, &mut send)
            .await
            .context("failed to copy stdin to esp peer")?;
        send.finish().context("failed to finish esp send stream")?;
        Ok::<(), anyhow::Error>(())
    });
    let mut peer_to_stdout = tokio::spawn(async move {
        let mut stdout = io::stdout();
        io::copy(&mut recv, &mut stdout)
            .await
            .context("failed to copy esp peer to stdout")?;
        stdout.flush().await.context("failed to flush stdout")?;
        Ok::<(), anyhow::Error>(())
    });

    tokio::select! {
        result = &mut stdin_to_peer => {
            result.context("stdin proxy task failed")??;
            peer_to_stdout.abort();
        }
        result = &mut peer_to_stdout => {
            result.context("stdout proxy task failed")??;
            stdin_to_peer.abort();
        }
    }

    conn.close(GRACEFUL_CLOSE, b"bye");
    endpoint.close().await;
    Ok(())
}

async fn handle_tcp_proxy_connection(
    conn: Connection,
    actor: ConfigActorHandle,
    allowed_ports: &[u16],
) -> Result<()> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .context("failed to accept TCP proxy stream")?;
    let request = read_proxy_request(&mut recv).await?;
    ensure_port_allowed(request.port, allowed_ports)?;
    let port = request.port;
    let peer = actor.proxy_request(conn.remote_id(), request).await?;
    info!(
        peer = %peer.node_id,
        peer_name = %peer.name,
        peer_id = %peer.connection_id,
        port = port,
        "opening localhost TCP proxy"
    );

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .with_context(|| format!("failed to connect to 127.0.0.1:{port}"))?;
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let mut peer_to_tcp = tokio::spawn(async move {
        io::copy(&mut recv, &mut tcp_write)
            .await
            .context("failed to copy esp peer to local TCP socket")?;
        tcp_write
            .shutdown()
            .await
            .context("failed to shutdown local TCP write side")?;
        Ok::<(), anyhow::Error>(())
    });
    let mut tcp_to_peer = tokio::spawn(async move {
        io::copy(&mut tcp_read, &mut send)
            .await
            .context("failed to copy local TCP socket to esp peer")?;
        send.finish().context("failed to finish esp send stream")?;
        Ok::<(), anyhow::Error>(())
    });

    tokio::select! {
        result = &mut peer_to_tcp => {
            result.context("peer-to-tcp proxy task failed")??;
            tcp_to_peer.abort();
        }
        result = &mut tcp_to_peer => {
            result.context("tcp-to-peer proxy task failed")??;
            peer_to_tcp.abort();
        }
    }
    conn.close(GRACEFUL_CLOSE, b"bye");
    Ok(())
}

pub fn ensure_port_allowed(port: u16, allowed_ports: &[u16]) -> Result<()> {
    let allowed_ports = normalize_allowed_ports(allowed_ports)?;
    if allowed_ports.contains(&port) {
        return Ok(());
    }
    bail!(
        "port {} is not allowed by this daemon; restart the daemon with --ports to allow it (allowed ports: {})",
        port,
        format_ports(&allowed_ports)
    )
}

fn ensure_membership_allows_port(
    peer: &Peer,
    membership: &MembershipCertificate,
    port: u16,
) -> Result<()> {
    let allowed_ports = membership.allowed_ports()?;
    if allowed_ports.contains(&port) {
        return Ok(());
    }
    bail!(
        "membership for peer {} does not allow port {}; allowed ports: {}",
        peer.node_id,
        port,
        format_ports(&allowed_ports)
    )
}

fn normalize_allowed_ports(ports: &[u16]) -> Result<Vec<u16>> {
    if ports.is_empty() {
        bail!("at least one allowed port is required");
    }
    if ports.contains(&0) {
        bail!("port 0 is not a valid TCP target port");
    }
    let mut normalized = ports.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    Ok(normalized)
}

fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn first_disallowed_port(requested_ports: &[u16], allowed_ports: &[u16]) -> Option<u16> {
    requested_ports
        .iter()
        .copied()
        .find(|port| !allowed_ports.contains(port))
}

async fn read_proxy_request(recv: &mut iroh::endpoint::RecvStream) -> Result<TcpProxyRequest> {
    read_yaml_frame(recv, MAX_PROXY_REQUEST_LEN, "TCP proxy request").await
}

async fn write_proxy_request(
    send: &mut iroh::endpoint::SendStream,
    request: &TcpProxyRequest,
) -> Result<()> {
    write_yaml_frame(send, request, MAX_PROXY_REQUEST_LEN, "TCP proxy request").await
}

async fn read_control_hello(recv: &mut iroh::endpoint::RecvStream) -> Result<Hello> {
    read_yaml_frame(recv, MAX_CONTROL_MESSAGE_LEN, "esp control hello").await
}

async fn write_control_hello(send: &mut iroh::endpoint::SendStream, hello: &Hello) -> Result<()> {
    write_yaml_frame(send, hello, MAX_CONTROL_MESSAGE_LEN, "esp control hello").await
}

async fn read_control_response(recv: &mut iroh::endpoint::RecvStream) -> Result<ControlResponse> {
    read_yaml_frame(recv, MAX_CONTROL_MESSAGE_LEN, "esp control response").await
}

async fn write_control_response(
    send: &mut iroh::endpoint::SendStream,
    response: &ControlResponse,
) -> Result<()> {
    write_yaml_frame(
        send,
        response,
        MAX_CONTROL_MESSAGE_LEN,
        "esp control response",
    )
    .await
}

async fn read_yaml_frame<R, T>(recv: &mut R, max_len: usize, label: &str) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 2];
    recv.read_exact(&mut len)
        .await
        .with_context(|| format!("failed to read {label} length"))?;
    let len = usize::from(u16::from_be_bytes(len));
    if len > max_len {
        bail!("{label} is too large");
    }

    let mut data = vec![0u8; len];
    recv.read_exact(&mut data)
        .await
        .with_context(|| format!("failed to read {label}"))?;
    serde_yaml::from_slice(&data).with_context(|| format!("invalid {label}"))
}

async fn write_yaml_frame<W, T>(send: &mut W, value: &T, max_len: usize, label: &str) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let data = serde_yaml::to_string(value)?.into_bytes();
    if data.len() > max_len || data.len() > usize::from(u16::MAX) {
        bail!("{label} is too large");
    }
    send.write_all(&(data.len() as u16).to_be_bytes())
        .await
        .with_context(|| format!("failed to write {label} length"))?;
    send.write_all(&data)
        .await
        .with_context(|| format!("failed to write {label}"))?;
    Ok(())
}

fn config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(CONFIG_FILE))
}

fn validate_existing_config_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    validate_config_metadata(path, &metadata)
}

fn validate_config_target_for_write(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_config_metadata(path, &metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn validate_config_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        bail!(
            "{} is a symlink; refusing to use it as esp config",
            path.display()
        );
    }
    if !file_type.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    validate_private_config_permissions(path, metadata)
}

#[cfg(unix)]
fn validate_private_config_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} permissions are {:03o}; refusing to use config with group/world access (run `chmod 600 {}`)",
            path.display(),
            mode,
            path.display()
        );
    }
    if metadata.nlink() > 1 {
        bail!(
            "{} has {} hard links; refusing to use linked secret config",
            path.display(),
            metadata.nlink()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_config_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

fn write_private_config(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_config_target_for_write(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?
        .to_string_lossy();
    let temp_path = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        Uuid::new_v4()
    ));

    let result = write_private_config_temp(&temp_path, bytes).and_then(|()| {
        fs::rename(&temp_path, path).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                path.display(),
                temp_path.display()
            )
        })?;
        sync_parent_dir(parent);
        validate_existing_config_file(path)
    });

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn write_private_config_temp(temp_path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(CONFIG_FILE_MODE);

    let mut file = options
        .open(temp_path)
        .with_context(|| format!("failed to create {}", temp_path.display()))?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(CONFIG_FILE_MODE))
        .with_context(|| {
            format!(
                "failed to set private permissions on {}",
                temp_path.display()
            )
        })?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", temp_path.display()))?;
    Ok(())
}

fn sync_parent_dir(parent: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

impl Config {
    fn load(path: &Path) -> Result<Self> {
        let text = read_private_config(path)?;
        let mut cfg: Self = serde_yaml::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let changed = cfg.ensure_local_config()?;
        if changed {
            cfg.save(path)?;
        }
        Ok(cfg)
    }

    fn save(&self, path: &Path) -> Result<()> {
        let text = serde_yaml::to_string(self)?;
        write_private_config(path, text.as_bytes())
    }

    fn secret_key(&self) -> Result<SecretKey> {
        decode_secret_key(&self.secret_key).context("invalid secret_key in esp config")
    }

    fn peer_by_id(&self, id: EndpointId) -> Option<&Peer> {
        self.peers.iter().find(|peer| peer.node_id == id)
    }

    fn peer_by_connection_id(&self, connection_id: &str) -> Option<&Peer> {
        self.peers
            .iter()
            .find(|peer| peer.connection_id == connection_id)
    }

    pub fn resolve_peer(&self, target: &str) -> Result<&Peer> {
        let target = target.trim();
        if is_valid_connection_id(target) {
            return self
                .peer_by_connection_id(target)
                .ok_or_else(|| anyhow!("no configured esp peer with connection id {}", target));
        }

        let name = normalize_connection_name(target)?;
        let matches: Vec<_> = self.peers.iter().filter(|peer| peer.name == name).collect();
        match matches.as_slice() {
            [peer] => Ok(peer),
            [] => bail!("no configured esp peer named {}", name),
            peers => {
                let ids = peers
                    .iter()
                    .map(|peer| peer.connection_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!(
                    "multiple esp peers are named {}; rename them or use a connection id: {}",
                    name,
                    ids
                )
            }
        }
    }

    fn ensure_local_config(&mut self) -> Result<bool> {
        let mut changed = self.ensure_local_identity();
        let local_node_id = self.secret_key()?.public();
        if self.creator_node_id.is_none() {
            self.creator_node_id = Some(
                self.peers
                    .first()
                    .map(|peer| peer.node_id)
                    .unwrap_or(local_node_id),
            );
            changed = true;
        }

        if self.creator_node_id == Some(local_node_id) {
            let local_peer = self.local_peer()?;
            let needs_membership = self
                .membership
                .as_ref()
                .map(|membership| {
                    membership.matches_peer(self, &local_peer).is_err()
                        || verify_membership_chain(self, membership, &[]).is_err()
                })
                .unwrap_or(true);
            if needs_membership {
                let secret_key = self.secret_key()?;
                self.membership = Some(MembershipCertificate::issue(
                    self,
                    &secret_key,
                    &local_peer,
                    &[DEFAULT_ALLOWED_PORT],
                )?);
                changed = true;
            }
        }
        Ok(changed)
    }

    fn ensure_local_identity(&mut self) -> bool {
        let mut changed = false;
        if self.name.trim().is_empty() {
            self.name = default_connection_name();
            changed = true;
        }
        if !is_valid_connection_id(&self.connection_id) {
            self.connection_id = generate_connection_id();
            changed = true;
        }
        changed
    }

    fn local_peer(&self) -> Result<Peer> {
        Ok(Peer {
            node_id: self.secret_key()?.public(),
            name: self.name.clone(),
            connection_id: self.connection_id.clone(),
        })
    }

    fn shared_memberships(&self) -> Vec<MembershipCertificate> {
        let mut memberships = self.memberships.clone();
        if let Some(membership) = &self.membership
            && !memberships
                .iter()
                .any(|known| known.subject_node_id == membership.subject_node_id)
        {
            memberships.push(membership.clone());
        }
        memberships
    }

    fn membership_chain_for(&self, node_id: EndpointId) -> Result<Vec<MembershipCertificate>> {
        let mut chain = Vec::new();
        let mut current = node_id;
        loop {
            if chain
                .iter()
                .any(|membership: &MembershipCertificate| membership.subject_node_id == current)
            {
                bail!("membership chain contains a cycle");
            }
            let membership = find_membership_by_subject(self, &[], current)
                .cloned()
                .ok_or_else(|| anyhow!("no membership certificate for {}", current))?;
            verify_membership_chain(self, &membership, &[])?;
            current = membership.issuer_node_id;
            let is_root = membership.subject_node_id == membership.issuer_node_id;
            chain.push(membership);
            if is_root {
                return Ok(chain);
            }
        }
    }

    pub fn issue_invite(&mut self, allowed_ports: &[u16]) -> Result<InviteCode> {
        self.ensure_local_config()?;
        let allowed_ports = normalize_allowed_ports(allowed_ports)?;
        self.ensure_can_issue_ports(&allowed_ports)?;
        let secret_key = self.secret_key()?;
        let invite_id = generate_connection_id();
        let invite_secret = generate_invite_secret();
        let invite = Invite {
            version: INVITE_VERSION,
            network_id: self.network_id.clone(),
            invite_id: invite_id.clone(),
            invite_secret: invite_secret.clone(),
            creator_node_id: self.creator_node_id,
            inviter_node_id: secret_key.public(),
            inviter_name: self.name.clone(),
            inviter_connection_id: self.connection_id.clone(),
            allowed_ports: allowed_ports.clone(),
            membership_chain: self.membership_chain_for(secret_key.public())?,
        };
        let issued = InviteCode {
            invite_id: invite_id.clone(),
            code: invite.encode()?,
        };
        self.invites.push(IssuedInvite {
            invite_id,
            secret_hash: hash_invite_secret(&invite_secret),
            allowed_ports,
        });
        Ok(issued)
    }

    fn ensure_can_issue_ports(&self, requested_ports: &[u16]) -> Result<()> {
        let local_node_id = self.secret_key()?.public();
        if self.creator_node_id == Some(local_node_id) {
            return Ok(());
        }
        let membership = self
            .membership
            .as_ref()
            .ok_or_else(|| anyhow!("local host has no membership certificate"))?;
        let granted_ports = membership.allowed_ports()?;
        if let Some(port) = first_disallowed_port(requested_ports, &granted_ports) {
            bail!(
                "local membership cannot grant port {}; allowed ports: {}",
                port,
                format_ports(&granted_ports)
            );
        }
        Ok(())
    }

    fn invite_allowed_ports_for_proof(
        &self,
        proof: Option<&InviteProof>,
    ) -> Result<Option<Vec<u16>>> {
        let Some(proof) = proof else {
            return Ok(None);
        };
        let secret_hash = hash_invite_secret(&proof.invite_secret);
        self.invites
            .iter()
            .find(|invite| invite.invite_id == proof.invite_id && invite.secret_hash == secret_hash)
            .map(|invite| normalize_allowed_ports(&invite.allowed_ports))
            .transpose()
    }

    fn consume_invite_proof(&mut self, proof: Option<&InviteProof>) -> bool {
        let Some(proof) = proof else {
            return false;
        };
        let secret_hash = hash_invite_secret(&proof.invite_secret);
        let Some(index) = self.invites.iter().position(|invite| {
            invite.invite_id == proof.invite_id && invite.secret_hash == secret_hash
        }) else {
            return false;
        };
        self.invites.remove(index);
        true
    }
}

#[cfg(unix)]
fn read_private_config(path: &Path) -> Result<String> {
    validate_existing_config_file(path)?;

    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path).with_context(|| {
        format!(
            "failed to open {} without following symlinks",
            path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    validate_config_metadata(path, &metadata)?;

    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(text)
}

#[cfg(not(unix))]
fn read_private_config(path: &Path) -> Result<String> {
    validate_existing_config_file(path)?;
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

impl Peer {
    fn has_identity(&self) -> bool {
        !self.name.trim().is_empty() && is_valid_connection_id(&self.connection_id)
    }

    fn display_name(&self) -> String {
        if self.has_identity() {
            format!("{} ({})", self.name, self.connection_id)
        } else {
            self.node_id.to_string()
        }
    }
}

impl MembershipCertificate {
    pub fn issue(
        cfg: &Config,
        issuer_key: &SecretKey,
        subject: &Peer,
        allowed_ports: &[u16],
    ) -> Result<Self> {
        if !is_valid_connection_id(&subject.connection_id) {
            bail!("cannot issue membership for invalid connection id");
        }
        let allowed_ports = normalize_allowed_ports(allowed_ports)?;
        let mut membership = Self {
            version: MEMBERSHIP_CERTIFICATE_VERSION,
            network_id: cfg.network_id.clone(),
            subject_node_id: subject.node_id,
            subject_connection_id: subject.connection_id.clone(),
            allowed_ports,
            issuer_node_id: issuer_key.public(),
            signature: String::new(),
        };
        let signature = issuer_key.sign(&membership.signature_payload()?);
        membership.signature = encode_signature(&signature);
        Ok(membership)
    }

    fn matches_peer(&self, cfg: &Config, peer: &Peer) -> Result<()> {
        self.allowed_ports()?;
        if self.network_id != cfg.network_id {
            bail!("membership certificate is for a different esp network");
        }
        if self.subject_node_id != peer.node_id {
            bail!("membership certificate subject does not match peer node id");
        }
        if self.subject_connection_id != peer.connection_id {
            bail!("membership certificate subject does not match peer connection id");
        }
        if !is_valid_connection_id(&self.subject_connection_id) {
            bail!("membership certificate has invalid connection id");
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<()> {
        let signature = decode_signature(&self.signature)?;
        let payload = self.signature_payload()?;
        self.issuer_node_id
            .verify(&payload, &signature)
            .context("membership certificate signature is invalid")
    }

    fn signature_payload(&self) -> Result<Vec<u8>> {
        if self.version != MEMBERSHIP_CERTIFICATE_VERSION {
            bail!(
                "unsupported membership certificate version {}",
                self.version
            );
        }
        let fields = [
            self.version.to_string(),
            self.network_id.clone(),
            self.subject_node_id.to_string(),
            self.subject_connection_id.clone(),
            format_ports(&self.allowed_ports()?),
            self.issuer_node_id.to_string(),
        ];
        let mut payload = Vec::new();
        append_signed_field(&mut payload, MEMBERSHIP_SIGNATURE_CONTEXT);
        for field in &fields {
            append_signed_field(&mut payload, field);
        }
        Ok(payload)
    }

    fn allowed_ports(&self) -> Result<Vec<u16>> {
        if self.version != MEMBERSHIP_CERTIFICATE_VERSION {
            bail!(
                "unsupported membership certificate version {}",
                self.version
            );
        }
        normalize_allowed_ports(&self.allowed_ports)
    }
}

fn hello_from_config(cfg: &Config) -> Hello {
    Hello {
        network_id: cfg.network_id.clone(),
        name: cfg.name.clone(),
        connection_id: cfg.connection_id.clone(),
        invite_proof: if cfg.membership.is_none() {
            cfg.invite_proof.clone()
        } else {
            None
        },
        membership: cfg.membership.clone(),
        memberships: cfg.shared_memberships(),
        peers: cfg.peers.clone(),
    }
}

fn memberships_from_hello(hello: &Hello) -> Vec<MembershipCertificate> {
    let mut memberships = hello.memberships.clone();
    if let Some(membership) = &hello.membership
        && !memberships
            .iter()
            .any(|known| known.subject_node_id == membership.subject_node_id)
    {
        memberships.push(membership.clone());
    }
    memberships
}

fn remember_local_membership_grant(
    path: &Path,
    cfg: &mut Config,
    membership: MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<()> {
    if remember_local_membership_grant_in_config(cfg, membership, extra_memberships)? {
        cfg.save(path)?;
    }
    Ok(())
}

fn remember_local_membership_grant_in_config(
    cfg: &mut Config,
    membership: MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<bool> {
    let local_peer = cfg.local_peer()?;
    membership.matches_peer(cfg, &local_peer)?;
    verify_membership_chain(cfg, &membership, extra_memberships)?;
    let changed = cfg.membership.as_ref() != Some(&membership) || cfg.invite_proof.is_some();
    cfg.membership = Some(membership);
    cfg.invite_proof = None;
    Ok(changed)
}

fn consume_invite_and_issue_membership(
    cfg: &mut Config,
    peer: &Peer,
    invite_proof: Option<&InviteProof>,
) -> Result<Option<MembershipCertificate>> {
    let Some(allowed_ports) = cfg.invite_allowed_ports_for_proof(invite_proof)? else {
        return Ok(None);
    };
    let local_peer = cfg.local_peer()?;
    let local_membership = cfg
        .membership
        .as_ref()
        .ok_or_else(|| anyhow!("local host has no membership certificate"))?;
    local_membership.matches_peer(cfg, &local_peer)?;
    verify_membership_chain(cfg, local_membership, &[])?;
    cfg.ensure_can_issue_ports(&allowed_ports)?;
    if !cfg.consume_invite_proof(invite_proof) {
        return Ok(None);
    }
    let secret_key = cfg.secret_key()?;
    MembershipCertificate::issue(cfg, &secret_key, peer, &allowed_ports).map(Some)
}

fn verified_membership_for_peer(
    cfg: &Config,
    peer: &Peer,
    direct_membership: Option<&MembershipCertificate>,
    extra_memberships: &[MembershipCertificate],
) -> Result<Option<MembershipCertificate>> {
    let membership = direct_membership
        .or_else(|| find_membership_by_subject(cfg, extra_memberships, peer.node_id));
    let Some(membership) = membership else {
        return Ok(None);
    };
    membership.matches_peer(cfg, peer)?;
    verify_membership_chain(cfg, membership, extra_memberships)?;
    Ok(Some(membership.clone()))
}

fn verify_membership_chain(
    cfg: &Config,
    membership: &MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<()> {
    let mut seen = Vec::new();
    verify_membership_chain_inner(cfg, membership, extra_memberships, &mut seen)
}

fn verify_membership_chain_inner(
    cfg: &Config,
    membership: &MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
    seen: &mut Vec<EndpointId>,
) -> Result<()> {
    if membership.version != MEMBERSHIP_CERTIFICATE_VERSION {
        bail!(
            "unsupported membership certificate version {}",
            membership.version
        );
    }
    let membership_ports = membership.allowed_ports()?;
    if membership.network_id != cfg.network_id {
        bail!("membership certificate is for a different esp network");
    }
    if !is_valid_connection_id(&membership.subject_connection_id) {
        bail!("membership certificate has invalid connection id");
    }
    if seen.contains(&membership.subject_node_id) {
        bail!("membership certificate chain contains a cycle");
    }
    membership.verify_signature()?;
    seen.push(membership.subject_node_id);

    if membership.subject_node_id == membership.issuer_node_id {
        if Some(membership.subject_node_id) != cfg.creator_node_id {
            bail!("membership root is not the esp network creator");
        }
        return Ok(());
    }

    let issuer_membership =
        find_membership_by_subject(cfg, extra_memberships, membership.issuer_node_id)
            .ok_or_else(|| anyhow!("missing membership issuer {}", membership.issuer_node_id))?;
    if Some(membership.issuer_node_id) != cfg.creator_node_id {
        let issuer_ports = issuer_membership.allowed_ports()?;
        if let Some(port) = first_disallowed_port(&membership_ports, &issuer_ports) {
            bail!(
                "membership for {} grants port {} outside issuer {} allowed ports: {}",
                membership.subject_node_id,
                port,
                membership.issuer_node_id,
                format_ports(&issuer_ports)
            );
        }
    }
    verify_membership_chain_inner(cfg, issuer_membership, extra_memberships, seen)
}

fn find_membership_by_subject<'a>(
    cfg: &'a Config,
    extra_memberships: &'a [MembershipCertificate],
    subject_node_id: EndpointId,
) -> Option<&'a MembershipCertificate> {
    cfg.membership
        .iter()
        .chain(cfg.memberships.iter())
        .chain(extra_memberships.iter())
        .find(|membership| membership.subject_node_id == subject_node_id)
}

fn insert_membership(cfg: &mut Config, membership: MembershipCertificate) -> Result<bool> {
    if membership.subject_node_id == cfg.secret_key()?.public() {
        return Ok(false);
    }

    if let Some(existing) = cfg
        .memberships
        .iter_mut()
        .find(|known| known.subject_node_id == membership.subject_node_id)
    {
        if existing.subject_connection_id != membership.subject_connection_id {
            bail!(
                "membership for {} changed connection id from {} to {}",
                membership.subject_node_id,
                existing.subject_connection_id,
                membership.subject_connection_id
            );
        }
        if *existing == membership {
            return Ok(false);
        }
        *existing = membership;
        return Ok(true);
    }

    cfg.memberships.push(membership);
    cfg.memberships.sort_by(|left, right| {
        left.subject_node_id
            .to_string()
            .cmp(&right.subject_node_id.to_string())
    });
    Ok(true)
}

fn ensure_shared_list_size(label: &str, len: usize) -> Result<()> {
    if len <= MAX_SHARED_PEERS {
        return Ok(());
    }
    bail!(
        "peer shared {} {}, maximum is {}",
        len,
        label,
        MAX_SHARED_PEERS
    )
}

fn append_signed_field(payload: &mut Vec<u8>, field: &str) {
    payload.extend_from_slice(field.len().to_string().as_bytes());
    payload.push(b':');
    payload.extend_from_slice(field.as_bytes());
    payload.push(b'\n');
}

fn encode_signature(signature: &Signature) -> String {
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

fn decode_signature(encoded: &str) -> Result<Signature> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .context("membership signature is not valid base64")?;
    let bytes: [u8; Signature::LENGTH] = bytes
        .try_into()
        .map_err(|_| anyhow!("membership signature must decode to 64 bytes"))?;
    Ok(Signature::from_bytes(&bytes))
}

fn default_connection_name() -> String {
    ["ESP_NAME", "HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok())
        .or_else(short_hostname)
        .or_else(|| std::env::var("USER").ok())
        .and_then(|value| normalize_connection_name(&value).ok())
        .unwrap_or_else(|| "host".to_string())
}

fn short_hostname() -> Option<String> {
    let output = std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8(output.stdout).ok()?;
    let name = name.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn normalize_connection_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("connection name cannot be empty");
    }
    if name.len() > 64 {
        bail!("connection name must be 64 characters or fewer");
    }
    Ok(name.to_string())
}

fn generate_connection_id() -> String {
    let mut value = Uuid::new_v4().as_u128();
    let mut id = String::with_capacity(6);
    for _ in 0..6 {
        let idx = (value % CONNECTION_ID_ALPHABET.len() as u128) as usize;
        id.push(CONNECTION_ID_ALPHABET[idx] as char);
        value /= CONNECTION_ID_ALPHABET.len() as u128;
    }
    id
}

pub fn is_valid_connection_id(id: &str) -> bool {
    id.len() == 6 && id.chars().all(|ch| ch.is_ascii_alphanumeric())
}

fn generate_invite_secret() -> String {
    URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
}

fn hash_invite_secret(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

pub fn encode_secret_key(secret_key: &SecretKey) -> String {
    URL_SAFE_NO_PAD.encode(secret_key.to_bytes())
}

fn decode_secret_key(encoded: &str) -> Result<SecretKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .context("secret key is not valid base64")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("secret key must decode to 32 bytes"))?;
    Ok(SecretKey::from_bytes(&bytes))
}

impl Invite {
    pub fn encode(&self) -> Result<String> {
        let yaml = serde_yaml::to_string(self)?;
        Ok(URL_SAFE_NO_PAD.encode(yaml))
    }

    pub fn decode(code: &str) -> Result<Self> {
        let yaml = URL_SAFE_NO_PAD
            .decode(code.trim())
            .context("invite is not valid base64")?;
        let invite: Self = serde_yaml::from_slice(&yaml).context("invite is not valid esp data")?;
        if invite.version != INVITE_VERSION {
            bail!("unsupported invite version {}", invite.version);
        }
        Ok(invite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creator_config(secret_key: &SecretKey) -> Config {
        let mut cfg = Config {
            version: 1,
            network_id: "net".to_string(),
            secret_key: encode_secret_key(secret_key),
            creator_node_id: Some(secret_key.public()),
            invite_proof: None,
            membership: None,
            memberships: Vec::new(),
            name: "creator".to_string(),
            connection_id: "ABC123".to_string(),
            invites: Vec::new(),
            peers: Vec::new(),
        };
        cfg.ensure_local_config().unwrap();
        cfg
    }

    fn temp_config_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("esp-{label}-{}.yml", Uuid::new_v4()))
    }

    #[test]
    fn membership_certificate_chains_to_creator_and_rejects_tampering() {
        let creator_key = SecretKey::generate();
        let cfg = creator_config(&creator_key);
        let member = Peer {
            node_id: SecretKey::generate().public(),
            name: "member".to_string(),
            connection_id: "DEF456".to_string(),
        };
        let membership =
            MembershipCertificate::issue(&cfg, &creator_key, &member, &[DEFAULT_ALLOWED_PORT])
                .unwrap();

        membership.matches_peer(&cfg, &member).unwrap();
        verify_membership_chain(&cfg, &membership, &[]).unwrap();

        let mut tampered = membership;
        tampered.subject_connection_id = "FED654".to_string();
        assert!(verify_membership_chain(&cfg, &tampered, &[]).is_err());
    }

    #[test]
    fn invite_ports_are_signed_into_membership() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let invite = cfg
            .issue_invite(&[8080, DEFAULT_ALLOWED_PORT, 8080])
            .unwrap();
        let invite = Invite::decode(&invite.code).unwrap();
        let proof = InviteProof {
            invite_id: invite.invite_id,
            invite_secret: invite.invite_secret,
        };
        let peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "joined".to_string(),
            connection_id: "DEF456".to_string(),
        };

        let granted = consume_invite_and_issue_membership(&mut cfg, &peer, Some(&proof))
            .unwrap()
            .unwrap();

        assert_eq!(invite.allowed_ports, vec![DEFAULT_ALLOWED_PORT, 8080]);
        assert_eq!(granted.allowed_ports, vec![DEFAULT_ALLOWED_PORT, 8080]);
        verify_membership_chain(&cfg, &granted, &[]).unwrap();

        let mut tampered = granted;
        tampered.allowed_ports.push(80);
        assert!(verify_membership_chain(&cfg, &tampered, &[]).is_err());
    }

    #[test]
    fn invite_proof_is_consumed_when_membership_is_granted() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let invite = cfg.issue_invite(&[DEFAULT_ALLOWED_PORT]).unwrap();
        let invite = Invite::decode(&invite.code).unwrap();
        let proof = InviteProof {
            invite_id: invite.invite_id,
            invite_secret: invite.invite_secret,
        };
        let peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "joined".to_string(),
            connection_id: "DEF456".to_string(),
        };

        let granted = consume_invite_and_issue_membership(&mut cfg, &peer, Some(&proof))
            .unwrap()
            .unwrap();

        assert_eq!(granted.subject_node_id, peer.node_id);
        assert_eq!(granted.allowed_ports, vec![DEFAULT_ALLOWED_PORT]);
        assert!(cfg.invites.is_empty());
        assert!(
            consume_invite_and_issue_membership(&mut cfg, &peer, Some(&proof))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn joined_member_cannot_issue_invite_for_ungranted_port() {
        let creator_key = SecretKey::generate();
        let creator_cfg = creator_config(&creator_key);
        let member_key = SecretKey::generate();
        let member_peer = Peer {
            node_id: member_key.public(),
            name: "member".to_string(),
            connection_id: "DEF456".to_string(),
        };
        let creator_peer = Peer {
            node_id: creator_key.public(),
            name: "creator".to_string(),
            connection_id: "ABC123".to_string(),
        };
        let mut member_cfg = Config {
            version: 1,
            network_id: "net".to_string(),
            secret_key: encode_secret_key(&member_key),
            creator_node_id: Some(creator_key.public()),
            invite_proof: None,
            membership: Some(
                MembershipCertificate::issue(
                    &creator_cfg,
                    &creator_key,
                    &member_peer,
                    &[DEFAULT_ALLOWED_PORT],
                )
                .unwrap(),
            ),
            memberships: vec![creator_cfg.membership.clone().unwrap()],
            name: "member".to_string(),
            connection_id: "DEF456".to_string(),
            invites: Vec::new(),
            peers: vec![creator_peer],
        };

        let err = member_cfg.issue_invite(&[8080]).unwrap_err().to_string();

        assert!(err.contains("cannot grant port 8080"));
    }

    #[test]
    fn membership_chain_rejects_delegated_port_widening() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let issuer_key = SecretKey::generate();
        let issuer_peer = Peer {
            node_id: issuer_key.public(),
            name: "issuer".to_string(),
            connection_id: "DEF456".to_string(),
        };
        let subject_peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "subject".to_string(),
            connection_id: "FED654".to_string(),
        };
        let issuer_membership =
            MembershipCertificate::issue(&cfg, &creator_key, &issuer_peer, &[DEFAULT_ALLOWED_PORT])
                .unwrap();
        let subject_membership =
            MembershipCertificate::issue(&cfg, &issuer_key, &subject_peer, &[8080]).unwrap();
        cfg.memberships.push(issuer_membership);

        let err = verify_membership_chain(&cfg, &subject_membership, &[])
            .unwrap_err()
            .to_string();

        assert!(err.contains("outside issuer"));
    }

    #[test]
    fn known_control_peer_without_membership_is_rejected() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "known".to_string(),
            connection_id: "DEF456".to_string(),
        };
        cfg.peers.push(peer.clone());

        let err = remember_control_peer_in_config(&mut cfg, peer, false, None, None, &[])
            .unwrap_err()
            .to_string();

        assert!(err.contains("valid membership certificate"));
    }

    #[test]
    fn known_proxy_peer_without_membership_is_rejected() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "known".to_string(),
            connection_id: "DEF456".to_string(),
        };
        cfg.peers.push(peer.clone());

        let err = remember_proxy_peer_in_config(&mut cfg, peer, None, &[], DEFAULT_ALLOWED_PORT)
            .unwrap_err()
            .to_string();

        assert!(err.contains("valid membership certificate"));
    }

    #[test]
    fn known_peer_with_membership_is_accepted() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "known".to_string(),
            connection_id: "DEF456".to_string(),
        };
        cfg.peers.push(peer.clone());
        let membership =
            MembershipCertificate::issue(&cfg, &creator_key, &peer, &[DEFAULT_ALLOWED_PORT])
                .unwrap();

        let changed = remember_proxy_peer_in_config(
            &mut cfg,
            peer.clone(),
            Some(&membership),
            &[],
            DEFAULT_ALLOWED_PORT,
        )
        .unwrap();

        assert!(changed);
        assert_eq!(
            cfg.peer_by_id(peer.node_id).unwrap().connection_id,
            peer.connection_id
        );
    }

    #[test]
    fn proxy_requires_membership_port_grant() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "known".to_string(),
            connection_id: "DEF456".to_string(),
        };
        let membership =
            MembershipCertificate::issue(&cfg, &creator_key, &peer, &[DEFAULT_ALLOWED_PORT])
                .unwrap();

        remember_proxy_peer_in_config(
            &mut cfg,
            peer.clone(),
            Some(&membership),
            &[],
            DEFAULT_ALLOWED_PORT,
        )
        .unwrap();
        let err = remember_proxy_peer_in_config(&mut cfg, peer, Some(&membership), &[], 8080)
            .unwrap_err()
            .to_string();

        assert!(err.contains("does not allow port 8080"));
    }

    #[test]
    fn known_advertised_peer_without_membership_is_rejected() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let remote_peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "remote".to_string(),
            connection_id: "DEF456".to_string(),
        };
        let advertised_peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "advertised".to_string(),
            connection_id: "FED654".to_string(),
        };
        cfg.peers.push(advertised_peer.clone());

        let err = remember_advertised_peers_in_config(
            &mut cfg,
            &remote_peer,
            vec![advertised_peer],
            Vec::new(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("has no valid membership"));
    }

    #[tokio::test]
    async fn config_actor_serializes_invite_consumption() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let invite = cfg.issue_invite(&[DEFAULT_ALLOWED_PORT]).unwrap();
        let invite = Invite::decode(&invite.code).unwrap();
        let proof = InviteProof {
            invite_id: invite.invite_id,
            invite_secret: invite.invite_secret,
        };
        let path = temp_config_path("actor-race");
        cfg.save(&path).unwrap();
        let actor = spawn_config_actor(path.clone(), cfg);

        let first_key = SecretKey::generate();
        let second_key = SecretKey::generate();
        let first_hello = Hello {
            network_id: "net".to_string(),
            name: "joined-one".to_string(),
            connection_id: "DEF456".to_string(),
            invite_proof: Some(proof.clone()),
            membership: None,
            memberships: Vec::new(),
            peers: Vec::new(),
        };
        let second_hello = Hello {
            network_id: "net".to_string(),
            name: "joined-two".to_string(),
            connection_id: "FED654".to_string(),
            invite_proof: Some(proof),
            membership: None,
            memberships: Vec::new(),
            peers: Vec::new(),
        };

        let (first, second) = tokio::join!(
            actor.control_sync(first_key.public(), first_hello, None),
            actor.control_sync(second_key.public(), second_hello, None)
        );

        let first_granted = first
            .as_ref()
            .ok()
            .and_then(|response| response.granted_membership.as_ref())
            .is_some();
        let second_granted = second
            .as_ref()
            .ok()
            .and_then(|response| response.granted_membership.as_ref())
            .is_some();
        assert_eq!(usize::from(first_granted) + usize::from(second_granted), 1);
        assert!(first.is_err() ^ second.is_err());

        drop(actor);
        let saved = Config::load(&path).unwrap();
        assert!(saved.invites.is_empty());
        assert_eq!(saved.peers.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_control_invite_uses_config_actor() {
        let creator_key = SecretKey::generate();
        let cfg = creator_config(&creator_key);
        let path = temp_config_path("local-control");
        let socket_path = std::env::temp_dir().join(format!("esp-{}.sock", Uuid::new_v4()));
        cfg.save(&path).unwrap();
        let actor = spawn_config_actor(path.clone(), cfg);
        let listener = bind_local_control_socket(&socket_path).unwrap();
        let server = tokio::spawn(run_local_control_server(listener, actor.clone()));

        let response = send_local_control_request_to_path(
            &socket_path,
            LocalControlRequest::IssueInvite {
                ports: vec![DEFAULT_ALLOWED_PORT],
            },
        )
        .await
        .unwrap()
        .unwrap();
        let LocalControlOk::Invite { code } = response else {
            panic!("expected invite response");
        };
        let invite = Invite::decode(&code).unwrap();
        let report = actor.status().await.unwrap();

        assert_eq!(report.invites, vec![invite.invite_id]);

        server.abort();
        drop(actor);
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn advertised_peer_with_valid_membership_is_remembered_without_invite() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let remote_peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "remote".to_string(),
            connection_id: "DEF456".to_string(),
        };
        let advertised_peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "advertised".to_string(),
            connection_id: "FED654".to_string(),
        };
        let advertised_membership = MembershipCertificate::issue(
            &cfg,
            &creator_key,
            &advertised_peer,
            &[DEFAULT_ALLOWED_PORT],
        )
        .unwrap();
        let path = std::env::temp_dir().join(format!("esp-test-{}.yml", Uuid::new_v4()));

        remember_advertised_peers_with_memberships(
            &path,
            &mut cfg,
            &remote_peer,
            vec![advertised_peer.clone()],
            vec![advertised_membership],
        )
        .unwrap();

        assert_eq!(
            cfg.peer_by_id(advertised_peer.node_id)
                .unwrap()
                .connection_id,
            advertised_peer.connection_id
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unknown_advertised_peer_without_membership_is_rejected() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let remote_peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "remote".to_string(),
            connection_id: "DEF456".to_string(),
        };
        let advertised_peer = Peer {
            node_id: SecretKey::generate().public(),
            name: "advertised".to_string(),
            connection_id: "FED654".to_string(),
        };
        let path = std::env::temp_dir().join(format!("esp-test-{}.yml", Uuid::new_v4()));

        let err = remember_advertised_peers_with_memberships(
            &path,
            &mut cfg,
            &remote_peer,
            vec![advertised_peer.clone()],
            Vec::new(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("has no valid membership"));
        assert!(cfg.peer_by_id(advertised_peer.node_id).is_none());
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn config_save_creates_private_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let secret_key = SecretKey::generate();
        let cfg = creator_config(&secret_key);
        let path = temp_config_path("private");

        cfg.save(&path).unwrap();

        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, CONFIG_FILE_MODE);
        Config::load(&path).unwrap();

        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn config_load_and_save_reject_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let secret_key = SecretKey::generate();
        let cfg = creator_config(&secret_key);
        let path = temp_config_path("loose");
        cfg.save(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let load_err = Config::load(&path).unwrap_err().to_string();
        assert!(load_err.contains("group/world access"));
        let save_err = cfg.save(&path).unwrap_err().to_string();
        assert!(save_err.contains("group/world access"));

        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn config_load_and_save_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let secret_key = SecretKey::generate();
        let cfg = creator_config(&secret_key);
        let target_path = temp_config_path("target");
        let link_path = temp_config_path("link");
        cfg.save(&target_path).unwrap();
        symlink(&target_path, &link_path).unwrap();

        let load_err = Config::load(&link_path).unwrap_err().to_string();
        assert!(load_err.contains("is a symlink"));
        let save_err = cfg.save(&link_path).unwrap_err().to_string();
        assert!(save_err.contains("is a symlink"));

        let _ = std::fs::remove_file(link_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[cfg(unix)]
    #[test]
    fn config_load_and_save_reject_hard_links() {
        let secret_key = SecretKey::generate();
        let cfg = creator_config(&secret_key);
        let path = temp_config_path("hard-link");
        let link_path = temp_config_path("hard-link-copy");
        cfg.save(&path).unwrap();
        std::fs::hard_link(&path, &link_path).unwrap();

        let load_err = Config::load(&path).unwrap_err().to_string();
        assert!(load_err.contains("hard links"));
        let save_err = cfg.save(&path).unwrap_err().to_string();
        assert!(save_err.contains("hard links"));

        let _ = std::fs::remove_file(link_path);
        let _ = std::fs::remove_file(path);
    }
}
