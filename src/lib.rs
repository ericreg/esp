use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint, EndpointId, RelayMode, SecretKey,
    address_lookup::AddrFilter,
    endpoint::{Connection, VarInt, presets},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
    time::{interval, timeout},
};
use tracing::{debug, info, warn};
use uuid::Uuid;

const CONTROL_ALPN: &[u8] = b"esp/control/0";
const TCP_ALPN: &[u8] = b"esp/tcp/0";
const CONFIG_FILE: &str = ".esp.yml";
pub const DEFAULT_ALLOWED_PORT: u16 = 22;
const MAX_PROXY_REQUEST_LEN: usize = 1024;
pub const MAX_SHARED_PEERS: usize = 100;
const GRACEFUL_CLOSE: VarInt = VarInt::from_u32(0);
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
    Invite,
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
    pub inviter_node_id: EndpointId,
    #[serde(default)]
    pub inviter_name: String,
    #[serde(default)]
    pub inviter_connection_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteProof {
    pub invite_id: String,
    pub invite_secret: String,
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
    #[serde(default)]
    peers: Vec<Peer>,
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
    #[serde(default)]
    peers: Vec<Peer>,
    port: u16,
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
        Command::Rename { name } => rename(&name),
        Command::Invite => print_invite(),
        Command::Status => status(),
    }
}

async fn init() -> Result<()> {
    let path = config_path()?;
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
            name: default_connection_name(),
            connection_id: generate_connection_id(),
            invites: Vec::new(),
            peers: Vec::new(),
        };
        cfg.save(&path)?;
        cfg
    };
    cfg.ensure_local_identity();
    cfg.save(&path)?;

    println!("esp config: {}", path.display());
    println!("name: {}", cfg.name);
    println!("connection id: {}", cfg.connection_id);
    println!("node id: {}", cfg.secret_key()?.public());
    println!("run `esp invite` to create an invite");
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
    let secret_key = SecretKey::generate();
    let mut connection_id = generate_connection_id();
    while !invite.inviter_connection_id.is_empty() && connection_id == invite.inviter_connection_id
    {
        connection_id = generate_connection_id();
    }
    let cfg = Config {
        version: 1,
        network_id: invite.network_id,
        secret_key: encode_secret_key(&secret_key),
        creator_node_id: Some(invite.inviter_node_id),
        invite_proof: Some(InviteProof {
            invite_id: invite.invite_id,
            invite_secret: invite.invite_secret,
        }),
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

    match sync_joined_peer_once(&path, &cfg.peers[0]).await {
        Ok(()) => println!("join sync: complete"),
        Err(err) => println!("join sync: skipped ({err})"),
    }
    Ok(())
}

fn rename(name: &str) -> Result<()> {
    let path = config_path()?;
    let mut cfg = Config::load(&path)?;
    cfg.name = normalize_connection_name(name)?;
    cfg.save(&path)?;
    println!("name: {}", cfg.name);
    println!("connection id: {}", cfg.connection_id);
    Ok(())
}

fn print_invite() -> Result<()> {
    let path = config_path()?;
    let mut cfg = Config::load(&path)?;
    let invite = cfg.issue_invite()?;
    cfg.save(&path)?;
    println!("{}", invite.code);
    Ok(())
}

fn status() -> Result<()> {
    let path = config_path()?;
    let cfg = Config::load(&path)?;
    println!("esp config: {}", path.display());
    println!("network: {}", cfg.network_id);
    println!("name: {}", cfg.name);
    println!("connection id: {}", cfg.connection_id);
    println!("node id: {}", cfg.secret_key()?.public());
    for invite in &cfg.invites {
        println!("issued invite: {}", invite.invite_id);
    }
    for peer in &cfg.peers {
        println!("peer: {} {}", peer.display_name(), peer.node_id);
    }
    Ok(())
}

async fn daemon(allowed_ports: Vec<u16>) -> Result<()> {
    if allowed_ports.is_empty() {
        bail!("at least one allowed port is required");
    }
    let path = config_path()?;
    let cfg = Config::load(&path)?;
    let secret_key = cfg.secret_key()?;
    let endpoint = Endpoint::builder(presets::N0)
        .clear_ip_transports()
        .secret_key(secret_key)
        .alpns(vec![CONTROL_ALPN.to_vec(), TCP_ALPN.to_vec()])
        .addr_filter(AddrFilter::relay_only())
        .relay_mode(RelayMode::Default)
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;

    info!(node_id = %endpoint.id(), "esp endpoint bound");
    endpoint.online().await;
    info!(addr = ?endpoint.addr(), "esp endpoint online");

    info!(ports = ?allowed_ports, "esp TCP proxy port allowlist active");
    run_acceptor(endpoint.clone(), path, allowed_ports).await?;
    endpoint.close().await;
    Ok(())
}

async fn sync_joined_peer_once(path: &PathBuf, inviter: &Peer) -> Result<()> {
    let cfg = Config::load(path)?;
    let secret_key = cfg.secret_key()?;
    let endpoint = Endpoint::builder(presets::N0)
        .clear_ip_transports()
        .secret_key(secret_key)
        .addr_filter(AddrFilter::relay_only())
        .relay_mode(RelayMode::Default)
        .bind()
        .await
        .context("failed to bind iroh endpoint for join sync")?;

    let result = async {
        let conn = endpoint
            .connect(inviter.node_id, CONTROL_ALPN)
            .await
            .with_context(|| format!("failed to connect to inviter {}", inviter.node_id))?;
        sync_control_connection(&conn, path, Some(inviter)).await?;
        conn.close(GRACEFUL_CLOSE, b"synced");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    endpoint.close().await;
    result
}

async fn run_acceptor(endpoint: Endpoint, path: PathBuf, allowed_ports: Vec<u16>) -> Result<()> {
    info!("accepting esp control and TCP proxy connections");
    while let Some(incoming) = endpoint.accept().await {
        let path = path.clone();
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
                        handle_control_connection(conn, path).await
                    } else if alpn == TCP_ALPN {
                        handle_tcp_proxy_connection(conn, path, &allowed_ports).await
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

async fn handle_control_connection(conn: Connection, path: PathBuf) -> Result<()> {
    sync_control_connection(&conn, &path, None).await?;
    conn.close(GRACEFUL_CLOSE, b"synced");
    Ok(())
}

async fn sync_control_connection(
    conn: &Connection,
    path: &PathBuf,
    expected_peer: Option<&Peer>,
) -> Result<()> {
    let mut cfg = Config::load(path)?;
    let remote = exchange_hello(conn, &cfg).await?;
    let peer = validate_peer_report(&cfg, conn.remote_id(), &remote, expected_peer)?;
    remember_control_peer(
        path,
        &mut cfg,
        peer.clone(),
        expected_peer.is_some(),
        remote.invite_proof.as_ref(),
    )?;
    remember_advertised_peers(path, &mut cfg, &peer, remote.peers)?;
    Ok(())
}

async fn exchange_hello(conn: &Connection, cfg: &Config) -> Result<Hello> {
    timeout(Duration::from_secs(15), async {
        let mut ticker = interval(Duration::from_millis(250));
        send_hello(conn, cfg).await?;
        loop {
            tokio::select! {
                _ = ticker.tick() => send_hello(conn, cfg).await?,
                data = conn.read_datagram() => {
                    let data = data.context("failed to read esp hello")?;
                    match serde_yaml::from_slice(&data) {
                        Ok(hello) => return Ok(hello),
                        Err(err) => debug!(error = %err, "ignoring non-hello datagram during handshake"),
                    }
                }
            }
        }
    })
    .await
    .context("timed out waiting for esp peer hello")?
}

async fn send_hello(conn: &Connection, cfg: &Config) -> Result<()> {
    let hello = Hello {
        network_id: cfg.network_id.clone(),
        name: cfg.name.clone(),
        connection_id: cfg.connection_id.clone(),
        invite_proof: cfg.invite_proof.clone(),
        peers: cfg.peers.clone(),
    };
    let data = serde_yaml::to_string(&hello)?.into_bytes();
    conn.send_datagram_wait(Bytes::from(data))
        .await
        .context("failed to send esp hello")?;
    Ok(())
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
    path: &PathBuf,
    cfg: &mut Config,
    peer: Peer,
    was_expected: bool,
    invite_proof: Option<&InviteProof>,
) -> Result<()> {
    if was_expected || cfg.peer_by_id(peer.node_id).is_some() {
        if insert_peer(cfg, peer)? {
            cfg.save(path)?;
        }
        return Ok(());
    }

    if !cfg.can_accept_invited_peer(invite_proof) {
        bail!("rejecting unknown peer {}", peer.node_id);
    }

    info!(peer = %peer.node_id, "remembering invited peer");
    insert_peer(cfg, peer)?;
    cfg.save(path)
}

pub fn remember_advertised_peers(
    path: &PathBuf,
    cfg: &mut Config,
    remote_peer: &Peer,
    advertised_peers: Vec<Peer>,
) -> Result<()> {
    if advertised_peers.len() > MAX_SHARED_PEERS {
        bail!(
            "peer shared {} peers, maximum is {}",
            advertised_peers.len(),
            MAX_SHARED_PEERS
        );
    }

    let mut changed = false;
    for peer in advertised_peers {
        if peer.node_id == remote_peer.node_id {
            continue;
        }
        if insert_peer(cfg, peer)? {
            changed = true;
        }
    }
    if changed {
        cfg.save(path)?;
    }
    Ok(())
}

fn remember_proxy_peer(
    path: &PathBuf,
    cfg: &mut Config,
    peer: Peer,
    invite_proof: Option<&InviteProof>,
) -> Result<()> {
    if cfg.peer_by_id(peer.node_id).is_none() && !cfg.can_accept_invited_peer(invite_proof) {
        bail!("rejecting unknown peer {}", peer.node_id);
    }
    if insert_peer(cfg, peer)? {
        cfg.save(path)?;
    }
    Ok(())
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
        .clear_ip_transports()
        .secret_key(secret_key)
        .addr_filter(AddrFilter::relay_only())
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
        requester_connection_id: cfg.connection_id,
        invite_proof: cfg.invite_proof.clone(),
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
    path: PathBuf,
    allowed_ports: &[u16],
) -> Result<()> {
    let mut cfg = Config::load(&path)?;
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .context("failed to accept TCP proxy stream")?;
    let request = read_proxy_request(&mut recv).await?;
    ensure_port_allowed(request.port, allowed_ports)?;
    let expected = cfg.peer_by_id(conn.remote_id()).cloned();
    let reported = Hello {
        network_id: request.network_id,
        name: request.requester_name,
        connection_id: request.requester_connection_id,
        invite_proof: request.invite_proof,
        peers: Vec::new(),
    };
    let peer = validate_peer_report(&cfg, conn.remote_id(), &reported, expected.as_ref())?;
    remember_proxy_peer(
        &path,
        &mut cfg,
        peer.clone(),
        reported.invite_proof.as_ref(),
    )?;
    remember_advertised_peers(&path, &mut cfg, &peer, request.peers)?;
    info!(
        peer = %peer.node_id,
        peer_name = %peer.name,
        peer_id = %peer.connection_id,
        port = request.port,
        "opening localhost TCP proxy"
    );

    let tcp = TcpStream::connect(("127.0.0.1", request.port))
        .await
        .with_context(|| format!("failed to connect to 127.0.0.1:{}", request.port))?;
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
    if allowed_ports.contains(&port) {
        return Ok(());
    }
    bail!(
        "port {} is not allowed; restart the daemon with --ports to allow it",
        port
    )
}

async fn read_proxy_request(recv: &mut iroh::endpoint::RecvStream) -> Result<TcpProxyRequest> {
    let mut len = [0u8; 2];
    recv.read_exact(&mut len)
        .await
        .context("failed to read TCP proxy request length")?;
    let len = usize::from(u16::from_be_bytes(len));
    if len > MAX_PROXY_REQUEST_LEN {
        bail!("TCP proxy request is too large");
    }

    let mut data = vec![0u8; len];
    recv.read_exact(&mut data)
        .await
        .context("failed to read TCP proxy request")?;
    serde_yaml::from_slice(&data).context("invalid TCP proxy request")
}

async fn write_proxy_request(
    send: &mut iroh::endpoint::SendStream,
    request: &TcpProxyRequest,
) -> Result<()> {
    let data = serde_yaml::to_string(request)?.into_bytes();
    if data.len() > MAX_PROXY_REQUEST_LEN || data.len() > usize::from(u16::MAX) {
        bail!("TCP proxy request is too large");
    }
    send.write_all(&(data.len() as u16).to_be_bytes())
        .await
        .context("failed to write TCP proxy request length")?;
    send.write_all(&data)
        .await
        .context("failed to write TCP proxy request")?;
    Ok(())
}

fn config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(CONFIG_FILE))
}

impl Config {
    fn load(path: &PathBuf) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut cfg: Self = serde_yaml::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let mut changed = cfg.ensure_local_identity();
        if cfg.creator_node_id.is_none() {
            cfg.creator_node_id = Some(
                cfg.peers
                    .first()
                    .map(|peer| peer.node_id)
                    .unwrap_or(cfg.secret_key()?.public()),
            );
            changed = true;
        }
        if changed {
            cfg.save(path)?;
        }
        Ok(cfg)
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        let text = serde_yaml::to_string(self)?;
        std::fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
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

    pub fn issue_invite(&mut self) -> Result<InviteCode> {
        let secret_key = self.secret_key()?;
        if self.creator_node_id != Some(secret_key.public()) {
            bail!("only the network creator can issue invites in this MVP");
        }
        let invite_id = generate_connection_id();
        let invite_secret = generate_invite_secret();
        let invite = Invite {
            version: 1,
            network_id: self.network_id.clone(),
            invite_id: invite_id.clone(),
            invite_secret: invite_secret.clone(),
            inviter_node_id: secret_key.public(),
            inviter_name: self.name.clone(),
            inviter_connection_id: self.connection_id.clone(),
        };
        let issued = InviteCode {
            invite_id: invite_id.clone(),
            code: invite.encode()?,
        };
        self.invites.push(IssuedInvite {
            invite_id,
            secret_hash: hash_invite_secret(&invite_secret),
        });
        Ok(issued)
    }

    fn can_accept_invited_peer(&self, proof: Option<&InviteProof>) -> bool {
        let Some(proof) = proof else {
            return false;
        };
        let secret_hash = hash_invite_secret(&proof.invite_secret);
        self.invites
            .iter()
            .any(|invite| invite.invite_id == proof.invite_id && invite.secret_hash == secret_hash)
    }
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
        serde_yaml::from_slice(&yaml).context("invite is not valid esp data")
    }
}
