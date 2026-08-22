use std::{path::PathBuf, time::Duration};

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
    io::{self, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tracing::{info, warn};
use uuid::Uuid;

const CONTROL_ALPN: &[u8] = b"esp/control/0";
const TCP_ALPN: &[u8] = b"esp/tcp/0";
const CONFIG_FILE: &str = ".esp.yml";
pub const DEFAULT_ALLOWED_PORT: u16 = 22;
const MAX_PROXY_REQUEST_LEN: usize = 64 * 1024 - 1;
const MAX_CONTROL_MESSAGE_LEN: usize = 64 * 1024 - 1;
pub const MAX_SHARED_PEERS: usize = 100;
const GRACEFUL_CLOSE: VarInt = VarInt::from_u32(0);
const MEMBERSHIP_SIGNATURE_CONTEXT: &str = "esp/membership/1";
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
    run_acceptor(endpoint.clone(), path, allowed_ports).await?;
    endpoint.close().await;
    Ok(())
}

async fn sync_joined_peer_once(path: &PathBuf, inviter: &Peer) -> Result<()> {
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
    sync_control_server(&conn, &path).await?;
    conn.close(GRACEFUL_CLOSE, b"synced");
    Ok(())
}

async fn sync_control_client(
    conn: &Connection,
    path: &PathBuf,
    expected_peer: &Peer,
) -> Result<()> {
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

async fn sync_control_server(conn: &Connection, path: &PathBuf) -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let mut cfg = Config::load(path)?;
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .context("failed to accept esp control stream")?;
        let remote = read_control_hello(&mut recv).await?;
        let peer = validate_peer_report(&cfg, conn.remote_id(), &remote, None)?;
        let remote_memberships = memberships_from_hello(&remote);
        let granted_membership = remember_control_peer(
            path,
            &mut cfg,
            peer.clone(),
            false,
            remote.invite_proof.as_ref(),
            remote.membership.as_ref(),
            &remote_memberships,
        )?;
        remember_advertised_peers_with_memberships(
            path,
            &mut cfg,
            &peer,
            remote.peers,
            remote_memberships,
        )?;
        let response = ControlResponse {
            hello: hello_from_config(&cfg),
            granted_membership,
        };
        write_control_response(&mut send, &response).await?;
        send.finish()
            .context("failed to finish esp control send stream")?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("timed out waiting for esp control sync")?
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
    direct_membership: Option<&MembershipCertificate>,
    extra_memberships: &[MembershipCertificate],
) -> Result<Option<MembershipCertificate>> {
    let verified_membership =
        verified_membership_for_peer(cfg, &peer, direct_membership, extra_memberships)?;
    if let Some(membership) = verified_membership.as_ref() {
        insert_membership(cfg, membership.clone())?;
    }

    if was_expected || cfg.peer_by_id(peer.node_id).is_some() {
        if insert_peer(cfg, peer)? || verified_membership.is_some() {
            cfg.save(path)?;
        }
        return Ok(None);
    }

    if verified_membership.is_some() {
        if insert_peer(cfg, peer)? {
            cfg.save(path)?;
        }
        return Ok(None);
    }

    let Some(granted_membership) = consume_invite_and_issue_membership(cfg, &peer, invite_proof)?
    else {
        bail!("rejecting unknown peer {}", peer.node_id);
    };

    info!(peer = %peer.node_id, "remembering invited peer");
    insert_membership(cfg, granted_membership.clone())?;
    insert_peer(cfg, peer)?;
    cfg.save(path)?;
    Ok(Some(granted_membership))
}

fn remember_proxy_peer(
    path: &PathBuf,
    cfg: &mut Config,
    peer: Peer,
    direct_membership: Option<&MembershipCertificate>,
    extra_memberships: &[MembershipCertificate],
) -> Result<()> {
    let verified_membership =
        verified_membership_for_peer(cfg, &peer, direct_membership, extra_memberships)?;
    let peer_is_known = cfg.peer_by_id(peer.node_id).is_some();
    if !peer_is_known && verified_membership.is_none() {
        bail!("rejecting unknown peer {}", peer.node_id);
    }

    let mut changed = false;
    if let Some(membership) = verified_membership {
        changed |= insert_membership(cfg, membership)?;
    }
    changed |= insert_peer(cfg, peer)?;
    if changed {
        cfg.save(path)?;
    }
    Ok(())
}

pub fn remember_advertised_peers(
    path: &PathBuf,
    cfg: &mut Config,
    remote_peer: &Peer,
    advertised_peers: Vec<Peer>,
) -> Result<()> {
    remember_advertised_peers_with_memberships(path, cfg, remote_peer, advertised_peers, Vec::new())
}

fn remember_advertised_peers_with_memberships(
    path: &PathBuf,
    cfg: &mut Config,
    remote_peer: &Peer,
    advertised_peers: Vec<Peer>,
    advertised_memberships: Vec<MembershipCertificate>,
) -> Result<()> {
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
        } else if cfg.peer_by_id(peer.node_id).is_none() {
            bail!("advertised peer {} has no valid membership", peer.node_id);
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
        membership: request.membership,
        memberships: request.memberships,
        peers: Vec::new(),
    };
    let peer = validate_peer_report(&cfg, conn.remote_id(), &reported, expected.as_ref())?;
    let remote_memberships = memberships_from_hello(&reported);
    remember_proxy_peer(
        &path,
        &mut cfg,
        peer.clone(),
        reported.membership.as_ref(),
        &remote_memberships,
    )?;
    remember_advertised_peers_with_memberships(
        &path,
        &mut cfg,
        &peer,
        request.peers,
        remote_memberships,
    )?;
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

async fn read_yaml_frame<T>(
    recv: &mut iroh::endpoint::RecvStream,
    max_len: usize,
    label: &str,
) -> Result<T>
where
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

async fn write_yaml_frame<T>(
    send: &mut iroh::endpoint::SendStream,
    value: &T,
    max_len: usize,
    label: &str,
) -> Result<()>
where
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

impl Config {
    fn load(path: &PathBuf) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut cfg: Self = serde_yaml::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let changed = cfg.ensure_local_config()?;
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

    pub fn issue_invite(&mut self) -> Result<InviteCode> {
        self.ensure_local_config()?;
        let secret_key = self.secret_key()?;
        let invite_id = generate_connection_id();
        let invite_secret = generate_invite_secret();
        let invite = Invite {
            version: 2,
            network_id: self.network_id.clone(),
            invite_id: invite_id.clone(),
            invite_secret: invite_secret.clone(),
            creator_node_id: self.creator_node_id,
            inviter_node_id: secret_key.public(),
            inviter_name: self.name.clone(),
            inviter_connection_id: self.connection_id.clone(),
            membership_chain: self.membership_chain_for(secret_key.public())?,
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

    fn has_invite_proof(&self, proof: Option<&InviteProof>) -> bool {
        let Some(proof) = proof else {
            return false;
        };
        let secret_hash = hash_invite_secret(&proof.invite_secret);
        self.invites
            .iter()
            .any(|invite| invite.invite_id == proof.invite_id && invite.secret_hash == secret_hash)
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
    pub fn issue(cfg: &Config, issuer_key: &SecretKey, subject: &Peer) -> Result<Self> {
        if !is_valid_connection_id(&subject.connection_id) {
            bail!("cannot issue membership for invalid connection id");
        }
        let mut membership = Self {
            version: 1,
            network_id: cfg.network_id.clone(),
            subject_node_id: subject.node_id,
            subject_connection_id: subject.connection_id.clone(),
            issuer_node_id: issuer_key.public(),
            signature: String::new(),
        };
        let signature = issuer_key.sign(&membership.signature_payload());
        membership.signature = encode_signature(&signature);
        Ok(membership)
    }

    fn matches_peer(&self, cfg: &Config, peer: &Peer) -> Result<()> {
        if self.version != 1 {
            bail!(
                "unsupported membership certificate version {}",
                self.version
            );
        }
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
        self.issuer_node_id
            .verify(&self.signature_payload(), &signature)
            .context("membership certificate signature is invalid")
    }

    fn signature_payload(&self) -> Vec<u8> {
        let fields = [
            self.version.to_string(),
            self.network_id.clone(),
            self.subject_node_id.to_string(),
            self.subject_connection_id.clone(),
            self.issuer_node_id.to_string(),
        ];
        let mut payload = Vec::new();
        append_signed_field(&mut payload, MEMBERSHIP_SIGNATURE_CONTEXT);
        for field in &fields {
            append_signed_field(&mut payload, field);
        }
        payload
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
    path: &PathBuf,
    cfg: &mut Config,
    membership: MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<()> {
    let local_peer = cfg.local_peer()?;
    membership.matches_peer(cfg, &local_peer)?;
    verify_membership_chain(cfg, &membership, extra_memberships)?;
    cfg.membership = Some(membership);
    cfg.invite_proof = None;
    cfg.save(path)
}

fn consume_invite_and_issue_membership(
    cfg: &mut Config,
    peer: &Peer,
    invite_proof: Option<&InviteProof>,
) -> Result<Option<MembershipCertificate>> {
    if !cfg.has_invite_proof(invite_proof) {
        return Ok(None);
    }
    let local_peer = cfg.local_peer()?;
    let local_membership = cfg
        .membership
        .as_ref()
        .ok_or_else(|| anyhow!("local host has no membership certificate"))?;
    local_membership.matches_peer(cfg, &local_peer)?;
    verify_membership_chain(cfg, local_membership, &[])?;
    if !cfg.consume_invite_proof(invite_proof) {
        return Ok(None);
    }
    let secret_key = cfg.secret_key()?;
    MembershipCertificate::issue(cfg, &secret_key, peer).map(Some)
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
    if membership.version != 1 {
        bail!(
            "unsupported membership certificate version {}",
            membership.version
        );
    }
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
        serde_yaml::from_slice(&yaml).context("invite is not valid esp data")
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

    #[test]
    fn membership_certificate_chains_to_creator_and_rejects_tampering() {
        let creator_key = SecretKey::generate();
        let cfg = creator_config(&creator_key);
        let member = Peer {
            node_id: SecretKey::generate().public(),
            name: "member".to_string(),
            connection_id: "DEF456".to_string(),
        };
        let membership = MembershipCertificate::issue(&cfg, &creator_key, &member).unwrap();

        membership.matches_peer(&cfg, &member).unwrap();
        verify_membership_chain(&cfg, &membership, &[]).unwrap();

        let mut tampered = membership;
        tampered.subject_connection_id = "FED654".to_string();
        assert!(verify_membership_chain(&cfg, &tampered, &[]).is_err());
    }

    #[test]
    fn invite_proof_is_consumed_when_membership_is_granted() {
        let creator_key = SecretKey::generate();
        let mut cfg = creator_config(&creator_key);
        let invite = cfg.issue_invite().unwrap();
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
        assert!(cfg.invites.is_empty());
        assert!(
            consume_invite_and_issue_membership(&mut cfg, &peer, Some(&proof))
                .unwrap()
                .is_none()
        );
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
        let advertised_membership =
            MembershipCertificate::issue(&cfg, &creator_key, &advertised_peer).unwrap();
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
}
