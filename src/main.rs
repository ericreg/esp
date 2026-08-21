use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

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
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
    time::{interval, sleep, timeout},
};
use tracing::{debug, info, warn};
use uuid::Uuid;

const CONTROL_ALPN: &[u8] = b"arc/control/0";
const TCP_ALPN: &[u8] = b"arc/tcp/0";
const CONFIG_FILE: &str = ".arc.yml";
const DEFAULT_CIDR: &str = "100.88.0.0/24";
const DEFAULT_CREATOR_IP: Ipv4Addr = Ipv4Addr::new(100, 88, 0, 1);
const DEFAULT_INVITED_IP: Ipv4Addr = Ipv4Addr::new(100, 88, 0, 2);
const DEFAULT_MTU: u16 = 1000;
const MAX_PROXY_REQUEST_LEN: usize = 1024;
const GRACEFUL_CLOSE: VarInt = VarInt::from_u32(0);

#[derive(Parser, Debug)]
#[command(about = "A tiny iroh-backed SSH transport proxy")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create ~/.arc.yml if needed and print an invite code.
    Init,
    /// Join an arc network from an invite code.
    Join { invite: String },
    /// Run the TCP proxy daemon. This is also the default command.
    Daemon,
    /// Proxy stdio to localhost:PORT on a peer over iroh.
    Proxy {
        /// Peer overlay IP from the arc config.
        target: Ipv4Addr,
        /// TCP port to connect to on the peer's localhost.
        port: u16,
    },
    /// Print a fresh invite code for the configured network.
    Invite,
    /// Print local tunnel information.
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    version: u8,
    network_id: String,
    cidr: String,
    mtu: u16,
    my_ip: Ipv4Addr,
    secret_key: String,
    peers: Vec<Peer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Peer {
    node_id: EndpointId,
    ip: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Invite {
    version: u8,
    network_id: String,
    cidr: String,
    mtu: u16,
    inviter_node_id: EndpointId,
    inviter_ip: Ipv4Addr,
    assigned_ip: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Hello {
    network_id: String,
    ip: Ipv4Addr,
}

#[derive(Debug, Serialize, Deserialize)]
struct TcpProxyRequest {
    network_id: String,
    requester_ip: Ipv4Addr,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Daemon) {
        Command::Init => init().await,
        Command::Join { invite } => join(&invite),
        Command::Daemon => daemon().await,
        Command::Proxy { target, port } => proxy(target, port).await,
        Command::Invite => print_invite(),
        Command::Status => status(),
    }
}

async fn init() -> Result<()> {
    let path = config_path()?;
    let cfg = if path.exists() {
        Config::load(&path)?
    } else {
        let secret_key = SecretKey::generate();
        let cfg = Config {
            version: 1,
            network_id: Uuid::new_v4().to_string(),
            cidr: DEFAULT_CIDR.to_string(),
            mtu: DEFAULT_MTU,
            my_ip: DEFAULT_CREATOR_IP,
            secret_key: encode_secret_key(&secret_key),
            peers: Vec::new(),
        };
        cfg.save(&path)?;
        cfg
    };

    println!("arc config: {}", path.display());
    println!("node id: {}", cfg.secret_key()?.public());
    println!("tunnel ip: {}", cfg.my_ip);
    println!("invite: {}", cfg.invite_code()?);
    Ok(())
}

fn join(invite_code: &str) -> Result<()> {
    let path = config_path()?;
    if path.exists() {
        bail!(
            "{} already exists; delete it first to leave the current arc network",
            path.display()
        );
    }

    let invite = Invite::decode(invite_code)?;
    let secret_key = SecretKey::generate();
    let cfg = Config {
        version: 1,
        network_id: invite.network_id,
        cidr: invite.cidr,
        mtu: invite.mtu,
        my_ip: invite.assigned_ip,
        secret_key: encode_secret_key(&secret_key),
        peers: vec![Peer {
            node_id: invite.inviter_node_id,
            ip: invite.inviter_ip,
        }],
    };
    cfg.save(&path)?;

    println!("arc config: {}", path.display());
    println!("node id: {}", secret_key.public());
    println!("tunnel ip: {}", cfg.my_ip);
    println!("peer ip: {}", cfg.peers[0].ip);
    Ok(())
}

fn print_invite() -> Result<()> {
    let cfg = Config::load(&config_path()?)?;
    println!("{}", cfg.invite_code()?);
    Ok(())
}

fn status() -> Result<()> {
    let path = config_path()?;
    let cfg = Config::load(&path)?;
    println!("arc config: {}", path.display());
    println!("network: {}", cfg.network_id);
    println!("cidr: {}", cfg.cidr);
    println!("node id: {}", cfg.secret_key()?.public());
    println!("tunnel ip: {}", cfg.my_ip);
    for peer in &cfg.peers {
        println!("peer: {} {}", peer.ip, peer.node_id);
    }
    Ok(())
}

async fn daemon() -> Result<()> {
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

    info!(node_id = %endpoint.id(), "arc endpoint bound");
    endpoint.online().await;
    info!(addr = ?endpoint.addr(), "arc endpoint online");

    if let Some(peer) = cfg.peers.first().cloned() {
        tokio::spawn(run_control_dialer(endpoint.clone(), cfg.clone(), peer));
    }

    run_acceptor(endpoint.clone(), path).await?;
    endpoint.close().await;
    Ok(())
}

async fn run_control_dialer(endpoint: Endpoint, cfg: Config, peer: Peer) {
    loop {
        info!(peer = %peer.node_id, peer_ip = %peer.ip, "dialing arc control peer");
        match endpoint.connect(peer.node_id, CONTROL_ALPN).await {
            Ok(conn) => {
                info!(peer = %peer.node_id, "arc control peer connected");
                if let Err(err) = exchange_and_validate_hello(&conn, &cfg, Some(&peer)).await {
                    warn!(error = %err, "arc control handshake failed");
                    conn.close(GRACEFUL_CLOSE, b"bad hello");
                } else {
                    let reason = conn.closed().await;
                    debug!(reason = %reason, "arc control connection closed");
                }
            }
            Err(err) => {
                warn!(error = %err, "failed to connect to arc control peer");
            }
        }
        sleep(Duration::from_secs(3)).await;
    }
}

async fn run_acceptor(endpoint: Endpoint, path: PathBuf) -> Result<()> {
    info!("accepting arc control and TCP proxy connections");
    while let Some(incoming) = endpoint.accept().await {
        let path = path.clone();
        tokio::spawn(async move {
            let accepting = match incoming.accept() {
                Ok(accepting) => accepting,
                Err(err) => {
                    warn!(error = %err, "failed to accept incoming arc connection");
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
                        "accepted arc connection"
                    );
                    let result = if alpn == CONTROL_ALPN {
                        handle_control_connection(conn, path).await
                    } else if alpn == TCP_ALPN {
                        handle_tcp_proxy_connection(conn, path).await
                    } else {
                        conn.close(GRACEFUL_CLOSE, b"unknown alpn");
                        Ok(())
                    };
                    if let Err(err) = result {
                        warn!(error = %err, "arc connection stopped");
                    }
                }
                Err(err) => warn!(error = %err, "incoming arc connection failed"),
            }
        });
    }
    Ok(())
}

async fn handle_control_connection(conn: Connection, path: PathBuf) -> Result<()> {
    let mut cfg = Config::load(&path)?;
    let peer = exchange_and_validate_hello(&conn, &cfg, None).await?;
    remember_peer(&path, &mut cfg, peer)?;
    let reason = conn.closed().await;
    debug!(reason = %reason, "arc control connection closed");
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
                    let data = data.context("failed to read arc hello")?;
                    match serde_yaml::from_slice(&data) {
                        Ok(hello) => return Ok(hello),
                        Err(err) => debug!(error = %err, "ignoring non-hello datagram during handshake"),
                    }
                }
            }
        }
    })
    .await
    .context("timed out waiting for arc peer hello")?
}

async fn send_hello(conn: &Connection, cfg: &Config) -> Result<()> {
    let hello = Hello {
        network_id: cfg.network_id.clone(),
        ip: cfg.my_ip,
    };
    let data = serde_yaml::to_string(&hello)?.into_bytes();
    conn.send_datagram_wait(Bytes::from(data))
        .await
        .context("failed to send arc hello")?;
    Ok(())
}

async fn exchange_and_validate_hello(
    conn: &Connection,
    cfg: &Config,
    expected_peer: Option<&Peer>,
) -> Result<Peer> {
    let remote = exchange_hello(conn, cfg).await?;
    validate_peer_report(cfg, conn.remote_id(), remote, expected_peer)
}

fn validate_peer_report(
    cfg: &Config,
    node_id: EndpointId,
    remote: Hello,
    expected_peer: Option<&Peer>,
) -> Result<Peer> {
    if remote.network_id != cfg.network_id {
        bail!("peer joined a different arc network");
    }
    if remote.ip == cfg.my_ip || !cidr_contains(&cfg.cidr, remote.ip)? {
        bail!("peer reported invalid overlay ip {}", remote.ip);
    }
    if let Some(peer) = expected_peer {
        if node_id != peer.node_id {
            bail!("peer node id {}, expected {}", node_id, peer.node_id);
        }
        if remote.ip != peer.ip {
            bail!("peer reported ip {}, expected {}", remote.ip, peer.ip);
        }
        return Ok(peer.clone());
    }
    Ok(Peer {
        node_id,
        ip: remote.ip,
    })
}

fn remember_peer(path: &PathBuf, cfg: &mut Config, peer: Peer) -> Result<()> {
    if cfg.peer_by_id(peer.node_id).is_some() {
        return Ok(());
    }
    if let Some(existing) = cfg.peer_by_ip(peer.ip) {
        if existing.node_id != peer.node_id {
            bail!(
                "overlay ip {} belongs to {}, not {}",
                peer.ip,
                existing.node_id,
                peer.node_id
            );
        }
        return Ok(());
    }
    if !cfg.peers.is_empty() {
        bail!("rejecting unknown peer {} {}", peer.ip, peer.node_id);
    }

    info!(peer = %peer.node_id, peer_ip = %peer.ip, "remembering invited peer");
    cfg.peers.push(peer);
    cfg.save(path)
}

async fn proxy(target: Ipv4Addr, port: u16) -> Result<()> {
    let cfg = Config::load(&config_path()?)?;
    let peer = cfg
        .peer_by_ip(target)
        .ok_or_else(|| anyhow!("no configured arc peer with overlay ip {}", target))?
        .clone();
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
        .with_context(|| format!("failed to connect to arc peer {}", peer.node_id))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("failed to open TCP proxy stream")?;
    let request = TcpProxyRequest {
        network_id: cfg.network_id,
        requester_ip: cfg.my_ip,
        port,
    };
    write_proxy_request(&mut send, &request).await?;

    let mut stdin_to_peer = tokio::spawn(async move {
        let mut stdin = io::stdin();
        io::copy(&mut stdin, &mut send)
            .await
            .context("failed to copy stdin to arc peer")?;
        send.finish().context("failed to finish arc send stream")?;
        Ok::<(), anyhow::Error>(())
    });
    let mut peer_to_stdout = tokio::spawn(async move {
        let mut stdout = io::stdout();
        io::copy(&mut recv, &mut stdout)
            .await
            .context("failed to copy arc peer to stdout")?;
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

async fn handle_tcp_proxy_connection(conn: Connection, path: PathBuf) -> Result<()> {
    let cfg = Config::load(&path)?;
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .context("failed to accept TCP proxy stream")?;
    let request = read_proxy_request(&mut recv).await?;
    let reported = Hello {
        network_id: request.network_id,
        ip: request.requester_ip,
    };
    let expected = cfg.peer_by_id(conn.remote_id());
    let peer = validate_peer_report(&cfg, conn.remote_id(), reported, expected)?;
    info!(
        peer = %peer.node_id,
        peer_ip = %peer.ip,
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
            .context("failed to copy arc peer to local TCP socket")?;
        tcp_write
            .shutdown()
            .await
            .context("failed to shutdown local TCP write side")?;
        Ok::<(), anyhow::Error>(())
    });
    let mut tcp_to_peer = tokio::spawn(async move {
        io::copy(&mut tcp_read, &mut send)
            .await
            .context("failed to copy local TCP socket to arc peer")?;
        send.finish().context("failed to finish arc send stream")?;
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

fn cidr_prefix(cidr: &str) -> Result<u8> {
    let (_, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("CIDR must contain a / prefix"))?;
    let prefix: u8 = prefix.parse().context("invalid CIDR prefix")?;
    if prefix > 32 {
        bail!("IPv4 prefix must be <= 32");
    }
    Ok(prefix)
}

fn cidr_contains(cidr: &str, ip: Ipv4Addr) -> Result<bool> {
    let (base, _) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("CIDR must contain a / prefix"))?;
    let base: Ipv4Addr = base.parse().context("invalid CIDR address")?;
    let prefix = cidr_prefix(cidr)?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok((u32::from(base) & mask) == (u32::from(ip) & mask))
}

fn config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(CONFIG_FILE))
}

impl Config {
    fn load(path: &PathBuf) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_yaml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        let text = serde_yaml::to_string(self)?;
        std::fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
    }

    fn secret_key(&self) -> Result<SecretKey> {
        decode_secret_key(&self.secret_key).context("invalid secret_key in arc config")
    }

    fn peer_by_id(&self, id: EndpointId) -> Option<&Peer> {
        self.peers.iter().find(|peer| peer.node_id == id)
    }

    fn peer_by_ip(&self, ip: Ipv4Addr) -> Option<&Peer> {
        self.peers.iter().find(|peer| peer.ip == ip)
    }

    fn invite_code(&self) -> Result<String> {
        if !self.peers.is_empty() {
            bail!("this two-host MVP only supports invites from the network creator");
        }
        let secret_key = self.secret_key()?;
        let invite = Invite {
            version: 1,
            network_id: self.network_id.clone(),
            cidr: self.cidr.clone(),
            mtu: self.mtu,
            inviter_node_id: secret_key.public(),
            inviter_ip: self.my_ip,
            assigned_ip: DEFAULT_INVITED_IP,
        };
        invite.encode()
    }
}

fn encode_secret_key(secret_key: &SecretKey) -> String {
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
    fn encode(&self) -> Result<String> {
        let yaml = serde_yaml::to_string(self)?;
        Ok(URL_SAFE_NO_PAD.encode(yaml))
    }

    fn decode(code: &str) -> Result<Self> {
        let yaml = URL_SAFE_NO_PAD
            .decode(code.trim())
            .context("invite is not valid base64")?;
        serde_yaml::from_slice(&yaml).context("invite is not valid arc data")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_round_trips() {
        let key = SecretKey::generate();
        let invite = Invite {
            version: 1,
            network_id: "net".to_string(),
            cidr: DEFAULT_CIDR.to_string(),
            mtu: DEFAULT_MTU,
            inviter_node_id: key.public(),
            inviter_ip: DEFAULT_CREATOR_IP,
            assigned_ip: DEFAULT_INVITED_IP,
        };

        let code = invite.encode().unwrap();
        let decoded = Invite::decode(&code).unwrap();
        assert_eq!(decoded.network_id, invite.network_id);
        assert_eq!(decoded.inviter_node_id, invite.inviter_node_id);
        assert_eq!(decoded.assigned_ip, invite.assigned_ip);
    }
}
