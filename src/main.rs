use std::{fmt, net::Ipv4Addr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint, EndpointId, RelayMode, SecretKey,
    endpoint::{Connection, VarInt, presets},
};
use serde::{Deserialize, Serialize};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};
use uuid::Uuid;

const ALPN: &[u8] = b"arc/tun/0";
const CONFIG_FILE: &str = ".arc.yml";
const DEFAULT_CIDR: &str = "100.88.0.0/24";
const DEFAULT_CREATOR_IP: Ipv4Addr = Ipv4Addr::new(100, 88, 0, 1);
const DEFAULT_INVITED_IP: Ipv4Addr = Ipv4Addr::new(100, 88, 0, 2);
const DEFAULT_MTU: u16 = 1000;
const GRACEFUL_CLOSE: VarInt = VarInt::from_u32(0);

#[derive(Parser, Debug)]
#[command(about = "A tiny iroh-backed TUN tunnel for SSH")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create ~/.arc.yml if needed and print an invite code.
    Init,
    /// Join a VPN from an invite code.
    Join { invite: String },
    /// Run the packet tunnel daemon. This is also the default command.
    Daemon,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Daemon) {
        Command::Init => init().await,
        Command::Join { invite } => join(&invite),
        Command::Daemon => daemon().await,
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
    let cfg = Config::load(&config_path()?)?;
    let tun = Arc::new(create_tun(&cfg)?);
    info!(
        ip = %cfg.my_ip,
        cidr = %cfg.cidr,
        mtu = cfg.mtu,
        "arc TUN interface ready"
    );

    let secret_key = cfg.secret_key()?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Default)
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;

    info!(node_id = %endpoint.id(), "arc endpoint bound");
    endpoint.online().await;
    info!(addr = ?endpoint.addr(), "arc endpoint online");

    if let Some(peer) = cfg.peers.first().cloned() {
        run_dialer(endpoint.clone(), tun.clone(), cfg.clone(), peer).await?;
    } else {
        info!("no configured peer; accepting an invited peer that knows this network id");
        run_acceptor(endpoint.clone(), tun.clone(), cfg.clone()).await?;
    }

    endpoint.close().await;
    Ok(())
}

async fn run_dialer(
    endpoint: Endpoint,
    tun: Arc<AsyncDevice>,
    cfg: Config,
    peer: Peer,
) -> Result<()> {
    loop {
        info!(peer = %peer.node_id, peer_ip = %peer.ip, "dialing arc peer");
        match endpoint.connect(peer.node_id, ALPN).await {
            Ok(conn) => {
                info!(peer = %peer.node_id, "arc peer connected");
                if let Err(err) = bridge_connection(
                    conn,
                    tun.clone(),
                    cfg.clone(),
                    Some(peer.clone()),
                    peer.node_id,
                )
                .await
                {
                    warn!(error = %err, "arc peer bridge stopped");
                }
            }
            Err(err) => {
                warn!(error = %err, "failed to connect to arc peer");
            }
        }
        sleep(Duration::from_secs(3)).await;
    }
}

async fn run_acceptor(endpoint: Endpoint, tun: Arc<AsyncDevice>, cfg: Config) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let cfg = cfg.clone();
        let tun = tun.clone();
        tokio::spawn(async move {
            let accepting = match incoming.accept() {
                Ok(accepting) => accepting,
                Err(err) => {
                    warn!(error = %err, "failed to accept incoming arc connection");
                    return;
                }
            };

            match accepting.await {
                Ok(conn) => {
                    let remote_id = conn.remote_id();
                    let peer = cfg.peer_by_id(remote_id).cloned();
                    if peer.is_none() && !cfg.peers.is_empty() {
                        warn!(peer = %remote_id, "rejecting unknown arc peer");
                        conn.close(GRACEFUL_CLOSE, b"unknown peer");
                        return;
                    }
                    info!(peer = %remote_id, "accepted arc peer");
                    if let Err(err) = bridge_connection(conn, tun, cfg, peer, remote_id).await {
                        warn!(error = %err, "arc peer bridge stopped");
                    }
                }
                Err(err) => warn!(error = %err, "incoming arc connection failed"),
            }
        });
    }
    Ok(())
}

async fn bridge_connection(
    conn: Connection,
    tun: Arc<AsyncDevice>,
    cfg: Config,
    expected_peer: Option<Peer>,
    remote_id: EndpointId,
) -> Result<()> {
    let max_datagram = conn.max_datagram_size().unwrap_or(usize::from(cfg.mtu));
    if max_datagram < usize::from(cfg.mtu) {
        warn!(
            max_datagram,
            mtu = cfg.mtu,
            "iroh datagram size is smaller than configured TUN MTU; large packets may be dropped"
        );
    }

    let remote = exchange_hello(&conn, &cfg).await?;
    if remote.network_id != cfg.network_id {
        bail!("peer joined a different arc network");
    }
    if remote.ip == cfg.my_ip || !cidr_contains(&cfg.cidr, remote.ip)? {
        bail!("peer reported invalid overlay ip {}", remote.ip);
    }
    let peer = match expected_peer {
        Some(peer) => {
            if remote.ip != peer.ip {
                bail!("peer reported ip {}, expected {}", remote.ip, peer.ip);
            }
            peer
        }
        None => Peer {
            node_id: remote_id,
            ip: remote.ip,
        },
    };
    info!(peer = %peer.node_id, peer_ip = %peer.ip, "arc peer handshake complete");

    let to_peer = pump_tun_to_peer(
        conn.clone(),
        tun.clone(),
        peer.clone(),
        cfg.mtu,
        max_datagram,
    );
    let from_peer = pump_peer_to_tun(conn.clone(), tun, cfg.my_ip, peer);

    tokio::select! {
        result = to_peer => result.context("TUN to peer pump failed")?,
        result = from_peer => result.context("peer to TUN pump failed")?,
        reason = conn.closed() => {
            debug!(reason = %reason, "arc connection closed");
        }
    }

    conn.close(GRACEFUL_CLOSE, b"bye");
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

async fn pump_tun_to_peer(
    conn: Connection,
    tun: Arc<AsyncDevice>,
    peer: Peer,
    mtu: u16,
    max_datagram: usize,
) -> Result<()> {
    let mut buf = vec![0u8; usize::from(mtu) + 64];
    loop {
        let n = tun.recv(&mut buf).await?;
        let packet = &buf[..n];
        let Some(ipv4) = Ipv4Packet::parse(packet) else {
            debug!("dropping non-IPv4 packet from TUN");
            continue;
        };
        if ipv4.dst != peer.ip {
            debug!(dst = %ipv4.dst, peer_ip = %peer.ip, "dropping packet for non-peer destination");
            continue;
        }
        if packet.len() > max_datagram {
            warn!(
                len = packet.len(),
                max_datagram, "dropping packet larger than iroh datagram limit"
            );
            continue;
        }
        conn.send_datagram_wait(Bytes::copy_from_slice(packet))
            .await?;
    }
}

async fn pump_peer_to_tun(
    conn: Connection,
    tun: Arc<AsyncDevice>,
    my_ip: Ipv4Addr,
    peer: Peer,
) -> Result<()> {
    loop {
        let packet = conn.read_datagram().await?;
        let Some(ipv4) = Ipv4Packet::parse(&packet) else {
            debug!("dropping non-IPv4 packet from peer");
            continue;
        };
        if ipv4.src != peer.ip || ipv4.dst != my_ip {
            debug!(
                src = %ipv4.src,
                dst = %ipv4.dst,
                peer_ip = %peer.ip,
                my_ip = %my_ip,
                "dropping packet with unexpected overlay addresses"
            );
            continue;
        }
        tun.send(&packet).await?;
    }
}

fn create_tun(cfg: &Config) -> Result<AsyncDevice> {
    let prefix = cidr_prefix(&cfg.cidr)?;
    let builder = DeviceBuilder::new()
        .layer(Layer::L3)
        .mtu(cfg.mtu)
        .ipv4(cfg.my_ip, prefix, None);

    #[cfg(not(target_os = "macos"))]
    let builder = builder.name("arc0");

    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    let builder = builder.with(|device| {
        device.packet_information(false);
    });

    builder.build_async().context(
        "failed to create arc TUN device; try running the daemon with administrator privileges",
    )
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

#[derive(Debug, Eq, PartialEq)]
struct Ipv4Packet {
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

impl Ipv4Packet {
    fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }
        let version = packet[0] >> 4;
        if version != 4 {
            return None;
        }
        Some(Self {
            src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        })
    }
}

impl fmt::Display for Ipv4Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
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

    #[test]
    fn parses_ipv4_packet_addresses() {
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 100, 88, 0, 1, 100, 88, 0, 2,
        ];

        let parsed = Ipv4Packet::parse(&packet).unwrap();
        assert_eq!(parsed.src, Ipv4Addr::new(100, 88, 0, 1));
        assert_eq!(parsed.dst, Ipv4Addr::new(100, 88, 0, 2));
    }
}
