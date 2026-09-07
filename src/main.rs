use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand, ValueEnum};
use iroh::{
    Endpoint, EndpointId, RelayMode, SecretKey, Signature,
    endpoint::{Connection, Incoming, RecvStream, SendStream, VarInt, presets},
};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
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
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, filter::LevelFilter};

const CONTROL_ALPN: &[u8] = b"esp/control/cbor/2";
const TCP_ALPN: &[u8] = b"esp/tcp/cbor/2";
const ESP_DIR: &str = ".esp";
const CONFIG_FILE: &str = "config.yml";
const LOG_DIR: &str = "logs";
const LOG_FILE_PREFIX: &str = "esp";
const LOCAL_CONTROL_SOCKET_FILE: &str = ".esp.sock";

#[cfg(unix)]
const CONFIG_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
pub const DEFAULT_ALLOWED_PORT: u16 = 22;
const MAX_PROXY_REQUEST_LEN: usize = 64 * 1024 - 1;
const MAX_CONTROL_MESSAGE_LEN: usize = 64 * 1024 - 1;
const MAX_LOCAL_CONTROL_MESSAGE_LEN: usize = 64 * 1024 - 1;
const CONFIG_ACTOR_QUEUE: usize = 64;
const INCOMING_WORKERS: usize = 64;
const INCOMING_WORKER_QUEUE: usize = 1;
const PEER_QUOTA_QUEUE: usize = 256;
const DEFAULT_MAX_CONNECTIONS_PER_PEER: usize = 8;
const LOCAL_CONTROL_SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const PROXY_TRANSPORT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const INCOMING_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_PROXY_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_PROXY_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
pub const MAX_SHARED_PEERS: usize = 100;
pub const DEFAULT_MAX_KNOWN_PEERS: usize = 100;
const ABSOLUTE_MAX_KNOWN_PEERS: usize = 1000;
const GRACEFUL_CLOSE: VarInt = VarInt::from_u32(0);
const CONFIG_VERSION: u8 = 2;
const INVITE_VERSION: u8 = 2;
const MEMBERSHIP_CERTIFICATE_VERSION: u8 = 2;
const MEMBERSHIP_SIGNATURE_CONTEXT: &str = "esp/membership/2";
const NETWORK_POLICY_VERSION: u8 = 1;
const NETWORK_POLICY_SIGNATURE_CONTEXT: &str = "esp/network-policy/1";
const REVOCATION_CERTIFICATE_VERSION: u8 = 1;
const REVOCATION_SIGNATURE_CONTEXT: &str = "esp/revocation/1";
const MAX_SHARED_REVOCATIONS: usize = 100;
const CONNECTION_ID_ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static DAEMON_LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

mod admin;
mod cbor;
mod output;
mod status_output;
#[cfg(unix)]
mod transport;

#[derive(Parser, Debug)]
#[command(about = "A tiny iroh-backed SSH transport proxy")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create ~/.esp/config.yml if needed.
    Init {
        /// Admin label for this network.
        network_label: String,
        /// Maximum number of remote peers this network should remember.
        #[arg(long, default_value_t = DEFAULT_MAX_KNOWN_PEERS)]
        max_peers: usize,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// Join an esp network from an invite code.
    Join {
        /// Invite code printed by the creator.
        invite: String,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// Run the TCP proxy daemon. This is also the default command.
    Daemon {
        /// Localhost ports peers may connect to through this daemon.
        #[arg(long, value_delimiter = ',', default_value = "22")]
        ports: Vec<u16>,
        /// Maximum concurrent incoming connections from each peer, including control syncs.
        #[arg(long, default_value = "8")]
        max_connections_per_peer: NonZeroUsize,
    },
    /// Proxy stdio to localhost:PORT on a peer over iroh.
    Proxy {
        /// Peer name or six-character connection id from the esp config.
        target: String,
        /// TCP port to connect to on the peer's localhost.
        port: u16,
    },
    /// Internal shared transport, started automatically by esp proxy.
    #[cfg(unix)]
    #[command(hide = true)]
    ProxyTransport,
    /// Rename this host in esp.
    Rename {
        name: String,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// Revoke a peer by name, connection id, or node id.
    Revoke {
        /// Peer name, six-character connection id, or full node id to revoke.
        target: String,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// Update signed network policy as an admin.
    Policy {
        /// Maximum number of remote peers this network should remember.
        #[arg(long)]
        max_peers: usize,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// Print a fresh invite code for the configured network.
    Invite {
        /// Admin label assigned to the invited peer (separate from its hostname).
        name: String,
        /// Localhost ports this invited peer may connect to on esp daemons.
        #[arg(long, value_delimiter = ',', default_value = "22")]
        ports: Vec<u16>,
        /// Role this invite grants to the joined member.
        #[arg(long, value_enum, default_value = "peer")]
        role: MembershipRole,
        #[command(flatten)]
        output: output::Arguments,
    },
    /// Browse the network and revoke peers in an interactive terminal.
    Admin,
    /// Print local esp information.
    Status {
        #[command(flatten)]
        output: output::Arguments,
        /// Include the full peer list in addition to the connected peer count.
        #[arg(long)]
        peers: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    #[serde(default)]
    pub format: output::FormatConfig,
    pub network_id: String,
    pub secret_key: String,
    pub network_policy: NetworkPolicyCertificate,
    pub creator_node_id: EndpointId,
    pub invite_proof: Option<InviteProof>,
    pub membership: Option<MembershipCertificate>,
    pub memberships: Vec<MembershipCertificate>,
    pub name: String,
    pub connection_id: String,
    pub invites: Vec<IssuedInvite>,
    #[serde(default)]
    pub peer_last_connected: HashMap<String, u64>,
    pub peers: Vec<Peer>,
    pub revocations: Vec<RevocationCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    #[n(0)]
    #[cbor(with = "cbor::endpoint_id")]
    pub node_id: EndpointId,
    #[n(1)]
    pub name: String,
    #[n(2)]
    pub connection_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedInvite {
    pub admin_label: String,
    pub invite_id: String,
    pub secret_hash: String,
    pub allowed_ports: Vec<u16>,
    pub role: MembershipRole,
}

#[derive(Debug, Clone)]
pub struct InviteCode {
    pub invite_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    #[n(0)]
    pub version: u8,
    #[n(1)]
    pub network_id: String,
    #[n(2)]
    pub invite_id: String,
    #[n(3)]
    pub invite_secret: String,
    #[n(4)]
    #[cbor(with = "cbor::endpoint_id")]
    pub creator_node_id: EndpointId,
    #[n(5)]
    #[cbor(with = "cbor::endpoint_id")]
    pub inviter_node_id: EndpointId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
#[serde(deny_unknown_fields)]
pub struct InviteProof {
    #[n(0)]
    pub invite_id: String,
    #[n(1)]
    pub invite_secret: String,
}

#[derive(Debug, Clone)]
struct InviteGrant {
    admin_label: String,
    invite_id: String,
    allowed_ports: Vec<u16>,
    role: MembershipRole,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ValueEnum, Encode, Decode)]
#[serde(rename_all = "lowercase")]
#[cbor(index_only)]
pub enum MembershipRole {
    #[n(0)]
    Admin,
    #[n(1)]
    Peer,
}

impl MembershipRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Peer => "peer",
        }
    }

    fn can_issue_invites(self) -> bool {
        matches!(self, Self::Admin)
    }
}

impl std::fmt::Display for MembershipRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct MembershipCertificate {
    #[n(0)]
    pub version: u8,
    #[n(1)]
    pub network_id: String,
    #[n(2)]
    #[cbor(with = "cbor::endpoint_id")]
    pub subject_node_id: EndpointId,
    #[n(3)]
    pub subject_connection_id: String,
    #[n(4)]
    pub role: MembershipRole,
    #[n(5)]
    pub allowed_ports: Vec<u16>,
    #[n(6)]
    #[cbor(with = "cbor::endpoint_id")]
    pub issuer_node_id: EndpointId,
    #[n(7)]
    pub signature: String,
    #[n(8)]
    pub admin_label: String,
    #[n(9)]
    pub invite_id: Option<String>,
    #[n(10)]
    pub joined_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct NetworkPolicyCertificate {
    #[n(0)]
    pub version: u8,
    #[n(1)]
    pub network_id: String,
    #[n(2)]
    pub max_peers: usize,
    #[n(3)]
    #[cbor(with = "cbor::endpoint_id")]
    pub issuer_node_id: EndpointId,
    #[n(4)]
    pub issued_at_unix: u64,
    #[n(5)]
    pub signature: String,
    #[n(6)]
    pub admin_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct RevocationCertificate {
    #[n(0)]
    pub version: u8,
    #[n(1)]
    pub network_id: String,
    #[n(2)]
    #[cbor(with = "cbor::endpoint_id")]
    pub subject_node_id: EndpointId,
    #[n(3)]
    #[cbor(with = "cbor::endpoint_id")]
    pub issuer_node_id: EndpointId,
    #[n(4)]
    pub issued_at_unix: u64,
    #[n(5)]
    pub signature: String,
}

impl Serialize for MembershipCertificate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_compact().map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for MembershipCertificate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let code = String::deserialize(deserializer)?;
        Self::decode_compact(&code).map_err(serde::de::Error::custom)
    }
}

impl Serialize for NetworkPolicyCertificate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_compact().map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for NetworkPolicyCertificate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let code = String::deserialize(deserializer)?;
        Self::decode_compact(&code).map_err(serde::de::Error::custom)
    }
}

impl Serialize for RevocationCertificate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_compact().map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for RevocationCertificate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let code = String::deserialize(deserializer)?;
        Self::decode_compact(&code).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct Hello {
    #[n(0)]
    network_id: String,
    #[n(1)]
    network_policy: Option<NetworkPolicyCertificate>,
    #[n(2)]
    name: String,
    #[n(3)]
    connection_id: String,
    #[n(4)]
    invite_proof: Option<InviteProof>,
    #[n(5)]
    membership: Option<MembershipCertificate>,
    #[n(6)]
    memberships: Vec<MembershipCertificate>,
    #[n(7)]
    peers: Vec<Peer>,
    #[n(8)]
    revocations: Vec<RevocationCertificate>,
}

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct ControlResponse {
    #[n(0)]
    error: Option<String>,
    #[n(1)]
    hello: Option<Hello>,
    #[n(2)]
    granted_membership: Option<MembershipCertificate>,
}

impl ControlResponse {
    fn ok(hello: Hello, granted_membership: Option<MembershipCertificate>) -> Self {
        Self {
            error: None,
            hello: Some(hello),
            granted_membership,
        }
    }

    fn err(error: impl Into<String>) -> Self {
        Self {
            error: Some(error.into()),
            hello: None,
            granted_membership: None,
        }
    }

    fn into_ok(self) -> Result<(Hello, Option<MembershipCertificate>)> {
        if let Some(error) = self.error {
            bail!("remote esp control rejected request: {error}");
        }
        let hello = self
            .hello
            .ok_or_else(|| anyhow!("esp control response missing hello"))?;
        Ok((hello, self.granted_membership))
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct TcpProxyRequest {
    #[n(0)]
    network_id: String,
    #[n(1)]
    network_policy: NetworkPolicyCertificate,
    #[n(2)]
    requester_name: String,
    #[n(3)]
    requester_connection_id: String,
    #[n(4)]
    invite_proof: Option<InviteProof>,
    #[n(5)]
    membership: Option<MembershipCertificate>,
    #[n(6)]
    memberships: Vec<MembershipCertificate>,
    #[n(7)]
    peers: Vec<Peer>,
    #[n(8)]
    revocations: Vec<RevocationCertificate>,
    #[n(9)]
    port: u16,
}

#[derive(Debug, Clone)]
struct HostIdentity {
    name: String,
    connection_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize)]
#[cbor(array)]
struct StatusReport {
    #[n(0)]
    network_id: String,
    #[n(1)]
    max_peers: usize,
    #[n(2)]
    name: String,
    #[n(3)]
    connection_id: String,
    #[n(4)]
    #[cbor(with = "cbor::endpoint_id")]
    node_id: EndpointId,
    #[n(5)]
    invites: Vec<String>,
    #[n(6)]
    #[serde(skip_serializing)]
    peers: Vec<Peer>,
    #[n(7)]
    #[cbor(with = "cbor::endpoint_ids")]
    revocations: Vec<EndpointId>,
    /// None when an older transport does not report live presence.
    #[n(8)]
    connected_peers: Option<usize>,
    #[n(9)]
    network_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct RevocationReport {
    #[n(0)]
    #[cbor(with = "cbor::endpoint_id")]
    pub node_id: EndpointId,
    #[n(1)]
    pub display_name: String,
    #[n(2)]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub struct NetworkPolicyReport {
    #[n(0)]
    pub max_peers: usize,
    #[n(1)]
    #[cbor(with = "cbor::endpoint_id")]
    pub issuer_node_id: EndpointId,
    #[n(2)]
    pub issued_at_unix: u64,
    #[n(3)]
    pub peers: Vec<Peer>,
    #[n(4)]
    pub network_label: Option<String>,
}

#[derive(Clone)]
struct ConfigActorHandle {
    sender: mpsc::Sender<ConfigActorCommand>,
}

enum ConfigActorCommand {
    PrepareProxy {
        target: String,
        port: u16,
        respond: oneshot::Sender<Result<(Peer, TcpProxyRequest)>>,
    },
    Status {
        respond: oneshot::Sender<Result<StatusReport>>,
    },
    Admin {
        request: admin::Request,
        respond: oneshot::Sender<Result<admin::Response>>,
    },
    Connected {
        node_id: EndpointId,
        connection_id: Uuid,
        respond: oneshot::Sender<Result<()>>,
    },
    Rename {
        name: String,
        respond: oneshot::Sender<Result<HostIdentity>>,
    },
    IssueInvite {
        name: String,
        allowed_ports: Vec<u16>,
        role: MembershipRole,
        respond: oneshot::Sender<Result<InviteCode>>,
    },
    Revoke {
        target: String,
        respond: oneshot::Sender<Result<RevocationReport>>,
    },
    UpdatePolicy {
        network_label: Option<String>,
        max_peers: usize,
        respond: oneshot::Sender<Result<NetworkPolicyReport>>,
    },
    ControlSync {
        node_id: EndpointId,
        remote: Hello,
        expected_peer: Option<Peer>,
        respond: oneshot::Sender<Result<ControlResponse>>,
    },
    RegisterConnection {
        node_id: EndpointId,
        respond: oneshot::Sender<Result<RegisteredConnection>>,
    },
    UnregisterConnection {
        node_id: EndpointId,
        connection_id: Uuid,
    },
    ProxyRequest {
        node_id: EndpointId,
        request: TcpProxyRequest,
        respond: oneshot::Sender<Result<Peer>>,
    },
    Hello {
        respond: oneshot::Sender<Result<Hello>>,
    },
}

struct RegisteredConnection {
    connection_id: Uuid,
    cancel: oneshot::Receiver<()>,
}

struct ActiveConnectionGuard {
    node_id: EndpointId,
    connection_id: Uuid,
    cancel: oneshot::Receiver<()>,
    sender: mpsc::Sender<ConfigActorCommand>,
}

#[derive(Clone)]
struct PeerQuotaHandle {
    sender: mpsc::Sender<PeerQuotaCommand>,
}

struct PeerQuotaPermit {
    peer_id: EndpointId,
    sender: mpsc::Sender<PeerQuotaCommand>,
}

enum PeerQuotaCommand {
    TryAcquire {
        peer_id: EndpointId,
        respond: oneshot::Sender<bool>,
    },
    Release {
        peer_id: EndpointId,
    },
}

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
// Version 2 uses new discriminants so old daemons cannot accept named-invite
// requests while silently ignoring the new label field.
enum LocalControlRequest {
    #[n(16)]
    Proxy {
        #[n(0)]
        target: String,
        #[n(1)]
        port: u16,
    },
    #[n(17)]
    Status,
    #[n(18)]
    Rename {
        #[n(0)]
        name: String,
    },
    #[n(19)]
    IssueInvite {
        #[n(2)]
        name: String,
        #[n(0)]
        ports: Vec<u16>,
        #[n(1)]
        role: MembershipRole,
    },
    #[n(20)]
    Revoke {
        #[n(0)]
        target: String,
    },
    #[n(21)]
    UpdatePolicy {
        #[n(0)]
        max_peers: usize,
        #[n(1)]
        network_label: Option<String>,
    },
    #[n(22)]
    Admin {
        #[n(0)]
        request: admin::Request,
    },
}

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
enum LocalProxyResponse {
    #[n(0)]
    Ready,
    #[n(1)]
    Error(#[n(0)] String),
}

/// Close only this session's connection, including when its task is cancelled.
struct CloseConnectionOnDrop(Connection);

impl Drop for CloseConnectionOnDrop {
    fn drop(&mut self) {
        self.0.close(GRACEFUL_CLOSE, b"bye");
    }
}

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct LocalControlResponse {
    #[n(0)]
    error: Option<String>,
    #[n(1)]
    status: Option<StatusReport>,
    #[n(2)]
    renamed: Option<LocalRenameReport>,
    #[n(3)]
    invite_code: Option<String>,
    #[n(4)]
    revoked: Option<RevocationReport>,
    #[n(5)]
    policy: Option<NetworkPolicyReport>,
    #[n(6)]
    admin: Option<admin::Response>,
}

#[derive(Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
struct LocalRenameReport {
    #[n(0)]
    name: String,
    #[n(1)]
    connection_id: String,
}

#[derive(Debug)]
enum LocalControlOk {
    Status { report: StatusReport },
    Renamed { name: String, connection_id: String },
    Invite { code: String },
    Revoked { report: RevocationReport },
    PolicyUpdated { report: NetworkPolicyReport },
    Admin { report: admin::Response },
}

impl LocalControlResponse {
    fn ok(ok: LocalControlOk) -> Self {
        match ok {
            LocalControlOk::Admin { report } => Self {
                error: None,
                status: None,
                renamed: None,
                invite_code: None,
                revoked: None,
                policy: None,
                admin: Some(report),
            },
            LocalControlOk::Status { report } => Self {
                error: None,
                status: Some(report),
                renamed: None,
                invite_code: None,
                revoked: None,
                policy: None,
                admin: None,
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
                revoked: None,
                policy: None,
                admin: None,
            },
            LocalControlOk::Invite { code } => Self {
                error: None,
                status: None,
                renamed: None,
                invite_code: Some(code),
                revoked: None,
                policy: None,
                admin: None,
            },
            LocalControlOk::Revoked { report } => Self {
                error: None,
                status: None,
                renamed: None,
                invite_code: None,
                revoked: Some(report),
                policy: None,
                admin: None,
            },
            LocalControlOk::PolicyUpdated { report } => Self {
                error: None,
                status: None,
                renamed: None,
                invite_code: None,
                revoked: None,
                policy: Some(report),
                admin: None,
            },
        }
    }

    fn err(error: String) -> Self {
        Self {
            error: Some(error),
            status: None,
            renamed: None,
            invite_code: None,
            revoked: None,
            policy: None,
            admin: None,
        }
    }

    fn into_result(self) -> Result<LocalControlOk> {
        if let Some(error) = self.error {
            bail!(error);
        }
        match (
            self.status,
            self.renamed,
            self.invite_code,
            self.revoked,
            self.policy,
            self.admin,
        ) {
            (Some(report), None, None, None, None, None) => Ok(LocalControlOk::Status { report }),
            (None, Some(renamed), None, None, None, None) => Ok(LocalControlOk::Renamed {
                name: renamed.name,
                connection_id: renamed.connection_id,
            }),
            (None, None, Some(code), None, None, None) => Ok(LocalControlOk::Invite { code }),
            (None, None, None, Some(report), None, None) => Ok(LocalControlOk::Revoked { report }),
            (None, None, None, None, Some(report), None) => {
                Ok(LocalControlOk::PolicyUpdated { report })
            }
            (None, None, None, None, None, Some(report)) => Ok(LocalControlOk::Admin { report }),
            _ => bail!("invalid local esp control response"),
        }
    }
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Daemon {
        ports: vec![DEFAULT_ALLOWED_PORT],
        max_connections_per_peer: NonZeroUsize::new(DEFAULT_MAX_CONNECTIONS_PER_PEER).unwrap(),
    });
    let is_daemon = matches!(command, Command::Daemon { .. } | Command::Admin);
    #[cfg(unix)]
    let is_daemon = is_daemon || matches!(command, Command::ProxyTransport);
    let _logging_guard = init_logging(is_daemon)?;

    match command {
        Command::Init {
            network_label,
            max_peers,
            output,
        } => init(&network_label, max_peers, output.resolve_from_config()?).await,
        Command::Join { invite, output } => join(&invite, output.resolve_from_config()?).await,
        Command::Daemon {
            ports,
            max_connections_per_peer,
        } => daemon(ports, max_connections_per_peer.get()).await,
        Command::Proxy { target, port } => proxy(target, port).await,
        #[cfg(unix)]
        Command::ProxyTransport => transport::run().await,
        Command::Rename { name, output } => rename(&name, output.resolve_from_config()?).await,
        Command::Revoke { target, output } => revoke(&target, output.resolve_from_config()?).await,
        Command::Policy { max_peers, output } => {
            update_policy(max_peers, output.resolve_from_config()?).await
        }
        Command::Invite {
            name,
            ports,
            role,
            output,
        } => print_invite(&name, &ports, role, output.resolve_from_config()?).await,
        Command::Admin => admin::run().await,
        Command::Status { output, peers } => status(output.resolve_from_config()?, peers).await,
    }
}

fn init_logging(daemon: bool) -> Result<Option<WorkerGuard>> {
    if daemon {
        let path = daemon_log_path()?;
        let file = create_log_file(&path)?;
        let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(false)
            .thread_name("esp-log-writer")
            .finish(file);
        tracing_subscriber::fmt()
            .with_writer(writer)
            .with_env_filter(env_filter_with_default(LevelFilter::INFO))
            .try_init()
            .map_err(|err| anyhow!("failed to initialize daemon logging: {err}"))?;
        info!(path = %path.display(), "esp daemon logging to file");
        return Ok(Some(guard));
    }

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .try_init()
        .map_err(|err| anyhow!("failed to initialize logging: {err}"))?;
    Ok(None)
}

fn env_filter_with_default(default_level: LevelFilter) -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy()
}

async fn init(network_label: &str, max_peers: usize, output: output::Options) -> Result<()> {
    let network_label = normalize_network_label(network_label)?;
    validate_max_known_peers(max_peers)?;
    let path = config_path()?;
    if path.exists()
        && let Some(mut report) = request_daemon_status().await?
    {
        ensure_network_label_matches(report.network_label.as_deref(), &network_label)?;
        if report.network_label.is_none() {
            let updated =
                request_daemon_policy_update(report.max_peers, Some(network_label.clone()))
                    .await?
                    .ok_or_else(|| {
                        anyhow!("transport stopped while assigning network label; retry init")
                    })?;
            if updated.network_label.as_deref() != Some(&network_label) {
                bail!(
                    "restart the transport with the updated esp binary to assign a network label"
                );
            }
            report.network_label = updated.network_label;
        }
        return print_init_report(&path, &report, output);
    }

    let mut cfg = if path.exists() {
        Config::load(&path)?
    } else {
        create_creator_config(
            &SecretKey::generate(),
            Uuid::new_v4().to_string(),
            default_connection_name(),
            generate_connection_id(),
            max_peers,
        )?
    };
    ensure_network_label_matches(cfg.network_policy.admin_label.as_deref(), &network_label)?;
    let mut peers = Vec::new();
    if cfg.network_policy.admin_label.is_none() {
        peers = cfg
            .issue_network_policy_with_label(cfg.max_known_peers()?, Some(network_label))?
            .peers;
        cfg.save(&path)?;
    }
    cfg.validate_local_config()?;
    print_init_report(&path, &status_report_from_config(&cfg)?, output)?;
    broadcast_control_sync_from_file(&path, peers).await;
    Ok(())
}

fn normalize_network_label(label: &str) -> Result<String> {
    normalize_connection_name(label).context("invalid network label")
}

fn ensure_network_label_matches(existing: Option<&str>, requested: &str) -> Result<()> {
    if let Some(existing) = existing
        && existing != requested
    {
        bail!("network is already labeled {existing:?}; init cannot rename it");
    }
    Ok(())
}

async fn join(invite_code: &str, output: output::Options) -> Result<()> {
    let path = config_path()?;
    if path.exists() {
        bail!(
            "{} already exists; delete it first to leave the current esp network",
            path.display()
        );
    }

    let invite = Invite::decode(invite_code)?;
    let secret_key = SecretKey::generate();
    let creator_node_id = invite.creator_node_id;
    let connection_id = generate_connection_id();
    let mut cfg = Config {
        format: output::FormatConfig::default(),
        version: CONFIG_VERSION,
        network_id: invite.network_id.clone(),
        network_policy: pending_join_network_policy(&invite.network_id, creator_node_id),
        secret_key: encode_secret_key(&secret_key),
        creator_node_id,
        invite_proof: Some(InviteProof {
            invite_id: invite.invite_id,
            invite_secret: invite.invite_secret,
        }),
        membership: None,
        memberships: Vec::new(),
        name: default_connection_name(),
        connection_id: connection_id.clone(),
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: vec![Peer {
            node_id: invite.inviter_node_id,
            name: String::new(),
            connection_id: String::new(),
        }],
        revocations: Vec::new(),
    };
    let inviter = cfg.peers[0].clone();

    sync_joined_config_once(&mut cfg, &inviter)
        .await
        .context("failed to complete join sync")?;
    if path.exists() {
        bail!(
            "{} was created while joining; refusing to overwrite it",
            path.display()
        );
    }
    save_completed_join(&path, &cfg)?;

    output.print(&join_report(&path, &cfg)?)
}

fn join_report(path: &Path, cfg: &Config) -> Result<serde_json::Value> {
    let membership = cfg
        .membership
        .as_ref()
        .ok_or_else(|| anyhow!("join completed without local membership"))?;
    let peer = cfg
        .peers
        .first()
        .ok_or_else(|| anyhow!("join completed without inviter"))?;
    Ok(serde_json::json!({
        "esp_config": path.display().to_string(),
        "name": cfg.name,
        "connection_id": cfg.connection_id,
        "node_id": cfg.secret_key()?.public().to_string(),
        "peer": peer.display_name(),
        "role": membership.role,
        "allowed_ports": membership.allowed_ports()?,
        "join_sync": "complete",
        "network_label": cfg.network_policy.admin_label,
    }))
}

async fn rename(name: &str, output: output::Options) -> Result<()> {
    if let Some(identity) = request_daemon_rename(name).await? {
        print_identity(&identity, output)?;
        return Ok(());
    }

    let path = config_path()?;
    let mut cfg = Config::load(&path)?;
    cfg.name = normalize_connection_name(name)?;
    cfg.save(&path)?;
    let identity = host_identity_from_config(&cfg);
    print_identity(&identity, output)?;
    Ok(())
}

async fn print_invite(
    name: &str,
    ports: &[u16],
    role: MembershipRole,
    output: output::Options,
) -> Result<()> {
    let allowed_ports = normalize_allowed_ports(ports)?;
    if let Some(code) = request_daemon_invite(name, &allowed_ports, role).await? {
        output.print(&serde_json::json!({ "invite_code": code }))?;
        return Ok(());
    }

    let path = config_path()?;
    let mut cfg = Config::load(&path)?;
    let invite = cfg.issue_invite(name, &allowed_ports, role)?;
    cfg.save(&path)?;
    output.print(&serde_json::json!({ "invite_code": invite.code }))?;
    Ok(())
}

async fn revoke(target: &str, output: output::Options) -> Result<()> {
    if let Some(report) = request_daemon_revoke(target).await? {
        print_revocation_report(&report, output)?;
        return Ok(());
    }

    let path = config_path()?;
    let mut cfg = Config::load(&path)?;
    let report = cfg.issue_revocation(target)?;
    let peers = report.peers.clone();
    cfg.save(&path)?;
    print_revocation_report(&report, output)?;
    broadcast_control_sync_from_file(&path, peers).await;
    Ok(())
}

async fn update_policy(max_peers: usize, output: output::Options) -> Result<()> {
    validate_max_known_peers(max_peers)?;
    if let Some(report) = request_daemon_policy_update(max_peers, None).await? {
        print_policy_report(&report, output)?;
        return Ok(());
    }

    let path = config_path()?;
    let mut cfg = Config::load(&path)?;
    let report = cfg.issue_network_policy(max_peers)?;
    let peers = report.peers.clone();
    cfg.save(&path)?;
    print_policy_report(&report, output)?;
    broadcast_control_sync_from_file(&path, peers).await;
    Ok(())
}

async fn status(output: output::Options, peers: bool) -> Result<()> {
    let path = config_path()?;
    if let Some(report) = request_daemon_status().await? {
        println!(
            "{}",
            status_output::render(&path, &report, true, output.format, output.no_color, peers)?
        );
        return Ok(());
    }

    let cfg = Config::load(&path)?;
    let report = status_report_from_config(&cfg)?;
    println!(
        "{}",
        status_output::render(&path, &report, false, output.format, output.no_color, peers)?
    );
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

async fn request_daemon_invite(
    name: &str,
    ports: &[u16],
    role: MembershipRole,
) -> Result<Option<String>> {
    let Some(response) = send_local_control_request(LocalControlRequest::IssueInvite {
        name: normalize_connection_name(name)?,
        ports: ports.to_vec(),
        role,
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

async fn request_daemon_revoke(target: &str) -> Result<Option<RevocationReport>> {
    let Some(response) = send_local_control_request(LocalControlRequest::Revoke {
        target: target.to_string(),
    })
    .await?
    else {
        return Ok(None);
    };
    match response {
        LocalControlOk::Revoked { report } => Ok(Some(report)),
        _ => bail!("daemon returned unexpected response to revoke request"),
    }
}

async fn request_daemon_policy_update(
    max_peers: usize,
    network_label: Option<String>,
) -> Result<Option<NetworkPolicyReport>> {
    let Some(response) = send_local_control_request(LocalControlRequest::UpdatePolicy {
        max_peers,
        network_label,
    })
    .await?
    else {
        return Ok(None);
    };
    match response {
        LocalControlOk::PolicyUpdated { report } => Ok(Some(report)),
        _ => bail!("daemon returned unexpected response to policy request"),
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
        write_cbor_frame(
            &mut stream,
            &request,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "local esp control request",
        )
        .await?;

        let response: LocalControlResponse = read_cbor_frame(
            &mut stream,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "local esp control response (restart the transport if it uses an older esp version)",
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

fn create_creator_config(
    secret_key: &SecretKey,
    network_id: String,
    name: String,
    connection_id: String,
    max_peers: usize,
) -> Result<Config> {
    validate_max_known_peers(max_peers)?;
    let name = normalize_connection_name(&name)?;
    if !is_valid_connection_id(&connection_id) {
        bail!("connection id must be six base62 characters");
    }
    let local_peer = Peer {
        node_id: secret_key.public(),
        name: name.clone(),
        connection_id: connection_id.clone(),
    };
    let membership = MembershipCertificate::issue_for_network(
        &network_id,
        secret_key,
        &local_peer,
        &[DEFAULT_ALLOWED_PORT],
        MembershipRole::Admin,
    )?;
    let network_policy =
        NetworkPolicyCertificate::issue_for_network(&network_id, secret_key, max_peers)?;
    let cfg = Config {
        format: output::FormatConfig::default(),
        version: CONFIG_VERSION,
        network_id,
        secret_key: encode_secret_key(secret_key),
        network_policy,
        creator_node_id: local_peer.node_id,
        invite_proof: None,
        membership: Some(membership),
        memberships: Vec::new(),
        name,
        connection_id,
        invites: Vec::new(),
        peer_last_connected: HashMap::new(),
        peers: Vec::new(),
        revocations: Vec::new(),
    };
    cfg.validate_local_config()?;
    Ok(cfg)
}

fn status_report_from_config(cfg: &Config) -> Result<StatusReport> {
    Ok(StatusReport {
        network_label: cfg.network_policy.admin_label.clone(),
        connected_peers: Some(0),
        network_id: cfg.network_id.clone(),
        max_peers: cfg.max_known_peers()?,
        name: cfg.name.clone(),
        connection_id: cfg.connection_id.clone(),
        node_id: cfg.secret_key()?.public(),
        invites: cfg
            .invites
            .iter()
            .map(|invite| invite.invite_id.clone())
            .collect(),
        peers: cfg.peers.clone(),
        revocations: cfg
            .revocations
            .iter()
            .map(|revocation| revocation.subject_node_id)
            .collect(),
    })
}

fn print_init_report(path: &Path, report: &StatusReport, output: output::Options) -> Result<()> {
    output.print(&serde_json::json!({
        "esp_config": path.display().to_string(),
        "name": report.name,
        "connection_id": report.connection_id,
        "node_id": report.node_id.to_string(),
        "network_label": report.network_label,
        "next_step": "run `esp invite \"name\"` to create a named invite",
    }))
}

fn print_identity(identity: &HostIdentity, output: output::Options) -> Result<()> {
    output.print(&serde_json::json!({
        "name": identity.name,
        "connection_id": identity.connection_id,
    }))
}

fn print_revocation_report(report: &RevocationReport, output: output::Options) -> Result<()> {
    output.print(&serde_json::json!({
        "revoked": report.node_id.to_string(),
        "name": report.display_name,
    }))
}

fn print_policy_report(report: &NetworkPolicyReport, output: output::Options) -> Result<()> {
    output.print(&serde_json::json!({
        "max_peers": report.max_peers,
        "policy_issuer": report.issuer_node_id.to_string(),
        "policy_issued_at": report.issued_at_unix,
        "network_label": report.network_label,
    }))
}

async fn daemon(allowed_ports: Vec<u16>, max_connections_per_peer: usize) -> Result<()> {
    let allowed_ports = normalize_allowed_ports(&allowed_ports)?;
    #[cfg(unix)]
    let _transport_lock = transport::try_lock(&local_control_socket_path()?)?
        .ok_or_else(|| anyhow!("an esp daemon or proxy transport is already running; close active proxies and wait for the transport to become idle before starting a daemon"))?;
    #[cfg(unix)]
    let (local_control_listener, _local_control_socket) =
        prepare_local_control_socket().context("failed to start local esp control")?;

    let path = config_path()?;
    sync_pending_join_if_needed(&path).await?;
    let cfg = Config::load(&path)?;
    let secret_key = cfg.secret_key()?;
    let actor = spawn_config_actor(path, cfg);
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

    #[cfg(unix)]
    let local_control_task =
        spawn_local_control_server(local_control_listener, actor.clone(), endpoint.clone());

    info!(ports = ?allowed_ports, max_connections_per_peer, "esp TCP proxy port allowlist active");
    let accept_result = tokio::select! {
        result = run_acceptor(endpoint.clone(), actor, allowed_ports, max_connections_per_peer) => result,
        result = shutdown_signal() => result,
    };
    #[cfg(unix)]
    local_control_task.abort();
    endpoint.close().await;
    accept_result
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("failed to listen for interrupt"),
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for interrupt")
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
    endpoint: Endpoint,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_local_control_server(listener, actor, endpoint, None))
}

#[cfg(unix)]
fn local_control_socket_path() -> Result<PathBuf> {
    Ok(esp_dir()?.join(LOCAL_CONTROL_SOCKET_FILE))
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
                    "esp transport already appears to be running at {}",
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
async fn run_local_control_server(
    listener: UnixListener,
    actor: ConfigActorHandle,
    endpoint: Endpoint,
    idle_timeout: Option<Duration>,
) {
    // Aborting the server also cancels its sessions instead of detaching them.
    let mut sessions = tokio::task::JoinSet::new();
    let idle_duration = idle_timeout.unwrap_or(PROXY_TRANSPORT_IDLE_TIMEOUT);
    let idle = tokio::time::sleep(idle_duration);
    tokio::pin!(idle);
    loop {
        let accepted = tokio::select! {
            biased;
            accepted = listener.accept() => accepted,
            _ = sessions.join_next(), if !sessions.is_empty() => {
                idle.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                continue;
            },
            _ = &mut idle, if idle_timeout.is_some() && sessions.is_empty() => {
                info!("shared proxy transport idle; shutting down");
                return;
            },
        };
        match accepted {
            Ok((stream, _addr)) => {
                let actor = actor.clone();
                let endpoint = endpoint.clone();
                sessions.spawn(async move {
                    if let Err(err) = handle_local_control_connection(stream, actor, endpoint).await
                    {
                        warn!(error = %format_args!("{err:#}"), "local esp request failed");
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
    endpoint: Endpoint,
) -> Result<()> {
    let request = timeout(
        LOCAL_CONTROL_SETUP_TIMEOUT,
        read_cbor_frame(
            &mut stream,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "local esp control request",
        ),
    )
    .await
    .context("timed out reading local esp control request")??;
    if let LocalControlRequest::Proxy { target, port } = request {
        return handle_local_proxy_connection(stream, actor, endpoint, target, port).await;
    }
    timeout(LOCAL_CONTROL_SETUP_TIMEOUT, async {
        let result = match request {
            LocalControlRequest::Admin { request } => actor
                .request(|respond| ConfigActorCommand::Admin { request, respond })
                .await
                .map(|report| LocalControlOk::Admin { report }),
            LocalControlRequest::Status => actor
                .status()
                .await
                .map(|report| LocalControlOk::Status { report }),
            LocalControlRequest::Rename { name } => {
                actor
                    .rename(name)
                    .await
                    .map(|identity| LocalControlOk::Renamed {
                        name: identity.name,
                        connection_id: identity.connection_id,
                    })
            }
            LocalControlRequest::IssueInvite { name, ports, role } => actor
                .issue_invite(name, ports, role)
                .await
                .map(|invite| LocalControlOk::Invite { code: invite.code }),
            LocalControlRequest::Revoke { target } => {
                let result = actor.revoke(target).await;
                if let Ok(report) = &result {
                    spawn_control_sync_broadcast(endpoint, actor.clone(), report.peers.clone());
                }
                result.map(|mut report| {
                    // The transport broadcasts to peers; clients only need the outcome.
                    // Avoid returning the complete directory in a bounded local frame.
                    report.peers.clear();
                    LocalControlOk::Revoked { report }
                })
            }
            LocalControlRequest::UpdatePolicy {
                max_peers,
                network_label,
            } => {
                let result = actor
                    .update_policy_with_label(max_peers, network_label)
                    .await;
                if let Ok(report) = &result {
                    spawn_control_sync_broadcast(endpoint, actor.clone(), report.peers.clone());
                }
                result.map(|report| LocalControlOk::PolicyUpdated { report })
            }
            LocalControlRequest::Proxy { .. } => {
                unreachable!("proxy handled before control dispatch")
            }
        };
        let response = match result {
            Ok(ok) => LocalControlResponse::ok(ok),
            Err(err) => LocalControlResponse::err(err.to_string()),
        };
        write_cbor_frame(
            &mut stream,
            &response,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "local esp control response (restart the transport if it uses an older esp version)",
        )
        .await?;
        stream
            .shutdown()
            .await
            .context("failed to finish local esp control response")?;
        Ok(())
    })
    .await
    .context("timed out handling local esp control request")?
}

async fn sync_joined_peer_once(path: &Path, inviter: &Peer) -> Result<()> {
    let mut cfg = Config::load(path)?;
    let changed = sync_joined_config_once(&mut cfg, inviter).await?;
    if changed {
        save_completed_join(path, &cfg)?;
    }
    Ok(())
}

async fn sync_joined_config_once(cfg: &mut Config, inviter: &Peer) -> Result<bool> {
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
        let changed = sync_control_config(&conn, cfg, inviter, true).await?;
        conn.close(GRACEFUL_CLOSE, b"synced");
        Ok::<bool, anyhow::Error>(changed)
    }
    .await;
    endpoint.close().await;
    let changed = result?;
    ensure_completed_join(cfg)?;
    Ok(changed)
}

async fn sync_pending_join_if_needed(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    if cfg.membership.is_some() {
        return Ok(());
    }
    if cfg.invite_proof.is_none() {
        bail!("local host has no membership certificate");
    }
    let inviter = cfg
        .peers
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("pending join config is missing inviter peer"))?;
    sync_joined_peer_once(path, &inviter)
        .await
        .context("failed to complete pending join sync")
}

fn save_completed_join(path: &Path, cfg: &Config) -> Result<()> {
    ensure_completed_join(cfg)?;
    cfg.save(path)
}

fn ensure_completed_join(cfg: &Config) -> Result<()> {
    if cfg.membership.is_none() {
        bail!("join did not complete; no membership certificate was returned");
    }
    if cfg.invite_proof.is_some() {
        bail!("join did not complete; invite proof is still pending");
    }
    cfg.validate_local_config()
}

fn pending_join_network_policy(
    network_id: &str,
    creator_node_id: EndpointId,
) -> NetworkPolicyCertificate {
    NetworkPolicyCertificate {
        admin_label: None,
        version: NETWORK_POLICY_VERSION,
        network_id: network_id.to_string(),
        max_peers: DEFAULT_MAX_KNOWN_PEERS,
        issuer_node_id: creator_node_id,
        issued_at_unix: 0,
        signature: String::new(),
    }
}

fn spawn_control_sync_broadcast(endpoint: Endpoint, actor: ConfigActorHandle, peers: Vec<Peer>) {
    tokio::spawn(async move {
        for peer in peers {
            if let Err(err) = sync_known_peer_from_actor(&endpoint, actor.clone(), &peer).await {
                warn!(
                    peer = %peer.node_id,
                    error = %err,
                    "failed to broadcast esp control sync"
                );
            }
        }
    });
}

async fn sync_known_peer_from_actor(
    endpoint: &Endpoint,
    actor: ConfigActorHandle,
    expected_peer: &Peer,
) -> Result<()> {
    let mut active = actor.register_connection(expected_peer.node_id).await?;
    let conn = endpoint
        .connect(expected_peer.node_id, CONTROL_ALPN)
        .await
        .with_context(|| format!("failed to connect to esp peer {}", expected_peer.node_id))?;
    let _close = CloseConnectionOnDrop(conn.clone());
    let presence_id = active.connection_id;
    let result = tokio::select! {
        _ = active.cancelled() => bail!("peer has been revoked"),
        result = timeout(Duration::from_secs(15), async {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open esp control stream")?;
        let hello = actor.hello().await?;
        write_control_hello(&mut send, &hello).await?;
        finish_control_send(&mut send).await?;

        let response = read_control_response(&mut recv).await?;
        let (remote, _) = response.into_ok()?;
        actor
            .control_sync(conn.remote_id(), remote, Some(expected_peer.clone()))
            .await?;
        actor.connected(expected_peer.node_id, presence_id).await?;
        Ok::<(), anyhow::Error>(())
    })
        => result.context("timed out waiting for esp control sync")?,
    };
    conn.close(GRACEFUL_CLOSE, b"synced");
    result
}

async fn broadcast_control_sync_from_file(path: &Path, peers: Vec<Peer>) {
    if peers.is_empty() {
        return;
    }
    let result = async {
        let cfg = Config::load(path)?;
        let secret_key = cfg.secret_key()?;
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .relay_mode(RelayMode::Default)
            .bind()
            .await
            .context("failed to bind iroh endpoint for revocation broadcast")?;
        for peer in peers {
            if let Err(err) = sync_known_peer_from_file(&endpoint, path, &peer).await {
                warn!(
                    peer = %peer.node_id,
                    error = %err,
                    "failed to broadcast esp control sync"
                );
            }
        }
        endpoint.close().await;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(err) = result {
        warn!(error = %err, "failed to broadcast esp revocation");
    }
}

async fn sync_known_peer_from_file(
    endpoint: &Endpoint,
    path: &Path,
    expected_peer: &Peer,
) -> Result<()> {
    let conn = endpoint
        .connect(expected_peer.node_id, CONTROL_ALPN)
        .await
        .with_context(|| format!("failed to connect to esp peer {}", expected_peer.node_id))?;
    sync_control_client(&conn, path, expected_peer, false).await?;
    conn.close(GRACEFUL_CLOSE, b"synced");
    Ok(())
}

async fn run_acceptor(
    endpoint: Endpoint,
    actor: ConfigActorHandle,
    allowed_ports: Vec<u16>,
    max_connections_per_peer: usize,
) -> Result<()> {
    let peer_quota = spawn_peer_quota_actor(max_connections_per_peer);
    let mut incoming_queue = spawn_incoming_workers(actor, allowed_ports, peer_quota);
    info!("accepting esp control and TCP proxy connections");
    while let Some(incoming) = endpoint.accept().await {
        if let Some(incoming) = incoming_queue.try_enqueue(incoming) {
            incoming.refuse();
            warn!("incoming esp connection queue full; refused connection");
        }
    }
    Ok(())
}

struct IncomingConnectionQueue {
    workers: Vec<mpsc::Sender<Incoming>>,
    next_worker: usize,
}

impl IncomingConnectionQueue {
    fn try_enqueue(&mut self, incoming: Incoming) -> Option<Incoming> {
        let mut incoming = Some(incoming);
        for offset in 0..self.workers.len() {
            let worker = (self.next_worker + offset) % self.workers.len();
            match self.workers[worker].try_send(incoming.take().expect("incoming is present")) {
                Ok(()) => {
                    self.next_worker = (worker + 1) % self.workers.len();
                    return None;
                }
                Err(mpsc::error::TrySendError::Full(value)) => {
                    incoming = Some(value);
                }
                Err(mpsc::error::TrySendError::Closed(value)) => {
                    incoming = Some(value);
                }
            }
        }
        Some(incoming.expect("incoming is returned when all workers are full"))
    }
}

fn spawn_incoming_workers(
    actor: ConfigActorHandle,
    allowed_ports: Vec<u16>,
    peer_quota: PeerQuotaHandle,
) -> IncomingConnectionQueue {
    let mut workers = Vec::with_capacity(INCOMING_WORKERS);
    for _ in 0..INCOMING_WORKERS {
        let (sender, receiver) = mpsc::channel(INCOMING_WORKER_QUEUE);
        workers.push(sender);
        tokio::spawn(run_incoming_worker(
            receiver,
            actor.clone(),
            allowed_ports.clone(),
            peer_quota.clone(),
        ));
    }
    IncomingConnectionQueue {
        workers,
        next_worker: 0,
    }
}

async fn run_incoming_worker(
    mut receiver: mpsc::Receiver<Incoming>,
    actor: ConfigActorHandle,
    allowed_ports: Vec<u16>,
    peer_quota: PeerQuotaHandle,
) {
    while let Some(incoming) = receiver.recv().await {
        if let Err(err) =
            handle_incoming_connection(incoming, actor.clone(), &allowed_ports, &peer_quota).await
        {
            warn!(error = %format_args!("{err:#}"), "esp connection stopped");
        }
    }
}

async fn handle_incoming_connection(
    incoming: Incoming,
    actor: ConfigActorHandle,
    allowed_ports: &[u16],
    peer_quota: &PeerQuotaHandle,
) -> Result<()> {
    let accepting = match incoming.accept() {
        Ok(accepting) => accepting,
        Err(err) => {
            warn!(error = %err, "failed to accept incoming esp connection");
            return Ok(());
        }
    };
    let remote_addr = accepting.remote_addr();
    let conn = timeout(INCOMING_HANDSHAKE_TIMEOUT, accepting)
        .await
        .context("timed out waiting for incoming esp handshake")?
        .context("incoming esp connection failed")?;
    let _close = CloseConnectionOnDrop(conn.clone());
    let peer_id = conn.remote_id();
    let Some(_peer_permit) = peer_quota.try_acquire(peer_id).await? else {
        conn.close(GRACEFUL_CLOSE, b"quota exceeded");
        warn!(peer = %peer_id, "peer connection quota exceeded");
        return Ok(());
    };
    let close_conn = conn.clone();
    let mut active_connection = match actor.register_connection(peer_id).await {
        Ok(active_connection) => active_connection,
        Err(err) => {
            conn.close(GRACEFUL_CLOSE, b"revoked");
            return Err(err);
        }
    };
    let presence_id = active_connection.connection_id;
    let alpn = conn.alpn().to_vec();
    info!(
        peer = %peer_id,
        remote_addr = ?remote_addr,
        alpn = %String::from_utf8_lossy(&alpn),
        "accepted esp connection"
    );

    tokio::select! {
        result = async {
            if alpn == CONTROL_ALPN {
                handle_control_connection(conn, actor, presence_id).await
            } else if alpn == TCP_ALPN {
                handle_tcp_proxy_connection(conn, actor, allowed_ports, presence_id).await
            } else {
                conn.close(GRACEFUL_CLOSE, b"unknown alpn");
                Ok(())
            }
        } => result,
        _ = active_connection.cancelled() => {
            close_conn.close(GRACEFUL_CLOSE, b"revoked");
            Ok(())
        }
    }
}

async fn handle_control_connection(
    conn: Connection,
    actor: ConfigActorHandle,
    presence_id: Uuid,
) -> Result<()> {
    sync_control_server(&conn, actor, presence_id).await?;
    conn.close(GRACEFUL_CLOSE, b"synced");
    Ok(())
}

async fn sync_control_client(
    conn: &Connection,
    path: &Path,
    expected_peer: &Peer,
    include_invite_proof: bool,
) -> Result<()> {
    let mut cfg = Config::load(path)?;
    if sync_control_config(conn, &mut cfg, expected_peer, include_invite_proof).await? {
        cfg.save(path)?;
    }
    Ok(())
}

async fn sync_control_config(
    conn: &Connection,
    cfg: &mut Config,
    expected_peer: &Peer,
    include_invite_proof: bool,
) -> Result<bool> {
    timeout(Duration::from_secs(15), async {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("failed to open esp control stream")?;
        let hello = if include_invite_proof {
            join_hello_from_config(cfg)
        } else {
            hello_from_config(cfg)
        }?;
        write_control_hello(&mut send, &hello).await?;
        finish_control_send(&mut send).await?;

        let response = read_control_response(&mut recv).await?;
        let (remote, granted_membership) = response.into_ok()?;
        apply_control_response_to_config(
            cfg,
            conn.remote_id(),
            remote,
            expected_peer,
            granted_membership,
        )?;
        cfg.peer_last_connected
            .insert(conn.remote_id().to_string(), current_unix_time()?);
        Ok(true)
    })
    .await
    .context("timed out waiting for esp control sync")?
}

fn apply_control_response_to_config(
    cfg: &mut Config,
    node_id: EndpointId,
    remote: Hello,
    expected_peer: &Peer,
    granted_membership: Option<MembershipCertificate>,
) -> Result<bool> {
    let peer = validate_peer_report(cfg, node_id, &remote, Some(expected_peer))?;
    let remote_memberships = memberships_from_hello(&remote);
    let pending_join = cfg.membership.is_none() && cfg.invite_proof.is_some();
    let mut changed = if let Some(policy) = remote.network_policy.clone() {
        if pending_join
            && let Some(issuer_membership) =
                find_membership_by_subject(cfg, &remote_memberships, policy.issuer_node_id).cloned()
        {
            remember_bootstrap_membership_chain(cfg, &issuer_membership, &remote_memberships)?;
        }
        remember_network_policy_in_config(cfg, policy, &remote_memberships)?
    } else {
        false
    };
    let (_, peer_changed) = remember_control_peer_in_config(
        cfg,
        peer.clone(),
        true,
        remote.invite_proof.as_ref(),
        remote.membership.as_ref(),
        &remote_memberships,
    )?;
    changed |= peer_changed;
    let (revocations_changed, _) =
        remember_revocations_in_config(cfg, remote.revocations.clone(), &remote_memberships)?;
    changed |= revocations_changed;
    let can_advertise_directory =
        peer_can_advertise_directory(cfg, &peer, remote.membership.as_ref(), &remote_memberships)?;
    changed |= remember_advertised_peers_in_config(
        cfg,
        &peer,
        remote.peers,
        remote_memberships.clone(),
        can_advertise_directory,
    )?;
    let fallback_membership = if cfg.membership.is_none() {
        let local_node_id = cfg.secret_key()?.public();
        find_membership_by_subject(cfg, &remote_memberships, local_node_id).cloned()
    } else {
        None
    };
    if let Some(grant) = granted_membership.or(fallback_membership) {
        changed |= remember_local_membership_grant_in_config(cfg, grant, &remote_memberships)?;
    }
    Ok(changed)
}

async fn sync_control_server(
    conn: &Connection,
    actor: ConfigActorHandle,
    presence_id: Uuid,
) -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .context("failed to accept esp control stream")?;
        let remote = read_control_hello(&mut recv).await?;
        let response = match actor.control_sync(conn.remote_id(), remote, None).await {
            Ok(response) => {
                actor.connected(conn.remote_id(), presence_id).await?;
                response
            }
            Err(err) => {
                warn!(
                    peer = %conn.remote_id(),
                    error = %err,
                    "rejecting esp control sync"
                );
                ControlResponse::err(err.to_string())
            }
        };
        write_control_response(&mut send, &response).await?;
        finish_control_send(&mut send).await?;
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
    let mut active_connections = HashMap::<EndpointId, HashMap<Uuid, oneshot::Sender<()>>>::new();
    let mut established = HashMap::<EndpointId, HashSet<Uuid>>::new();
    while let Some(command) = receiver.recv().await {
        match command {
            ConfigActorCommand::PrepareProxy {
                target,
                port,
                respond,
            } => {
                let _ = respond.send(prepare_proxy_request(&cfg, &target, port));
            }
            ConfigActorCommand::Admin { request, respond } => {
                let _ = respond.send(admin::respond(&cfg, &established, request));
            }
            ConfigActorCommand::Connected {
                node_id,
                connection_id,
                respond,
            } => {
                let result = (|| {
                    if is_node_revoked(&cfg, node_id) || cfg.peer_by_id(node_id).is_none() {
                        bail!("cannot record an unknown or revoked peer as connected");
                    }
                    if !active_connections
                        .get(&node_id)
                        .is_some_and(|connections| connections.contains_key(&connection_id))
                    {
                        bail!("connection is no longer registered");
                    }
                    if !established
                        .get(&node_id)
                        .is_some_and(|connections| connections.contains(&connection_id))
                    {
                        let now = current_unix_time()?;
                        commit_config_change(&path, &mut cfg, |next| {
                            next.peer_last_connected.insert(node_id.to_string(), now);
                            Ok(((), true))
                        })?;
                        established
                            .entry(node_id)
                            .or_default()
                            .insert(connection_id);
                    }
                    Ok(())
                })();
                let _ = respond.send(result);
            }
            ConfigActorCommand::Status { respond } => {
                let report = status_report_from_config(&cfg).map(|mut report| {
                    report.connected_peers = Some(
                        report
                            .peers
                            .iter()
                            .filter(|peer| {
                                established
                                    .get(&peer.node_id)
                                    .is_some_and(|connections| !connections.is_empty())
                            })
                            .count(),
                    );
                    report
                });
                let _ = respond.send(report);
            }
            ConfigActorCommand::Rename { name, respond } => {
                let result = commit_config_change(&path, &mut cfg, |next| {
                    next.name = normalize_connection_name(&name)?;
                    Ok((host_identity_from_config(next), true))
                });
                let _ = respond.send(result);
            }
            ConfigActorCommand::IssueInvite {
                name,
                allowed_ports,
                role,
                respond,
            } => {
                let result = commit_config_change(&path, &mut cfg, |next| {
                    let invite = next.issue_invite(&name, &allowed_ports, role)?;
                    Ok((invite, true))
                });
                let _ = respond.send(result);
            }
            ConfigActorCommand::Revoke { target, respond } => {
                let result = commit_config_change(&path, &mut cfg, |next| {
                    let report = next.issue_revocation(&target)?;
                    Ok((report, true))
                });
                if let Ok(report) = &result {
                    terminate_active_connections(&mut active_connections, report.node_id);
                }
                let _ = respond.send(result);
            }
            ConfigActorCommand::UpdatePolicy {
                max_peers,
                network_label,
                respond,
            } => {
                let result = commit_config_change(&path, &mut cfg, |next| {
                    let report = next.issue_network_policy_with_label(max_peers, network_label)?;
                    Ok((report, true))
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
                    let (response, revoked_nodes, changed) =
                        apply_control_sync(next, node_id, remote, expected_peer)?;
                    Ok(((response, revoked_nodes), changed))
                });
                if let Ok((_, revoked_nodes)) = &result {
                    terminate_revoked_connections(&mut active_connections, revoked_nodes);
                }
                let _ = respond.send(result.map(|(response, _)| response));
            }
            ConfigActorCommand::RegisterConnection { node_id, respond } => {
                let result = if is_node_revoked(&cfg, node_id) {
                    Err(anyhow!("peer {} has been revoked", node_id))
                } else {
                    let (cancel, cancelled) = oneshot::channel();
                    let connection_id = Uuid::new_v4();
                    active_connections
                        .entry(node_id)
                        .or_default()
                        .insert(connection_id, cancel);
                    Ok(RegisteredConnection {
                        connection_id,
                        cancel: cancelled,
                    })
                };
                let _ = respond.send(result);
            }
            ConfigActorCommand::UnregisterConnection {
                node_id,
                connection_id,
            } => {
                unregister_active_connection(&mut active_connections, node_id, connection_id);
                if let Some(connections) = established.get_mut(&node_id) {
                    connections.remove(&connection_id);
                    if connections.is_empty() {
                        established.remove(&node_id);
                    }
                }
            }
            ConfigActorCommand::ProxyRequest {
                node_id,
                request,
                respond,
            } => {
                let result = commit_config_change(&path, &mut cfg, |next| {
                    let (peer, revoked_nodes, peer_revoked, changed) =
                        apply_proxy_request(next, node_id, request)?;
                    Ok(((peer, revoked_nodes, peer_revoked), changed))
                });
                if let Ok((_, revoked_nodes, _)) = &result {
                    terminate_revoked_connections(&mut active_connections, revoked_nodes);
                }
                let _ = respond.send(result.and_then(|(peer, _, peer_revoked)| {
                    if peer_revoked {
                        bail!("peer {} has been revoked", peer.node_id);
                    }
                    Ok(peer)
                }));
            }
            ConfigActorCommand::Hello { respond } => {
                let _ = respond.send(hello_from_config(&cfg));
            }
        }
        established.retain(|node, _| !is_node_revoked(&cfg, *node));
    }
}

fn terminate_revoked_connections(
    active_connections: &mut HashMap<EndpointId, HashMap<Uuid, oneshot::Sender<()>>>,
    revoked_nodes: &[EndpointId],
) {
    for node_id in revoked_nodes {
        terminate_active_connections(active_connections, *node_id);
    }
}

fn terminate_active_connections(
    active_connections: &mut HashMap<EndpointId, HashMap<Uuid, oneshot::Sender<()>>>,
    node_id: EndpointId,
) {
    if let Some(connections) = active_connections.remove(&node_id) {
        for (_, cancel) in connections {
            let _ = cancel.send(());
        }
    }
}

fn unregister_active_connection(
    active_connections: &mut HashMap<EndpointId, HashMap<Uuid, oneshot::Sender<()>>>,
    node_id: EndpointId,
    connection_id: Uuid,
) {
    if let Some(connections) = active_connections.get_mut(&node_id) {
        connections.remove(&connection_id);
        if connections.is_empty() {
            active_connections.remove(&node_id);
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
        // Preserve local presentation edits made while this actor was running.
        if let Some(format) = output::read_format(path)? {
            next.format = format;
        }
        next.save(path)?;
    }
    *cfg = next;
    Ok(output)
}

impl ConfigActorHandle {
    async fn connected(&self, node_id: EndpointId, connection_id: Uuid) -> Result<()> {
        self.request(|respond| ConfigActorCommand::Connected {
            node_id,
            connection_id,
            respond,
        })
        .await
    }

    async fn prepare_proxy(&self, target: String, port: u16) -> Result<(Peer, TcpProxyRequest)> {
        self.request(|respond| ConfigActorCommand::PrepareProxy {
            target,
            port,
            respond,
        })
        .await
    }
    async fn status(&self) -> Result<StatusReport> {
        self.request(|respond| ConfigActorCommand::Status { respond })
            .await
    }

    async fn rename(&self, name: String) -> Result<HostIdentity> {
        self.request(|respond| ConfigActorCommand::Rename { name, respond })
            .await
    }

    async fn issue_invite(
        &self,
        name: String,
        allowed_ports: Vec<u16>,
        role: MembershipRole,
    ) -> Result<InviteCode> {
        self.request(|respond| ConfigActorCommand::IssueInvite {
            name,
            allowed_ports,
            role,
            respond,
        })
        .await
    }

    async fn revoke(&self, target: String) -> Result<RevocationReport> {
        self.request(|respond| ConfigActorCommand::Revoke { target, respond })
            .await
    }

    async fn update_policy_with_label(
        &self,
        max_peers: usize,
        network_label: Option<String>,
    ) -> Result<NetworkPolicyReport> {
        self.request(|respond| ConfigActorCommand::UpdatePolicy {
            max_peers,
            network_label,
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

    async fn register_connection(&self, node_id: EndpointId) -> Result<ActiveConnectionGuard> {
        let registered = self
            .request(|respond| ConfigActorCommand::RegisterConnection { node_id, respond })
            .await?;
        Ok(ActiveConnectionGuard {
            node_id,
            connection_id: registered.connection_id,
            cancel: registered.cancel,
            sender: self.sender.clone(),
        })
    }

    async fn proxy_request(&self, node_id: EndpointId, request: TcpProxyRequest) -> Result<Peer> {
        self.request(|respond| ConfigActorCommand::ProxyRequest {
            node_id,
            request,
            respond,
        })
        .await
    }

    async fn hello(&self) -> Result<Hello> {
        self.request(|respond| ConfigActorCommand::Hello { respond })
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

impl ActiveConnectionGuard {
    async fn connected(&self) -> Result<()> {
        ConfigActorHandle {
            sender: self.sender.clone(),
        }
        .request(|respond| ConfigActorCommand::Connected {
            node_id: self.node_id,
            connection_id: self.connection_id,
            respond,
        })
        .await
    }

    async fn cancelled(&mut self) {
        let _ = (&mut self.cancel).await;
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        let command = ConfigActorCommand::UnregisterConnection {
            node_id: self.node_id,
            connection_id: self.connection_id,
        };
        match self.sender.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(command)) => {
                let sender = self.sender.clone();
                tokio::spawn(async move {
                    let _ = sender.send(command).await;
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

fn spawn_peer_quota_actor(max_per_peer: usize) -> PeerQuotaHandle {
    let (sender, receiver) = mpsc::channel(PEER_QUOTA_QUEUE);
    tokio::spawn(run_peer_quota_actor(max_per_peer, receiver));
    PeerQuotaHandle { sender }
}

async fn run_peer_quota_actor(max_per_peer: usize, mut receiver: mpsc::Receiver<PeerQuotaCommand>) {
    let mut counts = HashMap::<EndpointId, usize>::new();
    while let Some(command) = receiver.recv().await {
        match command {
            PeerQuotaCommand::TryAcquire { peer_id, respond } => {
                let current = counts.get(&peer_id).copied().unwrap_or(0);
                let accepted = current < max_per_peer;
                if accepted {
                    counts.insert(peer_id, current + 1);
                }
                if respond.send(accepted).is_err() && accepted {
                    release_peer_quota(&mut counts, peer_id);
                }
            }
            PeerQuotaCommand::Release { peer_id } => {
                release_peer_quota(&mut counts, peer_id);
            }
        }
    }
}

fn release_peer_quota(counts: &mut HashMap<EndpointId, usize>, peer_id: EndpointId) {
    match counts.get_mut(&peer_id) {
        Some(count) if *count > 1 => *count -= 1,
        Some(_) => {
            counts.remove(&peer_id);
        }
        None => {}
    }
}

impl PeerQuotaHandle {
    async fn try_acquire(&self, peer_id: EndpointId) -> Result<Option<PeerQuotaPermit>> {
        let (respond, receive) = oneshot::channel();
        let command = PeerQuotaCommand::TryAcquire { peer_id, respond };
        match self.sender.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => return Ok(None),
            Err(mpsc::error::TrySendError::Closed(_)) => bail!("peer quota actor stopped"),
        }
        if receive.await.context("peer quota actor dropped response")? {
            Ok(Some(PeerQuotaPermit {
                peer_id,
                sender: self.sender.clone(),
            }))
        } else {
            Ok(None)
        }
    }
}

impl Drop for PeerQuotaPermit {
    fn drop(&mut self) {
        let command = PeerQuotaCommand::Release {
            peer_id: self.peer_id,
        };
        match self.sender.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(command)) => {
                let sender = self.sender.clone();
                tokio::spawn(async move {
                    let _ = sender.send(command).await;
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

fn apply_control_sync(
    cfg: &mut Config,
    node_id: EndpointId,
    remote: Hello,
    expected_peer: Option<Peer>,
) -> Result<(ControlResponse, Vec<EndpointId>, bool)> {
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
    let (revocations_changed, revoked_nodes) =
        remember_revocations_in_config(cfg, remote.revocations, &remote_memberships)?;
    changed |= revocations_changed;
    if let Some(policy) = remote.network_policy.clone() {
        changed |= remember_network_policy_in_config(cfg, policy, &remote_memberships)?;
    }
    let can_advertise_directory =
        peer_can_advertise_directory(cfg, &peer, remote.membership.as_ref(), &remote_memberships)?;
    changed |= remember_advertised_peers_in_config(
        cfg,
        &peer,
        remote.peers,
        remote_memberships,
        can_advertise_directory,
    )?;
    let response = ControlResponse::ok(hello_from_config(cfg)?, granted_membership);
    Ok((response, revoked_nodes, changed))
}

fn apply_proxy_request(
    cfg: &mut Config,
    node_id: EndpointId,
    request: TcpProxyRequest,
) -> Result<(Peer, Vec<EndpointId>, bool, bool)> {
    let expected = cfg.peer_by_id(node_id).cloned();
    let request_policy = request.network_policy.clone();
    let reported = Hello {
        network_id: request.network_id,
        network_policy: Some(request_policy.clone()),
        name: request.requester_name,
        connection_id: request.requester_connection_id,
        invite_proof: request.invite_proof,
        membership: request.membership,
        memberships: request.memberships,
        peers: Vec::new(),
        revocations: request.revocations,
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
    let (revocations_changed, revoked_nodes) =
        remember_revocations_in_config(cfg, reported.revocations, &remote_memberships)?;
    changed |= revocations_changed;
    changed |= remember_network_policy_in_config(cfg, request_policy, &remote_memberships)?;
    let can_advertise_directory = peer_can_advertise_directory(
        cfg,
        &peer,
        reported.membership.as_ref(),
        &remote_memberships,
    )?;
    changed |= remember_advertised_peers_in_config(
        cfg,
        &peer,
        request.peers,
        remote_memberships,
        can_advertise_directory,
    )?;
    let peer_revoked = is_node_revoked(cfg, peer.node_id);
    Ok((peer, revoked_nodes, peer_revoked, changed))
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
        ensure_peer_capacity(cfg, peer.node_id)?;
        changed |= insert_verified_membership_chain(cfg, membership, extra_memberships)?;
        changed |= insert_peer(cfg, peer)?;
        let grant = if direct_membership.is_none() && invite_proof.is_some() {
            Some(membership.clone())
        } else {
            None
        };
        return Ok((grant, changed));
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
    ensure_peer_capacity(cfg, peer.node_id)?;
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
    ensure_peer_capacity(cfg, peer.node_id)?;
    changed |= insert_verified_membership_chain(cfg, &membership, extra_memberships)?;
    changed |= insert_peer(cfg, peer)?;
    Ok(changed)
}

pub fn remember_advertised_peers(
    path: &Path,
    cfg: &mut Config,
    remote_peer: &Peer,
    advertised_peers: Vec<Peer>,
) -> Result<()> {
    remember_advertised_peers_with_memberships(
        path,
        cfg,
        remote_peer,
        advertised_peers,
        Vec::new(),
        true,
    )
}

fn remember_advertised_peers_with_memberships(
    path: &Path,
    cfg: &mut Config,
    remote_peer: &Peer,
    advertised_peers: Vec<Peer>,
    advertised_memberships: Vec<MembershipCertificate>,
    can_advertise_directory: bool,
) -> Result<()> {
    if remember_advertised_peers_in_config(
        cfg,
        remote_peer,
        advertised_peers,
        advertised_memberships,
        can_advertise_directory,
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
    can_advertise_directory: bool,
) -> Result<bool> {
    ensure_shared_list_size("peers", advertised_peers.len())?;
    ensure_shared_list_size("memberships", advertised_memberships.len())?;
    if !can_advertise_directory {
        if advertised_peers.is_empty() {
            return Ok(false);
        }
        bail!(
            "peer {} is not an admin and cannot advertise peers",
            remote_peer.node_id
        );
    }

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
            ensure_peer_capacity(cfg, peer.node_id)?;
            changed |= insert_membership(cfg, membership)?;
        } else {
            bail!("advertised peer {} has no valid membership", peer.node_id);
        }
        if insert_peer(cfg, peer)? {
            changed = true;
        }
    }
    enforce_state_caps(cfg)?;
    Ok(changed)
}

fn remember_network_policy_in_config(
    cfg: &mut Config,
    policy: NetworkPolicyCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<bool> {
    verify_network_policy(cfg, &policy, extra_memberships)?;
    if cfg.network_policy == policy {
        return Ok(false);
    }
    if verify_network_policy(cfg, &cfg.network_policy, &[]).is_ok()
        && !network_policy_is_newer(&policy, &cfg.network_policy)
    {
        return Ok(false);
    }
    cfg.network_policy = policy;
    enforce_state_caps(cfg)?;
    Ok(true)
}

fn remember_revocations_in_config(
    cfg: &mut Config,
    revocations: Vec<RevocationCertificate>,
    extra_memberships: &[MembershipCertificate],
) -> Result<(bool, Vec<EndpointId>)> {
    if revocations.len() > MAX_SHARED_REVOCATIONS {
        bail!(
            "peer shared {} revocations, maximum is {}",
            revocations.len(),
            MAX_SHARED_REVOCATIONS
        );
    }
    let mut changed = false;
    let mut revoked_nodes = Vec::new();
    for revocation in revocations {
        verify_revocation(cfg, &revocation, extra_memberships)?;
        let subject_node_id = revocation.subject_node_id;
        if insert_revocation(cfg, revocation)? {
            changed = true;
            revoked_nodes.push(subject_node_id);
        }
    }
    if changed {
        cfg.peers
            .retain(|peer| !revoked_nodes.contains(&peer.node_id));
    }
    Ok((changed, revoked_nodes))
}

fn insert_revocation(cfg: &mut Config, revocation: RevocationCertificate) -> Result<bool> {
    if cfg.revocations.iter().any(|known| known == &revocation) {
        return Ok(false);
    }
    cfg.revocations.push(revocation);
    cfg.revocations.sort_by(|left, right| {
        left.subject_node_id
            .cmp(&right.subject_node_id)
            .then(left.issued_at_unix.cmp(&right.issued_at_unix))
            .then(left.issuer_node_id.cmp(&right.issuer_node_id))
    });
    Ok(true)
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
    let max_peers = cfg.max_known_peers()?;
    if cfg.peers.len() >= max_peers {
        bail!(
            "known peer limit reached ({}); update network policy max_peers to store more",
            max_peers
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

fn ensure_peer_capacity(cfg: &Config, node_id: EndpointId) -> Result<()> {
    let local_node_id = cfg.secret_key()?.public();
    if node_id == local_node_id || cfg.peer_by_id(node_id).is_some() {
        return Ok(());
    }
    let max_peers = cfg.max_known_peers()?;
    if cfg.peers.len() >= max_peers {
        bail!(
            "known peer limit reached ({}); update network policy max_peers to store more",
            max_peers
        );
    }
    Ok(())
}

async fn proxy(target: String, port: u16) -> Result<()> {
    #[cfg(unix)]
    {
        let stream = transport::open_proxy(
            &local_control_socket_path()?,
            &config_path()?,
            &std::env::current_exe().context("failed to locate esp executable")?,
            target,
            port,
        )
        .await?;
        proxy_stdio(io::stdin(), io::stdout(), stream).await
    }
    #[cfg(not(unix))]
    {
        let _ = (target, port);
        bail!(
            "esp proxy requires a shared transport over a Unix socket; this platform is not supported"
        )
    }
}

#[cfg(unix)]
async fn request_local_proxy(
    mut stream: UnixStream,
    target: String,
    port: u16,
) -> Result<UnixStream> {
    timeout(
        LOCAL_CONTROL_SETUP_TIMEOUT + Duration::from_secs(5),
        async {
            write_cbor_frame(
                &mut stream,
                &LocalControlRequest::Proxy { target, port },
                MAX_LOCAL_CONTROL_MESSAGE_LEN,
                "local esp proxy request",
            )
            .await?;
            let response: LocalProxyResponse = read_cbor_frame(
                &mut stream,
                MAX_LOCAL_CONTROL_MESSAGE_LEN,
                "local esp proxy response",
            )
            .await
            .context(
                "failed to read proxy response; ensure the local esp transport is up to date",
            )?;
            match response {
                LocalProxyResponse::Ready => Ok(()),
                LocalProxyResponse::Error(error) => {
                    bail!("local esp transport rejected proxy: {error}")
                }
            }
        },
    )
    .await
    .context("timed out waiting for local esp proxy setup")??;
    Ok(stream)
}

#[cfg(unix)]
async fn proxy_stdio<R, W>(mut input: R, mut output: W, stream: UnixStream) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut read, mut write) = stream.into_split();
    let upload = async {
        io::copy(&mut input, &mut write)
            .await
            .context("failed to copy stdin to esp daemon")?;
        write
            .shutdown()
            .await
            .context("failed to finish local esp send stream")
    };
    let download = async {
        io::copy(&mut read, &mut output)
            .await
            .context("failed to copy esp transport to stdout")?;
        output.flush().await.context("failed to flush stdout")
    };
    tokio::pin!(upload, download);
    tokio::select! {
        result = &mut upload => {
            result?;
            // Preserve the response after stdin EOF (TCP half-close).
            download.await
        }
        // A remote EOF must also let an interactive client with open stdin exit.
        result = &mut download => result,
    }
}

fn prepare_proxy_request(cfg: &Config, target: &str, port: u16) -> Result<(Peer, TcpProxyRequest)> {
    ensure_completed_join(cfg)?;
    let peer = cfg.resolve_peer(target)?.clone();
    let hello = hello_from_config(cfg)?;
    let request = TcpProxyRequest {
        network_id: hello.network_id,
        network_policy: cfg.network_policy.clone(),
        requester_name: hello.name,
        requester_connection_id: hello.connection_id,
        invite_proof: None,
        membership: hello.membership,
        memberships: hello.memberships,
        peers: hello.peers,
        revocations: hello.revocations,
        port,
    };
    Ok((peer, request))
}

#[cfg(unix)]
struct ProxyTunnel {
    connection: CloseConnectionOnDrop,
    send: SendStream,
    recv: RecvStream,
    active: ActiveConnectionGuard,
}

#[cfg(unix)]
async fn open_proxy_tunnel(
    endpoint: &Endpoint,
    actor: &ConfigActorHandle,
    target: String,
    port: u16,
) -> Result<ProxyTunnel> {
    let (peer, request) = actor.prepare_proxy(target, port).await?;
    let mut active = actor.register_connection(peer.node_id).await?;
    let (connection, send, recv) = tokio::select! {
        result = async {
            let conn = endpoint.connect(peer.node_id, TCP_ALPN).await
                .with_context(|| format!("failed to connect to esp peer {}", peer.node_id))?;
            let connection = CloseConnectionOnDrop(conn);
            let (mut send, mut recv) = connection.0.open_bi().await.context("failed to open TCP proxy stream")?;
            write_proxy_request(&mut send, &request).await?;
            let response: LocalProxyResponse = read_cbor_frame(&mut recv, MAX_PROXY_REQUEST_LEN, "remote proxy setup response").await?;
            match response {
                LocalProxyResponse::Ready => {},
                LocalProxyResponse::Error(message) => bail!("remote esp proxy rejected request: {message}"),
            }
            Ok::<_, anyhow::Error>((connection, send, recv))
        } => result?,
        _ = active.cancelled() => bail!("peer {} has been revoked", peer.node_id),
    };
    active.connected().await?;
    info!(peer = %peer.node_id, peer_name = %peer.name, port, "opened outgoing TCP proxy");
    Ok(ProxyTunnel {
        connection,
        send,
        recv,
        active,
    })
}

#[cfg(unix)]
async fn handle_local_proxy_connection(
    mut stream: UnixStream,
    actor: ConfigActorHandle,
    endpoint: Endpoint,
    target: String,
    port: u16,
) -> Result<()> {
    let setup = timeout(
        LOCAL_CONTROL_SETUP_TIMEOUT,
        open_proxy_tunnel(&endpoint, &actor, target, port),
    )
    .await
    .context("timed out opening esp proxy")
    .and_then(|result| result);
    let response = match &setup {
        Ok(_) => LocalProxyResponse::Ready,
        Err(err) => LocalProxyResponse::Error(format!("{err:#}")),
    };
    timeout(
        LOCAL_CONTROL_SETUP_TIMEOUT,
        write_cbor_frame(
            &mut stream,
            &response,
            MAX_LOCAL_CONTROL_MESSAGE_LEN,
            "local esp proxy response",
        ),
    )
    .await
    .context("timed out writing local esp proxy response")??;
    let ProxyTunnel {
        connection,
        send,
        recv,
        mut active,
    } = setup?;
    let (read, write) = stream.into_split();
    let result = tokio::select! {
        result = bridge_proxy(read, write, send, recv) => result,
        _ = active.cancelled() => {
            connection.0.close(GRACEFUL_CLOSE, b"revoked");
            bail!("proxy peer has been revoked");
        }
    };
    // The shared endpoint remains alive for the daemon and all other sessions.
    drop(connection);
    result
}

/// Forward both halves within this task so errors and cancellation drop both futures.
/// A clean EOF only shuts down that direction, allowing the response to drain.
async fn bridge_proxy<R, W>(
    mut read: R,
    mut write: W,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let upload = async {
        copy_with_idle_timeout(
            &mut read,
            &mut send,
            TCP_PROXY_IDLE_TIMEOUT,
            "local socket to esp peer",
        )
        .await?;
        send.finish().context("failed to finish esp send stream")?;
        // Do not close the connection while its final bytes are still in flight.
        let stopped = timeout(TCP_PROXY_IDLE_TIMEOUT, send.stopped())
            .await
            .context("timed out finishing esp send stream")?
            .context("failed to finish delivery to esp peer")?;
        if let Some(code) = stopped {
            bail!("esp peer stopped receiving with code {code}");
        }
        Ok::<(), anyhow::Error>(())
    };
    let download = async {
        copy_with_idle_timeout(
            &mut recv,
            &mut write,
            TCP_PROXY_IDLE_TIMEOUT,
            "esp peer to local socket",
        )
        .await?;
        timeout(TCP_PROXY_IDLE_TIMEOUT, write.shutdown())
            .await
            .context("timed out shutting down local socket")?
            .context("failed to shutdown local socket")?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn handle_tcp_proxy_connection(
    conn: Connection,
    actor: ConfigActorHandle,
    allowed_ports: &[u16],
    presence_id: Uuid,
) -> Result<()> {
    let (mut send, mut recv) = timeout(TCP_PROXY_SETUP_TIMEOUT, conn.accept_bi())
        .await
        .context("timed out waiting for TCP proxy stream")??;
    let setup = timeout(TCP_PROXY_SETUP_TIMEOUT, async {
        let request = read_proxy_request(&mut recv).await?;
        ensure_port_allowed(request.port, allowed_ports)?;
        let port = request.port;
        let peer = actor.proxy_request(conn.remote_id(), request).await?;
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .with_context(|| format!("failed to connect to 127.0.0.1:{port}"))?;
        actor.connected(peer.node_id, presence_id).await?;
        info!(peer = %peer.node_id, peer_name = %peer.name, port, "opened localhost TCP proxy");
        Ok::<_, anyhow::Error>(tcp)
    })
    .await
    .context("timed out setting up TCP proxy")
    .and_then(|result| result);
    let response = match &setup {
        Ok(_) => LocalProxyResponse::Ready,
        Err(err) => LocalProxyResponse::Error(format!("{err:#}")),
    };
    timeout(
        TCP_PROXY_SETUP_TIMEOUT,
        write_cbor_frame(
            &mut send,
            &response,
            MAX_PROXY_REQUEST_LEN,
            "remote proxy setup response",
        ),
    )
    .await
    .context("timed out writing TCP proxy setup response")??;
    let tcp = match setup {
        Ok(tcp) => tcp,
        Err(err) => {
            finish_control_send(&mut send).await?;
            return Err(err);
        }
    };
    let (read, write) = tcp.into_split();
    bridge_proxy(read, write, send, recv).await
}

async fn copy_with_idle_timeout<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
    label: &str,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .with_context(|| format!("{label} idle timeout"))?
            .with_context(|| format!("failed to read {label}"))?;
        if read == 0 {
            return Ok(total);
        }
        timeout(idle_timeout, writer.write_all(&buffer[..read]))
            .await
            .with_context(|| format!("{label} write idle timeout"))?
            .with_context(|| format!("failed to write {label}"))?;
        total += read as u64;
    }
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
    read_cbor_frame(recv, MAX_PROXY_REQUEST_LEN, "TCP proxy request").await
}

async fn write_proxy_request(
    send: &mut iroh::endpoint::SendStream,
    request: &TcpProxyRequest,
) -> Result<()> {
    write_cbor_frame(send, request, MAX_PROXY_REQUEST_LEN, "TCP proxy request").await
}

async fn read_control_hello(recv: &mut iroh::endpoint::RecvStream) -> Result<Hello> {
    read_cbor_frame(recv, MAX_CONTROL_MESSAGE_LEN, "esp control hello").await
}

async fn write_control_hello(send: &mut iroh::endpoint::SendStream, hello: &Hello) -> Result<()> {
    write_cbor_frame(send, hello, MAX_CONTROL_MESSAGE_LEN, "esp control hello").await
}

async fn read_control_response(recv: &mut iroh::endpoint::RecvStream) -> Result<ControlResponse> {
    read_cbor_frame(recv, MAX_CONTROL_MESSAGE_LEN, "esp control response").await
}

async fn write_control_response(
    send: &mut iroh::endpoint::SendStream,
    response: &ControlResponse,
) -> Result<()> {
    write_cbor_frame(
        send,
        response,
        MAX_CONTROL_MESSAGE_LEN,
        "esp control response",
    )
    .await
}

async fn finish_control_send(send: &mut iroh::endpoint::SendStream) -> Result<()> {
    send.finish()
        .context("failed to finish esp control send stream")?;
    if let Some(code) = send
        .stopped()
        .await
        .context("failed waiting for esp control send stream acknowledgement")?
    {
        bail!("esp control send stream stopped by peer with code {code}");
    }
    Ok(())
}

async fn read_cbor_frame<R, T>(recv: &mut R, max_len: usize, label: &str) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'b> Decode<'b, ()>,
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
    cbor::decode_exact(&data).with_context(|| format!("invalid {label}"))
}

async fn write_cbor_frame<W, T>(send: &mut W, value: &T, max_len: usize, label: &str) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Encode<()>,
{
    let data = minicbor::to_vec(value).with_context(|| format!("failed to encode {label}"))?;
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
    Ok(esp_dir()?.join(CONFIG_FILE))
}

fn daemon_log_path() -> Result<PathBuf> {
    if let Some(path) = DAEMON_LOG_PATH.get() {
        return Ok(path.clone());
    }

    let path = new_daemon_log_path()?;
    let _ = DAEMON_LOG_PATH.set(path);
    Ok(DAEMON_LOG_PATH
        .get()
        .expect("daemon log path is initialized")
        .clone())
}

fn new_daemon_log_path() -> Result<PathBuf> {
    let state_dir = esp_dir()?;
    ensure_state_dir(&state_dir)?;
    let dir = log_dir_path()?;
    ensure_state_dir(&dir)?;
    Ok(dir.join(timestamped_log_file_name(SystemTime::now())?))
}

fn timestamped_log_file_name(now: SystemTime) -> Result<String> {
    let timestamp = now
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    Ok(format!(
        "{LOG_FILE_PREFIX}-{}-{:09}.log",
        timestamp.as_secs(),
        timestamp.subsec_nanos()
    ))
}

fn log_dir_path() -> Result<PathBuf> {
    Ok(esp_dir()?.join(LOG_DIR))
}

fn esp_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(ESP_DIR))
}

fn create_log_file(path: &Path) -> Result<fs::File> {
    validate_log_target_for_write(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(CONFIG_FILE_MODE);

    let file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(CONFIG_FILE_MODE))
        .with_context(|| format!("failed to set private permissions on {}", path.display()))?;
    Ok(file)
}

fn validate_log_target_for_write(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_config_metadata(path, &metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn ensure_config_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_state_dir(parent)?;
    }
    Ok(())
}

fn ensure_state_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_state_dir(path, &metadata),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let created = create_private_dir(path)?;
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("failed to inspect {}", path.display()))?;
            validate_state_dir(path, &metadata)?;
            if created {
                validate_private_dir_permissions(path, &metadata)?;
            }
            Ok(())
        }
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn create_private_dir(path: &Path) -> Result<bool> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(PRIVATE_DIR_MODE);
    match builder.create(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err).with_context(|| format!("failed to create {}", path.display())),
    }
}

fn validate_state_dir(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        bail!(
            "{} is a symlink; refusing to use it as esp state directory",
            path.display()
        );
    }
    if !file_type.is_dir() {
        bail!("{} is not a directory", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_dir_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} permissions are {:03o}; refusing to use state directory with group/world access (run `chmod 700 {}`)",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_dir_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
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
    ensure_config_dir(path)?;
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
        let header: serde_yaml::Value = serde_yaml::from_str(&text)?;
        if header.get("version").and_then(serde_yaml::Value::as_u64) != Some(CONFIG_VERSION as u64)
        {
            bail!(
                "unsupported esp config version; upgrade all hosts, restart transports, and recreate the network with named invites (existing state has not been modified)"
            );
        }
        let cfg: Self = serde_yaml::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        cfg.validate_local_config()?;
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

    fn validate_local_config(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            bail!("unsupported config version {}", self.version);
        }
        let local_node_id = self.secret_key()?.public();
        normalize_connection_name(&self.name)?;
        if !is_valid_connection_id(&self.connection_id) {
            bail!("local connection id must be six base62 characters");
        }
        verify_network_policy(self, &self.network_policy, &[])?;
        if self.creator_node_id == local_node_id {
            let local_peer = self.local_peer()?;
            let membership = self
                .membership
                .as_ref()
                .ok_or_else(|| anyhow!("creator config missing local membership certificate"))?;
            membership.matches_peer(self, &local_peer)?;
            verify_membership_chain(self, membership, &[])?;
            if membership.role != MembershipRole::Admin {
                bail!("creator membership must be admin");
            }
        } else if let Some(membership) = &self.membership {
            let local_peer = self.local_peer()?;
            membership.matches_peer(self, &local_peer)?;
            verify_membership_chain(self, membership, &[])?;
        } else if self.invite_proof.is_none() {
            bail!("joined config missing local membership certificate");
        }
        validate_state_caps(self)
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

    fn local_membership_chain(&self) -> Result<Vec<MembershipCertificate>> {
        self.membership_chain_for(self.secret_key()?.public())
    }

    fn can_advertise_directory(&self) -> bool {
        self.local_membership_role()
            .is_some_and(MembershipRole::can_issue_invites)
    }

    fn local_membership_role(&self) -> Option<MembershipRole> {
        let membership = self.membership.as_ref()?;
        let local_peer = self.local_peer().ok()?;
        membership.matches_peer(self, &local_peer).ok()?;
        verify_membership_chain(self, membership, &[]).ok()?;
        Some(membership.role)
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

    fn max_known_peers(&self) -> Result<usize> {
        verify_network_policy(self, &self.network_policy, &[])?;
        Ok(self.network_policy.max_peers)
    }

    pub fn issue_network_policy(&mut self, max_peers: usize) -> Result<NetworkPolicyReport> {
        self.issue_network_policy_with_label(max_peers, None)
    }

    fn issue_network_policy_with_label(
        &mut self,
        max_peers: usize,
        network_label: Option<String>,
    ) -> Result<NetworkPolicyReport> {
        self.validate_local_config()?;
        self.ensure_local_admin()?;
        let peers = self.peers.clone();
        let secret_key = self.secret_key()?;
        let mut policy = NetworkPolicyCertificate::issue(self, &secret_key, max_peers)?;
        if let Some(label) = network_label {
            let label = normalize_network_label(&label)?;
            ensure_network_label_matches(policy.admin_label.as_deref(), &label)?;
            policy.admin_label = Some(label);
            policy.signature = encode_signature(&secret_key.sign(&policy.signature_payload()?));
        }
        verify_network_policy(self, &policy, &[])?;
        self.network_policy = policy.clone();
        enforce_state_caps(self)?;
        Ok(NetworkPolicyReport {
            network_label: policy.admin_label.clone(),
            max_peers: policy.max_peers,
            issuer_node_id: policy.issuer_node_id,
            issued_at_unix: policy.issued_at_unix,
            peers,
        })
    }

    pub fn issue_revocation(&mut self, target: &str) -> Result<RevocationReport> {
        self.validate_local_config()?;
        self.ensure_local_admin()?;
        let (target_id, display_name) = self.resolve_revocation_target(target)?;
        let local_node_id = self.secret_key()?.public();
        if target_id == local_node_id {
            bail!("cannot revoke the local esp node");
        }
        if is_node_revoked(self, target_id) {
            bail!("peer {} is already revoked", target_id);
        }

        let peers = self.peers.clone();
        let secret_key = self.secret_key()?;
        let revocation = RevocationCertificate::issue(self, &secret_key, target_id)?;
        verify_revocation(self, &revocation, &[])?;
        insert_revocation(self, revocation)?;
        self.peers.retain(|peer| peer.node_id != target_id);
        Ok(RevocationReport {
            node_id: target_id,
            display_name,
            peers,
        })
    }

    pub fn issue_invite(
        &mut self,
        name: &str,
        allowed_ports: &[u16],
        role: MembershipRole,
    ) -> Result<InviteCode> {
        self.validate_local_config()?;
        let allowed_ports = normalize_allowed_ports(allowed_ports)?;
        self.ensure_can_issue_invite(&allowed_ports)?;
        let secret_key = self.secret_key()?;
        let admin_label = normalize_connection_name(name)?;
        let invite_id = generate_connection_id();
        let invite_secret = generate_invite_secret();
        let invite = Invite {
            version: INVITE_VERSION,
            network_id: self.network_id.clone(),
            invite_id: invite_id.clone(),
            invite_secret: invite_secret.clone(),
            creator_node_id: self.creator_node_id,
            inviter_node_id: secret_key.public(),
        };
        let issued = InviteCode {
            invite_id: invite_id.clone(),
            code: invite.encode()?,
        };
        self.invites.push(IssuedInvite {
            admin_label,
            invite_id,
            secret_hash: hash_invite_secret(&invite_secret),
            allowed_ports,
            role,
        });
        Ok(issued)
    }

    fn ensure_local_admin(&self) -> Result<()> {
        let membership = self
            .membership
            .as_ref()
            .ok_or_else(|| anyhow!("local host has no membership certificate"))?;
        let local_peer = self.local_peer()?;
        membership.matches_peer(self, &local_peer)?;
        verify_membership_chain(self, membership, &[])?;
        if !membership.role.can_issue_invites() {
            bail!(
                "local membership role {} cannot issue invites or revoke peers",
                membership.role
            );
        }
        Ok(())
    }

    fn ensure_can_issue_invite(&self, requested_ports: &[u16]) -> Result<()> {
        self.ensure_local_admin()?;
        let local_node_id = self.secret_key()?.public();
        if self.creator_node_id == local_node_id {
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

    fn resolve_revocation_target(&self, target: &str) -> Result<(EndpointId, String)> {
        let target = target.trim();
        if let Ok(node_id) = target.parse::<EndpointId>() {
            let display_name = self
                .peer_by_id(node_id)
                .map(Peer::display_name)
                .unwrap_or_else(|| node_id.to_string());
            return Ok((node_id, display_name));
        }

        let peer = self.resolve_peer(target)?;
        Ok((peer.node_id, peer.display_name()))
    }

    fn invite_grant_for_proof(&self, proof: Option<&InviteProof>) -> Result<Option<InviteGrant>> {
        let Some(proof) = proof else {
            return Ok(None);
        };
        validate_invite_secret(&proof.invite_secret)?;
        let secret_hash = hash_invite_secret(&proof.invite_secret);
        self.invites
            .iter()
            .find(|invite| invite.invite_id == proof.invite_id && invite.secret_hash == secret_hash)
            .map(|invite| {
                normalize_allowed_ports(&invite.allowed_ports).map(|allowed_ports| InviteGrant {
                    admin_label: invite.admin_label.clone(),
                    invite_id: invite.invite_id.clone(),
                    allowed_ports,
                    role: invite.role,
                })
            })
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
        role: MembershipRole,
    ) -> Result<Self> {
        Self::issue_for_network(&cfg.network_id, issuer_key, subject, allowed_ports, role)
    }

    pub fn issue_for_network(
        network_id: &str,
        issuer_key: &SecretKey,
        subject: &Peer,
        allowed_ports: &[u16],
        role: MembershipRole,
    ) -> Result<Self> {
        if !is_valid_connection_id(&subject.connection_id) {
            bail!("cannot issue membership for invalid connection id");
        }
        let allowed_ports = normalize_allowed_ports(allowed_ports)?;
        let mut membership = Self {
            version: MEMBERSHIP_CERTIFICATE_VERSION,
            admin_label: normalize_connection_name(&subject.name)?,
            invite_id: None,
            joined_at_unix: current_unix_time()?,
            network_id: network_id.to_string(),
            subject_node_id: subject.node_id,
            subject_connection_id: subject.connection_id.clone(),
            role,
            allowed_ports,
            issuer_node_id: issuer_key.public(),
            signature: String::new(),
        };
        let signature = issuer_key.sign(&membership.signature_payload()?);
        membership.signature = encode_signature(&signature);
        Ok(membership)
    }

    fn encode_compact(&self) -> Result<String> {
        self.signature_payload()?;
        decode_signature(&self.signature)?;
        if !is_valid_connection_id(&self.subject_connection_id) {
            bail!("membership certificate has invalid connection id");
        }
        cbor::encode_compact(self).context("failed to encode membership certificate")
    }

    fn decode_compact(code: &str) -> Result<Self> {
        let mut value: Self =
            cbor::decode_compact(code).context("invalid membership certificate")?;
        value.signature_payload()?;
        decode_signature(&value.signature)?;
        if !is_valid_connection_id(&value.subject_connection_id) {
            bail!("membership certificate has invalid connection id");
        }
        value.allowed_ports = value.allowed_ports()?;
        Ok(value)
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
        validate_network_id(&self.network_id)?;
        if normalize_connection_name(&self.admin_label)? != self.admin_label {
            bail!("membership admin label is not normalized");
        }
        if self
            .invite_id
            .as_ref()
            .is_some_and(|id| !is_valid_connection_id(id))
        {
            bail!("membership invite id must be six base62 characters");
        }
        let fields = [
            self.version.to_string(),
            self.network_id.clone(),
            self.subject_node_id.to_string(),
            self.subject_connection_id.clone(),
            self.role.to_string(),
            format_ports(&self.allowed_ports()?),
            self.issuer_node_id.to_string(),
            self.admin_label.clone(),
            self.invite_id.clone().unwrap_or_default(),
            self.joined_at_unix.to_string(),
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

impl NetworkPolicyCertificate {
    fn issue(cfg: &Config, issuer_key: &SecretKey, max_peers: usize) -> Result<Self> {
        let mut policy = Self::issue_for_network(&cfg.network_id, issuer_key, max_peers)?;
        policy.admin_label = cfg.network_policy.admin_label.clone();
        policy.issued_at_unix = policy.issued_at_unix.max(
            cfg.network_policy
                .issued_at_unix
                .checked_add(1)
                .ok_or_else(|| anyhow!("network policy timestamp overflow"))?,
        );
        policy.signature = encode_signature(&issuer_key.sign(&policy.signature_payload()?));
        Ok(policy)
    }

    pub fn issue_for_network(
        network_id: &str,
        issuer_key: &SecretKey,
        max_peers: usize,
    ) -> Result<Self> {
        validate_max_known_peers(max_peers)?;
        let mut policy = Self {
            admin_label: None,
            version: NETWORK_POLICY_VERSION,
            network_id: network_id.to_string(),
            max_peers,
            issuer_node_id: issuer_key.public(),
            issued_at_unix: current_unix_time()?,
            signature: String::new(),
        };
        let signature = issuer_key.sign(&policy.signature_payload()?);
        policy.signature = encode_signature(&signature);
        Ok(policy)
    }

    fn encode_compact(&self) -> Result<String> {
        self.signature_payload()?;
        decode_signature(&self.signature)?;
        cbor::encode_compact(self).context("failed to encode network policy")
    }

    fn decode_compact(code: &str) -> Result<Self> {
        let value: Self = cbor::decode_compact(code).context("invalid network policy")?;
        value.signature_payload()?;
        decode_signature(&value.signature)?;
        Ok(value)
    }

    fn verify_signature(&self) -> Result<()> {
        let signature = decode_signature(&self.signature)?;
        let payload = self.signature_payload()?;
        self.issuer_node_id
            .verify(&payload, &signature)
            .context("network policy signature is invalid")
    }

    fn signature_payload(&self) -> Result<Vec<u8>> {
        if self.version != NETWORK_POLICY_VERSION {
            bail!("unsupported network policy version {}", self.version);
        }
        validate_network_id(&self.network_id)?;
        validate_max_known_peers(self.max_peers)?;
        let fields = [
            self.version.to_string(),
            self.network_id.clone(),
            self.max_peers.to_string(),
            self.issuer_node_id.to_string(),
            self.issued_at_unix.to_string(),
        ];
        let mut payload = Vec::new();
        append_signed_field(&mut payload, NETWORK_POLICY_SIGNATURE_CONTEXT);
        for field in &fields {
            append_signed_field(&mut payload, field);
        }
        if let Some(label) = &self.admin_label {
            if normalize_network_label(label)? != *label {
                bail!("network label must be normalized");
            }
            append_signed_field(&mut payload, label);
        }
        Ok(payload)
    }
}

impl RevocationCertificate {
    fn issue(cfg: &Config, issuer_key: &SecretKey, subject_node_id: EndpointId) -> Result<Self> {
        let mut revocation = Self {
            version: REVOCATION_CERTIFICATE_VERSION,
            network_id: cfg.network_id.clone(),
            subject_node_id,
            issuer_node_id: issuer_key.public(),
            issued_at_unix: current_unix_time()?,
            signature: String::new(),
        };
        let signature = issuer_key.sign(&revocation.signature_payload()?);
        revocation.signature = encode_signature(&signature);
        Ok(revocation)
    }

    fn encode_compact(&self) -> Result<String> {
        self.signature_payload()?;
        decode_signature(&self.signature)?;
        cbor::encode_compact(self).context("failed to encode revocation")
    }

    fn decode_compact(code: &str) -> Result<Self> {
        let value: Self = cbor::decode_compact(code).context("invalid revocation")?;
        value.signature_payload()?;
        decode_signature(&value.signature)?;
        Ok(value)
    }

    fn verify_signature(&self) -> Result<()> {
        let signature = decode_signature(&self.signature)?;
        let payload = self.signature_payload()?;
        self.issuer_node_id
            .verify(&payload, &signature)
            .context("revocation certificate signature is invalid")
    }

    fn signature_payload(&self) -> Result<Vec<u8>> {
        if self.version != REVOCATION_CERTIFICATE_VERSION {
            bail!("unsupported revocation version {}", self.version);
        }
        validate_network_id(&self.network_id)?;
        let fields = [
            self.version.to_string(),
            self.network_id.clone(),
            self.subject_node_id.to_string(),
            self.issuer_node_id.to_string(),
            self.issued_at_unix.to_string(),
        ];
        let mut payload = Vec::new();
        append_signed_field(&mut payload, REVOCATION_SIGNATURE_CONTEXT);
        for field in &fields {
            append_signed_field(&mut payload, field);
        }
        Ok(payload)
    }
}

fn hello_from_config(cfg: &Config) -> Result<Hello> {
    let can_advertise_directory = cfg.can_advertise_directory();
    Ok(Hello {
        network_id: cfg.network_id.clone(),
        network_policy: Some(cfg.network_policy.clone()),
        name: cfg.name.clone(),
        connection_id: cfg.connection_id.clone(),
        invite_proof: None,
        membership: cfg.membership.clone(),
        memberships: if can_advertise_directory {
            cfg.shared_memberships()
        } else {
            cfg.local_membership_chain()?
        },
        peers: if can_advertise_directory {
            cfg.peers.clone()
        } else {
            Vec::new()
        },
        revocations: cfg.revocations.clone(),
    })
}

fn join_hello_from_config(cfg: &Config) -> Result<Hello> {
    if cfg.membership.is_some() {
        return hello_from_config(cfg);
    }
    let invite_proof = cfg
        .invite_proof
        .clone()
        .ok_or_else(|| anyhow!("joined config missing invite proof"))?;
    Ok(Hello {
        network_id: cfg.network_id.clone(),
        network_policy: None,
        name: cfg.name.clone(),
        connection_id: cfg.connection_id.clone(),
        invite_proof: Some(invite_proof),
        membership: None,
        memberships: cfg.memberships.clone(),
        peers: Vec::new(),
        revocations: cfg.revocations.clone(),
    })
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
    let Some(grant) = cfg.invite_grant_for_proof(invite_proof)? else {
        return Ok(None);
    };
    let local_peer = cfg.local_peer()?;
    let local_membership = cfg
        .membership
        .as_ref()
        .ok_or_else(|| anyhow!("local host has no membership certificate"))?;
    local_membership.matches_peer(cfg, &local_peer)?;
    verify_membership_chain(cfg, local_membership, &[])?;
    cfg.ensure_can_issue_invite(&grant.allowed_ports)?;
    if !cfg.consume_invite_proof(invite_proof) {
        return Ok(None);
    }
    let secret_key = cfg.secret_key()?;
    let mut membership =
        MembershipCertificate::issue(cfg, &secret_key, peer, &grant.allowed_ports, grant.role)?;
    membership.admin_label = normalize_connection_name(&grant.admin_label)?;
    membership.invite_id = Some(grant.invite_id);
    membership.signature = encode_signature(&secret_key.sign(&membership.signature_payload()?));
    Ok(Some(membership))
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

fn peer_can_advertise_directory(
    cfg: &Config,
    peer: &Peer,
    direct_membership: Option<&MembershipCertificate>,
    extra_memberships: &[MembershipCertificate],
) -> Result<bool> {
    Ok(
        verified_membership_for_peer(cfg, peer, direct_membership, extra_memberships)?
            .is_some_and(|membership| membership.role.can_issue_invites()),
    )
}

fn insert_verified_membership_chain(
    cfg: &mut Config,
    membership: &MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<bool> {
    verify_membership_chain(cfg, membership, extra_memberships)?;
    let mut changed = false;
    let mut current = membership.clone();
    loop {
        changed |= insert_membership(cfg, current.clone())?;
        if current.subject_node_id == current.issuer_node_id {
            return Ok(changed);
        }
        current = find_membership_by_subject(cfg, extra_memberships, current.issuer_node_id)
            .cloned()
            .ok_or_else(|| anyhow!("missing membership issuer {}", current.issuer_node_id))?;
    }
}

fn remember_bootstrap_membership_chain(
    cfg: &mut Config,
    membership: &MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<bool> {
    verify_membership_chain(cfg, membership, extra_memberships)?;
    let mut changed = false;
    let mut current = membership.clone();
    loop {
        changed |= insert_bootstrap_membership(cfg, current.clone())?;
        if current.subject_node_id == current.issuer_node_id {
            return Ok(changed);
        }
        current = find_membership_by_subject(cfg, extra_memberships, current.issuer_node_id)
            .cloned()
            .ok_or_else(|| anyhow!("missing membership issuer {}", current.issuer_node_id))?;
    }
}

fn verify_membership_chain(
    cfg: &Config,
    membership: &MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<()> {
    let mut seen = Vec::new();
    verify_membership_chain_inner(cfg, membership, extra_memberships, &mut seen, true)
}

fn verify_membership_chain_without_revocations(
    cfg: &Config,
    membership: &MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<()> {
    let mut seen = Vec::new();
    verify_membership_chain_inner(cfg, membership, extra_memberships, &mut seen, false)
}

fn verify_membership_chain_inner(
    cfg: &Config,
    membership: &MembershipCertificate,
    extra_memberships: &[MembershipCertificate],
    seen: &mut Vec<EndpointId>,
    check_revocations: bool,
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
    if check_revocations && is_node_revoked(cfg, membership.subject_node_id) {
        bail!(
            "membership subject {} has been revoked",
            membership.subject_node_id
        );
    }
    seen.push(membership.subject_node_id);

    if membership.subject_node_id == membership.issuer_node_id {
        if membership.subject_node_id != cfg.creator_node_id {
            bail!("membership root is not the esp network creator");
        }
        if membership.role != MembershipRole::Admin {
            bail!("membership root must be admin");
        }
        return Ok(());
    }

    let issuer_membership =
        find_membership_by_subject(cfg, extra_memberships, membership.issuer_node_id)
            .ok_or_else(|| anyhow!("missing membership issuer {}", membership.issuer_node_id))?;
    if !issuer_membership.role.can_issue_invites() {
        bail!(
            "membership issuer {} has role {} and cannot issue memberships",
            membership.issuer_node_id,
            issuer_membership.role
        );
    }
    if membership.issuer_node_id != cfg.creator_node_id {
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
    verify_membership_chain_inner(
        cfg,
        issuer_membership,
        extra_memberships,
        seen,
        check_revocations,
    )
}

fn verify_revocation(
    cfg: &Config,
    revocation: &RevocationCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<()> {
    if revocation.network_id != cfg.network_id {
        bail!("revocation certificate is for a different esp network");
    }
    revocation.verify_signature()?;
    let issuer_membership =
        find_membership_by_subject(cfg, extra_memberships, revocation.issuer_node_id)
            .ok_or_else(|| anyhow!("missing revocation issuer {}", revocation.issuer_node_id))?;
    verify_membership_chain_without_revocations(cfg, issuer_membership, extra_memberships)?;
    if !issuer_membership.role.can_issue_invites() {
        bail!(
            "revocation issuer {} has role {} and cannot revoke peers",
            revocation.issuer_node_id,
            issuer_membership.role
        );
    }
    Ok(())
}

fn verify_network_policy(
    cfg: &Config,
    policy: &NetworkPolicyCertificate,
    extra_memberships: &[MembershipCertificate],
) -> Result<()> {
    if policy.network_id != cfg.network_id {
        bail!("network policy is for a different esp network");
    }
    policy.verify_signature()?;
    let issuer_membership =
        find_membership_by_subject(cfg, extra_memberships, policy.issuer_node_id)
            .ok_or_else(|| anyhow!("missing network policy issuer {}", policy.issuer_node_id))?;
    verify_membership_chain(cfg, issuer_membership, extra_memberships)?;
    if !issuer_membership.role.can_issue_invites() {
        bail!(
            "network policy issuer {} has role {} and cannot update policy",
            policy.issuer_node_id,
            issuer_membership.role
        );
    }
    Ok(())
}

fn is_node_revoked(cfg: &Config, node_id: EndpointId) -> bool {
    cfg.revocations.iter().any(|revocation| {
        revocation.subject_node_id == node_id && verify_revocation(cfg, revocation, &[]).is_ok()
    })
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
    if cfg
        .memberships
        .iter()
        .all(|known| known.subject_node_id != membership.subject_node_id)
    {
        let max_memberships = max_stored_memberships(cfg)?;
        if cfg.memberships.len() >= max_memberships {
            bail!(
                "known membership limit reached ({}); update network policy max_peers to store more",
                max_memberships
            );
        }
    }
    upsert_membership(cfg, membership)
}

fn insert_bootstrap_membership(
    cfg: &mut Config,
    membership: MembershipCertificate,
) -> Result<bool> {
    if membership.subject_node_id == cfg.secret_key()?.public() {
        return Ok(false);
    }
    upsert_membership(cfg, membership)
}

fn upsert_membership(cfg: &mut Config, membership: MembershipCertificate) -> Result<bool> {
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

fn validate_max_known_peers(max_peers: usize) -> Result<()> {
    if max_peers == 0 {
        bail!("max_peers must be at least 1");
    }
    if max_peers > ABSOLUTE_MAX_KNOWN_PEERS {
        bail!(
            "max_peers {} exceeds the hard maximum {}",
            max_peers,
            ABSOLUTE_MAX_KNOWN_PEERS
        );
    }
    Ok(())
}

fn max_stored_memberships(cfg: &Config) -> Result<usize> {
    Ok(cfg.max_known_peers()?.saturating_add(1))
}

fn enforce_state_caps(cfg: &mut Config) -> Result<()> {
    let max_peers = cfg.max_known_peers()?;
    validate_max_known_peers(max_peers)?;
    if cfg.peers.len() > max_peers {
        cfg.peers.truncate(max_peers);
    }

    let max_memberships = max_stored_memberships(cfg)?;
    if cfg.memberships.len() > max_memberships {
        cfg.memberships.truncate(max_memberships);
    }
    Ok(())
}

fn validate_state_caps(cfg: &Config) -> Result<()> {
    let max_peers = cfg.max_known_peers()?;
    validate_max_known_peers(max_peers)?;
    if cfg.peers.len() > max_peers {
        bail!(
            "config stores {} peers but network policy allows {}",
            cfg.peers.len(),
            max_peers
        );
    }
    let max_memberships = max_stored_memberships(cfg)?;
    if cfg.memberships.len() > max_memberships {
        bail!(
            "config stores {} memberships but network policy allows {}",
            cfg.memberships.len(),
            max_memberships
        );
    }
    Ok(())
}

fn network_policy_is_newer(
    candidate: &NetworkPolicyCertificate,
    current: &NetworkPolicyCertificate,
) -> bool {
    candidate
        .issued_at_unix
        .cmp(&current.issued_at_unix)
        .then_with(|| candidate.issuer_node_id.cmp(&current.issuer_node_id))
        .then_with(|| candidate.signature.cmp(&current.signature))
        .is_gt()
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
        .context("signature is not valid base64")?;
    let bytes: [u8; Signature::LENGTH] = bytes
        .try_into()
        .map_err(|_| anyhow!("signature must decode to 64 bytes"))?;
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
    if !name.chars().all(|ch| ch.is_ascii_graphic() || ch == ' ') {
        bail!("connection name must contain only printable ASCII characters");
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

fn current_unix_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")
        .map(|duration| duration.as_secs())
}

pub fn is_valid_connection_id(id: &str) -> bool {
    id.len() == 6 && id.chars().all(|ch| ch.is_ascii_alphanumeric())
}

fn validate_network_id(id: &str) -> Result<()> {
    Uuid::parse_str(id).context("network id must be a UUID")?;
    Ok(())
}

fn generate_invite_secret() -> String {
    URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
}

fn validate_invite_secret(secret: &str) -> Result<()> {
    let bytes = URL_SAFE_NO_PAD
        .decode(secret)
        .context("invite secret is not valid base64")?;
    if bytes.len() != 16 {
        bail!("invite secret must decode to 16 bytes");
    }
    Ok(())
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
    fn validate(&self) -> Result<()> {
        if self.version != INVITE_VERSION {
            bail!("unsupported invite version {}", self.version);
        }
        if !is_valid_connection_id(&self.invite_id) {
            bail!("invite id must be six base62 characters");
        }
        validate_network_id(&self.network_id)?;
        validate_invite_secret(&self.invite_secret)?;
        Ok(())
    }

    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        cbor::encode_compact(self).context("failed to encode invite code")
    }

    pub fn decode(code: &str) -> Result<Self> {
        let invite: Self = cbor::decode_compact(code).context("invalid invite code")?;
        invite.validate()?;
        Ok(invite)
    }
}

#[cfg(not(test))]
fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start async runtime")?;
    let result = runtime.block_on(run());
    // Tokio stdin uses an uncancellable blocking read. After remote EOF, SSH may
    // still hold stdin open; do not let that read prevent the proxy from exiting.
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}
