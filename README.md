# esp

`esp` carries TCP traffic over iroh so you can SSH between machines without
opening inbound SSH ports or configuring a VPN. SSH still authenticates users
and encrypts the SSH session.

## Installation

With Rust and `just` installed:

```sh
just install
# Or:
cargo install --locked --path . --force
```

The executable is normally installed in `~/.cargo/bin`. Check `esp --help`.

## Create and join networks

On the first machine:

```sh
esp init "Home network"
esp invite "Home network" "laptop"
esp daemon
```

Copy the `invite_code` field to the second machine:

```sh
esp join INVITE_CODE
esp daemon
```

Each invitation is fresh and single-use. It includes the shared network label;
joining verifies that label against the inviter's signed policy before accepting
membership. Labels are immutable, case-sensitive, trimmed printable ASCII,
1–64 characters long. Quoted spaces are allowed. A local label cannot refer to
two different active networks. Repeating `init` for an existing label returns its
identity and leaves its policy unchanged.

A machine can belong to several networks:

```sh
esp init "Work network"
esp invite "Work network" "work laptop" --role admin
esp status
```

Each network has independent identities, peer names, invitations, membership
roles, revocations, policy, ports, and connection history. One shared daemon
serves all configured networks. Creating, joining, and removing a network while
it runs updates that daemon without restarting the other endpoints. The daemon
can start with no networks. An invalid network appears as an error in status
while healthy networks keep running.

## SSH and forwarding

```sh
ssh -o 'ProxyCommand=esp proxy "Home network" %n %p' user@host
ssh -o 'ProxyCommand=esp proxy "Home network" %n %p' user@A1B2C3
```

Or in `~/.ssh/config`:

```sshconfig
Host home-server
    HostName server
    User user
    ProxyCommand esp proxy "Home network" %n %p
```

Peer lookup is confined to the chosen network. It accepts admin labels,
hostnames, six-character connection IDs, and full node IDs. Exact IDs take
precedence. Ambiguous names or labels fail and show IDs for disambiguation.

`esp proxy` starts one shared outgoing-only helper when needed. All local proxy
processes use `~/.esp/.esp.sock`, protected by the persistent
`~/.esp/.esp.lock`. Each network has its own iroh endpoint. The helper exits
30 seconds after the last local session ends.

Running `esp daemon` promotes an existing helper in place, enabling inbound
forwarding while preserving active sessions. The foreground command owns the
promoted process: termination or loss of its controlling connection stops the
shared daemon. A second foreground owner is rejected.

A remote proxy connects to `127.0.0.1:PORT` on the receiving host. The requested
port must be allowed by both the requester's signed membership and the
receiving network's local transport settings. Invitations grant port 22 and the
ordinary `peer` role by default. Admins can grant other ports or the admin role:

```sh
esp invite "Home network" "web host" --ports 22,80,8080
esp invite "Home network" "admin laptop" --role admin
esp daemon --ports 22,80,8080 --max-connections-per-peer 32
```

## Configuration

Global preferences live in `~/.esp/config.yml`:

```yaml
version: 3
format:
  type: json
  colorize: true
transport:
  ports: [22]
  max_connections_per_peer: 8
```

Network identities and signed state live in
`~/.esp/networks/<network_uuid>.yml`. Each network file may override transport
settings:

```yaml
transport:
  ports: []
  max_connections_per_peer: 4
```

An empty port list disables inbound forwarding on that network. Settings use
explicit daemon flags first, then network overrides, then global defaults.
They are read when starting or promoting the daemon and when adding a network.
Restart the daemon after manually editing transport settings. State saves
preserve those edits.

Keep network files private: they contain each network's secret identity.
Directories use mode `0700`, files use `0600`, and writes are atomic. esp rejects
symlinked state paths, linked secret files, and files with group/world access.
Do not copy network identities between machines.

Report commands default to highlighted JSON. `--format json|text` overrides the
global format; `--color` and `--no-color` independently override colorization.
Text output uses snake_case keys and groups networks into separate blocks.
Colored text uses bold white keys and light-blue values. Preferences change on
the next command and CLI overrides are not saved. Scalar legacy format settings
are rejected.

```sh
esp status --no-color
esp status "Home network" --peers --format text
esp invite "Home network" "laptop" --no-color | jq -r .invite_code
```

`status` lists networks in label order, including role, transport state, and peer
counts. `status NETWORK` shows detailed identity and configuration information.
`--peers` includes peer records in either form. Connected counts measure
established connections observed locally; offline presence is `null` in JSON and
`unknown` in text. Reachable but idle hosts are not counted as connected.

The daemon writes timestamped INFO logs under `~/.esp/logs/`. Use `RUST_LOG` to
change the log level.

## Administration

`esp admin [NETWORK]` opens **Networks → Peers → Peer details**. Every active
local network is shown; ordinary memberships are read-only. Tab and Shift-Tab
move focus, arrows or `j/k` navigate, Page Up/Down move by ten, and `J/K` scroll
details. Press `q` or Ctrl-C to quit. Use `ssh -t` for remote terminals.

The header and details show the selected network, host, peer identities, role,
ports, invite provenance, and local connection history. Connected/running values
are green, stopped transport is red, and unknown presence is gray. Keys are bold.
The interface handles network removal and daemon reconnects while it is open.

An online administrator can press `r` to revoke the selected peer. The prompt
names both the peer and network. Press `y` to confirm or `n`/Esc to cancel;
Enter defaults to cancellation. Revocation closes that peer's sessions and
broadcasts the signed change. Peer admin labels remain separate from hostnames;
`rename NETWORK NAME` changes this host's hostname within that network.

## Commands and destruction

```sh
esp init NETWORK --max-peers 100
esp join INVITE
esp invite NETWORK PEER --role peer --ports 22
esp proxy NETWORK PEER PORT
esp rename NETWORK NAME
esp revoke NETWORK PEER
esp policy NETWORK --max-peers 100
esp status [NETWORK] [--peers]
esp admin [NETWORK]
esp destroy NETWORK [--global] [--yes]
esp daemon # also the default command: esp
```

`destroy NETWORK` closes that network's local sessions and removes its local
file. Other members' records are unchanged. A fresh invitation can rejoin it.

`destroy NETWORK --global` requires a serving daemon and a valid admin
membership. It durably records a signed destruction certificate, disables
forwarding and membership changes, closes active sessions, and sends the
certificate to known members. Recipients verify the signature and admin chain
against the pinned creator and known revocations. Ordinary members can relay
valid certificates.

Both forms prompt for confirmation. Noninteractive use requires `--yes`.

Global destruction is permanent. A terminal record retains the control identity
and pending deliveries, survives restart, rejects rejoining that UUID, and is
hidden from active network lists. Notifications retry with exponential backoff
capped at five minutes. Offline members stop only after receiving the
certificate; the command reports that destruction is recorded with delivery
pending when applicable. Reusing the label with `init` creates a new UUID and
identity.

## Upgrade to version 3

This is a forward-only breaking release. There is no migration or compatibility
layer for previous configurations, invitations, certificates, or protocols.

1. Stop old daemons and automatic transports on every host.
2. Back up and manually move the old private configuration aside.
3. Install version 3 on all hosts and initialize new networks.
4. Issue fresh invitations and join the other hosts.
5. Update SSH ProxyCommand entries to include the network label, then restart
   daemons.

esp never automatically deletes or migrates old configuration. Integration tests
use temporary profiles and leave existing user networks untouched.

## Linux systemd

Example `~/.config/systemd/user/esp.service`:

```ini
[Unit]
Description=esp SSH transport proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.cargo/bin/esp daemon
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now esp.service
systemctl --user status esp.service
```

To keep user services running after logout:

```sh
sudo loginctl enable-linger "$USER"
```

## Protocol and limits

Membership, policy, revocation, invitation, and configuration versions are 3.
Network protocols use `esp/control/cbor/3`, `esp/tcp/cbor/3`, and
`esp/destruction/cbor/3`. UUIDs and verified certificates are the authentication
boundary; labels are used for local selection.

Remote messages use CBOR with two-byte big-endian lengths, capped at 65,535
bytes. Version 3 local manager messages use four-byte lengths with an 8 MiB cap
for multi-network reports. Every network-specific local request carries its
UUID. Proxy setup requires a Ready/Error acknowledgement before raw TCP bytes.
Admin peer pages contain at most 50 rows.

Signed network policy bounds stored peers and certificates; shared directory
and revocation messages are also bounded. Inbound work has a shared process
budget and per-network peer quotas. Connections have handshake/setup deadlines
and a one-hour idle timeout in each direction. TCP half-closes let pending
responses finish after input EOF.

Invites are bearer bootstrap secrets. Successful joining pins the creator,
consumes the invitation, and obtains signed membership. Established peers use
membership certificates instead of invite secrets. Only administrators may
advertise the peer directory; ordinary members share their own membership chain
and signed policy/revocations. iroh tries direct paths and can use relays when
needed.
