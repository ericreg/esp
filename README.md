# esp

`esp` is a tiny iroh-backed TCP proxy aimed at one thing first: SSH between
machines without manually exposing port 22.

It is an SSH transport helper, not a general VPN manager.

## Installation

From this checkout:

```sh
cargo install --path . --force
```

This installs `esp` into Cargo's bin directory, usually `~/.cargo/bin`. Make
sure that directory is on your `PATH`:

```sh
esp --help
```

You can also install from git:

```sh
cargo install --git https://github.com/ericreg/esp.git --force
```

## Flow

On the first machine:

```sh
esp init
```

This creates `~/.esp/config.yml`, detects this host's name, and generates a unique
connection id. Create an invite explicitly:

```sh
esp invite
```

Keep the daemon running on that machine:

```sh
esp
```

By default, the daemon only allows peers to proxy to local SSH on port `22`.
Allow additional localhost ports explicitly on that host:

```sh
esp daemon --ports 22,8000
```

Each daemon process opens one timestamped log file at startup and writes
INFO-level logs there by default, for example
`~/.esp/logs/esp-1767225600-000000000.log`. Set `RUST_LOG` to override the log
level.

Invites grant the `peer` role and SSH-only port access by default. To grant a
peer additional ports, include them in the invite:

```sh
esp invite --ports 22,80,8080
```

Only admins can create invites. To let a new host invite others, grant the
`admin` role explicitly:

```sh
esp invite --role admin
```

The effective policy is the intersection of the peer's signed invite grant and
the daemon's local `--ports` allowlist.

On the second machine:

```sh
esp join <invite-code>
esp
```

To add a third machine, print a new invite on any already-joined admin:

```sh
esp invite
```

Join with that new code on the third machine. Each host shares its detected name
and its unique case-sensitive, six-character base62 connection id when it joins
and when it initiates a proxy connection. Duplicate names are allowed but must
be disambiguated by id.

Once daemons are connected, SSH through esp to any learned peer:

```sh
ssh -o ProxyCommand='esp proxy %n %p' user@host
ssh -o ProxyCommand='esp proxy %n %p' user@A1B2C3
```

Or add an SSH config entry:

```sshconfig
Host host
    HostName host
    User user
    ProxyCommand esp proxy %n %p
```

Then connect normally:

```sh
ssh host
```

If multiple peers are named `host`, esp exits and prints the matching connection
ids. Rename one of them with `esp rename NAME` or use the id directly.

The remote daemon connects to `127.0.0.1:%p` on its own machine, so Linux
firewall rules do not need to allow inbound SSH from esp peers.

## Commands

```sh
esp init --max-peers 100 # create ~/.esp/config.yml if missing
esp join CODE         # join from an invite code
esp proxy TARGET PORT # proxy stdio to localhost:PORT on peer name or id
esp rename NAME       # rename this host
esp revoke TARGET     # revoke a peer by name, connection id, or node id as an admin
esp policy --max-peers 100 # update the signed network peer cap as an admin
esp invite --role peer --ports 22 # create and print an invite as an admin
esp status            # show daemon state, local node, and peer details
esp daemon --ports 22 # run the daemon; this is also the default `esp`
```

## Linux systemd

Example user service at `~/.config/systemd/user/esp.service`:

```ini
[Unit]
Description=esp SSH transport proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.cargo/bin/esp daemon --ports 22
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
```

Enable and start it:

```sh
systemctl --user daemon-reload
systemctl --user enable --now esp.service
systemctl --user status esp.service
```

To keep user services running after logout:

```sh
sudo loginctl enable-linger "$USER"
```

## Leaving

There is no leave command. Stop the daemon and delete `~/.esp/config.yml`.

## Security

`esp` is a reachability layer in front of SSH. SSH still authenticates users and
encrypts SSH sessions, but esp decides which peers can ask the daemon to open a
local TCP connection.

- The daemon allows proxying to local port 22 only by default. Additional ports
  must be explicitly allowed with `esp daemon --ports`.
- Invite codes are short bearer bootstrap secrets containing the network id,
  inviter node id, invite id, and invite secret. A successful join connects to
  the inviter, consumes the invite there, fetches signed network policy and
  membership chain data, and returns a signed membership certificate for the new
  node. Membership certificates include the peer's role and allowed port list in
  the signed payload.
- The creator is an admin by default. Only admins can create invites, and admins
  can grant either `peer` or `admin` with `esp invite --role`.
- Network creation signs a peer storage policy. `esp init --max-peers` sets the
  initial known-peer cap, and admins can update it with `esp policy --max-peers`.
- Invites grant port access per peer with `esp invite --ports`. Proxy traffic is
  accepted only when both the peer's signed membership and the daemon's local
  `--ports` allow the requested port.
- After join, peers authenticate esp membership with certificates signed by an
  existing member and chained back to the network creator. Normal proxy requests
  do not carry invite secrets.
- Admins can revoke peers with `esp revoke TARGET`. Revocations are signed,
  persisted, shared during control/proxy sync, and cause the daemon to close
  active connections from the revoked node.
- `esp status` asks the daemon first and shows whether it is running. If the
  daemon is unavailable, it falls back to the local config so peers can still
  inspect their node identity. When the daemon is running, local `esp invite`,
  `esp rename`, `esp revoke`, `esp policy`, and existing-config `esp init`
  commands use the daemon's private local control socket instead of writing
  `~/.esp/config.yml` directly.
- Admins act as the peer directory. Generic hellos from peers carry only their
  self identity, membership chain, signed network policy, and revocations; only
  admins may advertise additional peers and membership certificates.
- Shared peer, certificate, and revocation lists are capped per message, and
  total stored peers/certificates are capped by signed network policy. Duplicate
  connection ids are rejected.
- The daemon bounds inbound work with small `try_send`-based worker queues,
  per-peer concurrent connection quotas, handshake/setup read timeouts, and a
  one-hour idle timeout on TCP proxy byte streams.
- `~/.esp/config.yml` contains this host's private iroh key and, while a join is
  pending, may contain an unused invite proof. esp writes this file atomically
  with `0600` permissions and refuses to use configs with group/world access,
  symlinks, or hard links. Pending invite proofs are sent only during the
  explicit join sync to the inviter. Keep the file private and do not share it
  between machines.
- Duplicate peer names are allowed, so use the six-character connection id when
  a name is ambiguous.

## Notes

- SSH bytes are carried over iroh QUIC streams. esp lets iroh try direct
  connections first and use relays when a direct path is unavailable.
- The daemon allows proxying to local port 22 only unless additional ports are
  passed with `esp daemon --ports`.
- The inviter accepts invited peers by checking the random network id and issued
  invite proof, then signs a membership certificate bound to the joining node
  id, connection id, role, and allowed ports. Only admins can issue invites.
- Hosts exchange signed policy, minimal membership identity, and signed
  revocations during join, control sync, and proxy connection setup. Admins can
  additionally publish the peer directory.
- Shared peer, certificate, and revocation lists are capped at 100 entries per
  message. Total stored peers are capped by signed network policy.
