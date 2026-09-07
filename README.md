# esp

`esp` is a tiny iroh-backed TCP proxy aimed at one thing first: SSH between
machines without manually exposing port 22.

It is an SSH transport helper, not a general VPN manager.

## Installation

With Rust and `just` installed, run from this checkout:

```sh
just install
```

Or run Cargo directly:

```sh
cargo install --locked --path . --force
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
esp init "Home network"
```

This creates `~/.esp/config.yml` with the required network label, detects this
host's name, and generates a unique connection id. Network labels are trimmed,
nonblank printable ASCII strings of at most 64 bytes. They are signed into the
network policy and shared with joined hosts. Admins can run `esp init "label"`
to label an existing unlabeled network; repeating the same label is safe. Init
does not rename an already labeled network. Update esp on all hosts before
assigning a network label, since older versions cannot verify labeled policies.
Create an invite explicitly:

```sh
esp invite "laptop"
```

Copy the `invite_code` value from the JSON report for `esp join`. Each run
creates a fresh, single-use invite, including on the network creator.
Codes from the same host share a long prefix and suffix because they encode the
same network and host identities; the random invite id and secret change in the
middle of the code.

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
esp invite "web host" --ports 22,80,8080
```

Only admins can create invites. To let a new host invite others, grant the
`admin` role explicitly:

```sh
esp invite "admin laptop" --role admin
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
esp invite "laptop"
```

Join with that new code on the third machine. Each host shares its detected name
and its unique case-sensitive, six-character base62 connection id when it joins
and when it initiates a proxy connection. Duplicate names are allowed but must
be disambiguated by id.

Keep `esp daemon` running on machines that should accept incoming connections.
From a client, SSH through esp to any learned peer:

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

`esp proxy` automatically starts a shared background transport when needed and
connects to it through `~/.esp/.esp.sock`, with its transport lock stored at
`~/.esp/.esp.lock`. Other proxy processes reuse that transport;
each SSH session gets its own connection through the same iroh endpoint. Closing
the first session leaves the others connected. Once all local sessions have
ended, the background transport exits after 30 seconds of inactivity. The next
SSH session starts it again automatically.

If a local daemon is already running, proxies use its endpoint. The automatic
client transport handles outgoing sessions and control updates; incoming TCP
forwarding requires `esp daemon` on the receiving host. To start a daemon while
the client transport is running, close local proxy sessions and let it exit.

By default, a daemon accepts up to eight concurrent incoming connections from
each peer, including control syncs. To allow more, set the limit on the receiving
host:

```sh
esp daemon --max-connections-per-peer 32
```

The limit must be positive; the daemon also retains its overall worker limits.
After upgrading esp, restart the local daemon to enable the new proxy request.

If multiple peers are named `host`, esp exits and prints the matching connection
ids. Rename one of them with `esp rename NAME` or use the id directly.

The remote daemon connects to `127.0.0.1:%p` on its own machine, so Linux
firewall rules do not need to allow inbound SSH from esp peers.

## Interactive administration

Run `esp admin` in a terminal on an admin host, or `ssh -t amd esp admin`.
The header identifies the current network and local host. The left pane lists
joined peers by admin label, hostname, and connection ID. The right pane shows
the selected peer's identities, role, ports, original six-character invite ID,
inviter, join time, and local connection history.

A green **Connected** peer has at least one established, authorized connection
to this host's esp transport. Idle reachable hosts are not marked connected;
there are no background reachability probes. Last-connected timestamps are
saved locally and survive transport restarts. They are not network-wide history.

Use arrows or `j`/`k` to select, Page Up/Down to move ten peers, `J`/`K` to scroll
details, `r` to revoke, and `q` or Ctrl-C to quit. Revocation opens a confirmation
with **Cancel** selected. Use Tab or left/right and Enter to confirm, or Escape
to cancel. Revocation closes active sessions and broadcasts the signed change;
the peer needs a new invite to rejoin. Revoked peers and pending invitations are
not included in the list.

Without a local daemon or helper, the TUI shows saved data with **Unknown**
connection status and disables revocation. It reconnects automatically when the
transport starts. A disconnected or unresponsive transport marks the view stale.
The minimum terminal size is 80 columns by 20 rows.

Pressing `r` opens `remove peer <admin_label> from network? y/n`. Press `y` to
remove that peer or `n`/Esc to cancel; Enter defaults to cancellation.

Every new invite requires an admin label: `esp invite "Eric laptop"`. Labels are
trimmed, nonblank printable ASCII strings of at most 64 bytes. The label stays
separate from the joining machine's hostname and is signed into its membership,
along with the consumed invite ID and join time. Other admins receive these
fields through membership exchange. `esp rename` still changes the hostname;
labels cannot be edited in this version and are not proxy lookup aliases.
Duplicate labels are allowed; use connection IDs to distinguish peers. The
network creator's label initially matches its hostname and has no invite ID.

## Commands

```sh
esp init "Home network" --max-peers 100 # create ~/.esp/config.yml if missing
esp join CODE         # join from an invite code
esp proxy TARGET PORT # proxy stdio to localhost:PORT on peer name or id
esp rename NAME       # rename this host
esp revoke TARGET     # revoke a peer by name, connection id, or node id as an admin
esp policy --max-peers 100 # update the signed network peer cap as an admin
esp invite "laptop" --role peer --ports 22 # create and print an invite as an admin
esp status            # show transport, local node, and connected peer count as highlighted JSON
esp status --format json --no-color # plain JSON for scripts
esp status --format text # snake_case text output; color follows the config
esp status --peers     # include the full peer list (also works with --format text)
esp admin             # interactive two-pane administration (admin members only)
esp daemon --ports 22 # run the daemon; this is also the default `esp`
esp daemon --max-connections-per-peer 32 # allow more concurrent connections per peer
```

The report commands (`init`, `join`, `rename`, `invite`, `revoke`, `policy`, and
`status`) use the top-level `format` settings in `~/.esp/config.yml`:

```yaml
format:
  type: json
  colorize: true
```

`type` accepts `json` or `text` and defaults to `json`. `colorize` accepts `true`
or `false` and defaults to `true`. Colored JSON uses syntax highlighting; colored
text uses bold white keys and light blue values. In text output, the init hint
appears after the fields, separated by a blank line, without a `next_step` key.
JSON retains `next_step`.

`--format json|text` overrides only the type, while `--color` and `--no-color`
override colorization. CLI overrides do not modify the saved preferences. Changes
take effect on the next command, including with a running transport. For example:

```sh
esp join CODE --format text
esp status --format text --color
esp invite "laptop" --format json --no-color | jq -r .invite_code
```

The previous scalar settings (`json`, `json_colorized`, and `text`) remain readable
and are converted to the nested form when the config is next saved, preserving
their existing output behavior.

`invite` now returns an `invite_code` field rather than a bare code. The interactive
admin screen, proxy byte stream, daemon logs, and command help retain their own
formats.

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

There is no leave command. Stop any daemon, close local SSH sessions, wait for
the automatic transport to exit, and delete `~/.esp/config.yml`.

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
  can grant either `peer` or `admin` with `esp invite "name" --role`.
- Network creation signs a peer storage policy. `esp init --max-peers` sets the
  initial known-peer cap, and admins can update it with `esp policy --max-peers`.
- Invites grant port access per peer with `esp invite "name" --ports`. Proxy traffic is
  accepted only when both the peer's signed membership and the daemon's local
  `--ports` allow the requested port.
- After join, peers authenticate esp membership with certificates signed by an
  existing member and chained back to the network creator. Normal proxy requests
  do not carry invite secrets.
- Admins can revoke peers with `esp revoke TARGET`. Revocations are signed,
  persisted, shared during control/proxy sync, and cause the daemon to close
  active connections from the revoked node.
- `esp status` asks the local transport (a daemon or automatic client helper)
  first and shows whether it is running. If it is unavailable, it falls back to
  the local config so peers can still inspect their node identity. The
  `connected_peers` count measures distinct peers with established connections
  observed by this host (zero without a running transport). Use `--peers` to
  include the full known peer list. Older transports that do not report presence
  show `null` in JSON or `unknown` in text until restarted. While a
  transport is running, local `esp invite`,
  `esp rename`, `esp revoke`, `esp policy`, and existing-config `esp init`
  commands use its private local control socket instead of writing
  `~/.esp/config.yml` directly.
- Admins act as the peer directory. Generic hellos from peers carry only their
  self identity, membership chain, signed network policy, and revocations; only
  admins may advertise additional peers and membership certificates.
- Shared peer, certificate, and revocation lists are capped per message, and
  total stored peers/certificates are capped by signed network policy. Duplicate
  connection ids are rejected.
- The daemon bounds inbound work with small `try_send`-based worker queues,
  configurable per-peer concurrent connection quotas, handshake/setup read
  timeouts, and a one-hour idle timeout in each direction on proxy byte streams.
  The local request setup timeout does not limit the lifetime of an established
  tunnel. TCP half-closes allow pending responses to finish after input EOF.
- `~/.esp/config.yml` contains this host's private iroh key and, while a join is
  pending, may contain an unused invite proof. esp writes this file atomically
  with `0600` permissions and refuses to use configs with group/world access,
  symlinks, or hard links. Pending invite proofs are sent only during the
  explicit join sync to the inviter. Keep the file private and do not share it
  between machines.
- Duplicate peer names are allowed, so use the six-character connection id when
  a name is ambiguous.

## Notes

- Control messages, TCP proxy setup requests, and local daemon requests use CBOR
  encoded with `minicbor`. Local request discriminants start at 16 for version 2,
  so older daemons reject new requests instead of ignoring named-invite fields.
  Each message has a two-byte big-endian payload length
  followed by one CBOR value, capped at 65,535 bytes. Proxy setup includes a
  remote Ready/Error acknowledgement before SSH data starts as a raw byte stream.
  Admin lists are fetched in pages of at most 50 peers.
- Invites and signed records use derived CBOR arrays. UUIDs, signatures, and
  invite secrets retain their string representations; endpoint keys use byte
  strings. Invite codes and the signed-record fields in
  `~/.esp/config.yml` contain URL-safe base64 of these CBOR values. Rust
  `#[n(...)]` annotations define the field and variant numbers.
- Named invites and administration use configuration, invite, and membership
  format version 2. Update all hosts, stop existing transports, and recreate
  the network and invites before rejoining peers and restarting transports.
  Back up the old private configuration before manually moving it aside.
  Existing state is never automatically deleted or migrated. Old configs and
  invites are rejected, and mixed-version transports are not supported.
  The network protocols are `esp/control/cbor/2` and `esp/tcp/cbor/2`.
- SSH bytes are carried over iroh QUIC streams. esp lets iroh try direct
  connections first and use relays when a direct path is unavailable.
- The daemon allows proxying to local port 22 only unless additional ports are
  passed with `esp daemon --ports`.
- The inviter accepts invited peers by checking the random network id and issued
  invite proof, then signs a membership certificate bound to the joining node
  id, connection id, role, allowed ports, admin label, invite ID, and join time.
  Only admins can issue invites.
- Hosts exchange signed policy, minimal membership identity, and signed
  revocations during join, control sync, and proxy connection setup. Admins can
  additionally publish the peer directory.
- Shared peer, certificate, and revocation lists are capped at 100 entries per
  message. Total stored peers are capped by signed network policy.
