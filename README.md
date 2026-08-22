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

This creates `~/.esp.yml`, detects this host's name, and generates a unique
connection id. Create an invite explicitly:

```sh
esp invite
```

Keep the daemon running on that machine:

```sh
RUST_LOG=info esp
```

By default, the daemon only allows peers to proxy to local SSH on port `22`.
Allow additional localhost ports explicitly on that host:

```sh
RUST_LOG=info esp daemon --ports 22,8000
```

Invites are SSH-only by default too. To grant a peer additional ports, include
them in the invite:

```sh
esp invite --ports 22,80,8080
```

The effective policy is the intersection of the peer's signed invite grant and
the daemon's local `--ports` allowlist.

On the second machine:

```sh
esp join <invite-code>
RUST_LOG=info esp
```

To add a third machine, print a new invite on any already-joined machine:

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
esp init              # create ~/.esp.yml if missing
esp join CODE         # join from an invite code
esp proxy TARGET PORT # proxy stdio to localhost:PORT on peer name or id
esp rename NAME       # rename this host
esp invite --ports 22 # create and print another invite from this network member
esp status            # show local node and peer details
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

There is no leave command. Stop the daemon and delete `~/.esp.yml`.

## Security

`esp` is a reachability layer in front of SSH. SSH still authenticates users and
encrypts SSH sessions, but esp decides which peers can ask the daemon to open a
local TCP connection.

- The daemon allows proxying to local port 22 only by default. Additional ports
  must be explicitly allowed with `esp daemon --ports`.
- Invite codes are bearer bootstrap secrets. A successful join consumes the
  invite on the inviter and returns a signed membership certificate for the new
  node. Membership certificates include the peer's allowed port list in the
  signed payload.
- Invites grant port access per peer with `esp invite --ports`. Proxy traffic is
  accepted only when both the peer's signed membership and the daemon's local
  `--ports` allow the requested port.
- After join, peers authenticate esp membership with certificates signed by an
  existing member and chained back to the network creator. Normal proxy requests
  do not carry invite secrets.
- When the daemon is running, local `esp invite`, `esp rename`, `esp status`,
  and existing-config `esp init` commands use the daemon's private local control
  socket instead of writing `~/.esp.yml` directly.
- Peers share known peers and membership certificates during join and proxy
  setup. Shared peer and certificate lists are capped at 100 entries, and
  duplicate connection ids are rejected.
- `~/.esp.yml` contains this host's private iroh key and, while a join is
  pending, may contain an unused invite proof. esp writes this file atomically
  with `0600` permissions and refuses to use configs with group/world access,
  symlinks, or hard links. Keep it private and do not share the file between
  machines.
- Duplicate peer names are allowed, so use the six-character connection id when
  a name is ambiguous.

## Notes

- SSH bytes are carried over iroh QUIC streams. esp lets iroh try direct
  connections first and use relays when a direct path is unavailable.
- The daemon allows proxying to local port 22 only unless additional ports are
  passed with `esp daemon --ports`.
- The inviter accepts invited peers by checking the random network id and issued
  invite, then signs a membership certificate bound to the joining node id and
  connection id. Any joined host with a valid membership can issue invites, so
  treat network members and invite codes as trusted.
- Hosts exchange known peers only during join and proxy connection setup.
- Shared peer and certificate lists are capped at 100 entries. This is for
  security reasons. You can change this in the code.
