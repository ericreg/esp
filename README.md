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
Allow additional localhost ports explicitly:

```sh
RUST_LOG=info esp daemon --ports 22,8000
```

On the second machine:

```sh
esp join <invite-code>
RUST_LOG=info esp
```

To add a third machine, print a new invite on the first machine:

```sh
esp invite
```

Join with that new code on the third machine. Each host shares its detected name
and its unique case-sensitive, six-character base62 connection id when it joins
and when it initiates a proxy connection. Duplicate names are allowed but must
be disambiguated by id.

Once daemons are connected, SSH through esp to any learned peer:

```sh
ssh -o ProxyCommand='esp proxy %h %p' user@host
ssh -o ProxyCommand='esp proxy %h %p' user@A1B2C3
```

Or add an SSH config entry:

```sshconfig
Host host
    HostName host
    User user
    ProxyCommand esp proxy %h %p
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
esp invite            # create and print another invite from the creator config
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
- Invite codes are bearer secrets. Anyone with a valid invite can attempt to
  join that esp network.
- Peers share known peers during join and proxy setup. Shared peer lists are
  capped at 100 peers, and duplicate connection ids are rejected.
- `~/.esp.yml` contains this host's private iroh key. Keep it private and do not
  share the file between machines.
- Duplicate peer names are allowed, so use the six-character connection id when
  a name is ambiguous.

## Notes

- SSH bytes are carried over iroh QUIC streams.
- The daemon allows proxying to local port 22 only unless additional ports are
  passed with `esp daemon --ports`.
- The creator accepts invited peers by checking the random network id and issued
  invite. Treat invite codes as secrets.
- Hosts exchange known peers only during join and proxy connection setup.
- Shared peer lists are capped at 100 peers.
