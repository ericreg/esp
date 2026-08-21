# arc

`arc` is a tiny iroh-backed TCP proxy aimed at one thing first: SSH between two
machines without manually exposing port 22.

This is an MVP. It is a two-host SSH transport helper, not a general VPN manager.

## Flow

On the first machine:

```sh
cargo run -- init
cargo build
```

This creates `~/.arc.yml` and prints an invite code. Keep the daemon running on
that machine:

```sh
RUST_LOG=info ./target/debug/arc
```

On the second machine:

```sh
cargo run -- join <invite-code>
cargo build
RUST_LOG=info ./target/debug/arc
```

The first host gets `100.88.0.1`; the invited host gets `100.88.0.2`. Once both
daemons are connected, SSH through arc:

```sh
ssh -o ProxyCommand='./target/debug/arc proxy %h %p' user@100.88.0.2
```

The remote daemon connects to `127.0.0.1:%p` on its own machine, so Linux
firewall rules do not need to allow inbound SSH on an arc interface.

## Commands

```sh
arc init          # create ~/.arc.yml if missing and print an invite
arc join CODE     # join from an invite code
arc proxy IP PORT # proxy stdio to localhost:PORT on the peer with overlay IP
arc invite        # print another invite from the creator config
arc status        # show local node and tunnel details
arc daemon        # run the daemon; this is also the default `arc`
```

## Leaving

There is no leave command. Stop the daemon and delete `~/.arc.yml`.

## Notes

- The daemon does not create a TUN interface and should not need root.
- SSH bytes are carried over iroh QUIC streams.
- The creator accepts an invited peer by checking the random network id in the
  invite. Treat invite codes as secrets.
