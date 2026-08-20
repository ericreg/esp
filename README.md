# arc

`arc` is a tiny iroh-backed TUN tunnel aimed at one thing first: SSH between two
machines without manually exposing port 22.

This is an MVP. It is a two-host tunnel, not a general VPN manager yet.

## Flow

On the first machine:

```sh
cargo run -- init
cargo build
```

This creates `~/.arc.yml` and prints an invite code. Keep the daemon running on
that machine:

```sh
sudo env HOME="$HOME" RUST_LOG=info ./target/debug/arc
```

On the second machine:

```sh
cargo run -- join <invite-code>
cargo build
sudo env HOME="$HOME" RUST_LOG=info ./target/debug/arc
```

The first host gets `100.88.0.1`; the invited host gets `100.88.0.2`. Once both
daemons are connected, SSH over the tunnel:

```sh
ssh user@100.88.0.1
ssh user@100.88.0.2
```

Use whichever address belongs to the remote machine.

## Commands

```sh
arc init          # create ~/.arc.yml if missing and print an invite
arc join CODE     # join from an invite code
arc invite        # print another invite from the creator config
arc status        # show local node and tunnel details
arc daemon        # run the daemon; this is also the default `arc`
```

## Leaving

There is no leave command. Stop the daemon and delete `~/.arc.yml`.

## Notes

- The daemon creates a TUN interface, so it usually needs root or administrator
  privileges. On macOS this will be an automatically assigned `utunN`
  interface; on other platforms the daemon asks for `arc0`.
- Packets are carried as QUIC datagrams over iroh.
- The default MTU is `1000` to stay friendly to iroh datagram payload limits.
- The creator accepts an invited peer by checking the random network id in the
  invite. Treat invite codes as secrets.
