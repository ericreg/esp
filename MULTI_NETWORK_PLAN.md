# Multi-network support for esp

## Summary and command interface

Replace the single-network configuration with independently stored networks managed by one shared daemon. This is a breaking release: no migration or compatibility layer.

| Command | Behavior |
|---|---|
| `esp init NETWORK` | Create a network with this shared label |
| `esp join INVITE` | Obtain the network label from the invitation and verify it during joining |
| `esp invite NETWORK PEER` | Create an invitation with the peer’s admin label |
| `esp revoke NETWORK PEER` | Revoke a peer in that network |
| `esp destroy NETWORK [--global] [--yes]` | Remove locally, or destroy network-wide |
| `esp proxy NETWORK PEER PORT` | Open a proxy through the selected network |
| `esp rename NETWORK NAME` | Rename this host within that network |
| `esp policy NETWORK --max-peers N` | Update that network’s signed policy |
| `esp status [NETWORK] [--peers]` | Summarize all networks, or show one network’s details |
| `esp admin [NETWORK]` | Open the network browser, optionally preselecting a network |
| `esp daemon` or `esp` | Serve all configured networks |

Existing invitation, policy, and formatting flags remain available on their corresponding commands.

- Network labels are mandatory, signed, immutable, and shared across members. Preserve current normalization: trimmed, case-sensitive printable ASCII, 1–64 characters, with quoted spaces allowed.
- Reject joining a different network whose label is already used locally. Repeating `init` for an existing label returns its existing identity without changing policy.
- Peer lookup stays inside the selected network and accepts admin labels, hostnames, connection IDs, and node IDs. Exact IDs take precedence; ambiguous name/label matches fail with disambiguating IDs.
- Update generated hints, SSH examples, help, and documentation to use the new syntax.

## Configuration and storage

Separate global preferences from network identities and signed state.

Global `~/.esp/config.yml`:

```yaml
version: 3
format:
  type: text
  colorize: true
transport:
  ports: [22]
  max_connections_per_peer: 8
```

- Store each network in `~/.esp/networks/<network_id>.yml`, using its UUID rather than its label as the filename.
- Each network has its own secret key, connection ID, hostname, memberships, invitations, policy, revocations, peers, and connection history.
- Allow optional per-network `transport` overrides. Effective settings use explicit daemon flags first, then network overrides, then global defaults. An empty port list disables incoming TCP forwarding for that network.
- Formatting remains global. Explicit `--format`, `--color`, and `--no-color` override the configuration.
- Read transport settings when starting or promoting the daemon and when adding a network. Manual transport-setting changes require restarting the daemon; preserve those edits when saving network state.
- Retain the shared socket and persistent lock inside `~/.esp`, private directory/file permissions, symlink protections, and atomic writes.
- Introduce version 3 configuration, invitations, certificates, and protocols. Reject older state and messages clearly; never automatically delete or migrate existing configuration.

## Shared daemon and network lifecycle

Introduce a network manager owning separate configuration actors and iroh endpoints, indexed internally by network UUID.

- Route every network-specific local request through an explicit UUID. Labels select networks locally; UUIDs and certificates remain the authentication boundary.
- Serialize creation, joining, and removal with daemon startup and offline mutations. Reserve labels before redeeming invitations to prevent concurrent duplicate joins.
- New invitation codes include the network label. Verify it against the inviter’s signed policy before completing membership and making the network available.
- Add or remove networks while running without restarting other endpoints. A failed network must not stop healthy networks; status reports its error.
- Allow the daemon to run with zero networks and accept later additions.
- Automatic proxy startup creates one outgoing-only shared helper. Preserve its idle shutdown behavior.
- Running `esp daemon` while that helper exists promotes it in place, enables incoming forwarding, and preserves active proxy sessions. The foreground command owns its lifetime; termination or loss of that controlling connection shuts down the shared process. A second foreground daemon invocation reports that one is already running.
- Keep peer quotas and connection tracking isolated by network, with bounded process-wide work queues.

Local destruction requires confirmation unless `--yes` is supplied. Noninteractive invocation requires `--yes`.

- Stop the selected network’s sessions and remove its local state before reporting success.
- Leave other members’ records unchanged; this is local removal, not revocation.
- A fresh invitation can subsequently rejoin that network.

Global destruction additionally requires an active daemon in serving mode and a valid local admin membership.

- Create and durably persist a signed destruction certificate containing the network UUID, issuer, timestamp, and authority proof.
- Immediately disable that network’s forwarding, invitations, policy changes, and active sessions.
- Distribute the certificate to known members. Recipients verify its signature and admin chain against the pinned creator and known revocations; ordinary members may relay a valid certificate.
- Retain a terminal record, control identity, and delivery information after destruction. Hide it from active network lists, reject rejoining its UUID, and serve only destruction notifications.
- Retry pending deliveries on startup and with bounded exponential backoff, capped at five minutes. Accepted destruction is permanent and cannot be reversed by older state.
- Report destruction as recorded with delivery pending where applicable. Offline members stop when the certificate reaches them; instantaneous shutdown across disconnected members is not guaranteed.
- Reusing the label with `init` creates a new UUID and identity.

## Status and admin interface

- `status` without a network returns an object containing daemon state and a label-sorted `networks` array with each network’s label, UUID, local role, transport state, and peer counts.
- `status NETWORK` shows that network’s detailed identity and configuration information.
- `--peers` adds peer records to either form. Offline presence is unknown rather than presented as a measured connected count.
- Text output groups networks into separate blocks, retaining snake_case keys and configured colors. JSON retains syntax highlighting by default.

The admin TUI uses three panes: **Networks → Peers → Peer details**.

- Show every active local network, including ordinary-member networks as read-only.
- `Tab` and `Shift-Tab` move focus; arrows and `j/k` navigate the focused list. Preserve detail scrolling.
- Selecting a network updates the header, peers, permissions, and details. Tag asynchronous responses with network UUID and selection generation so stale results cannot cross networks.
- Preserve bold keys, light-blue values, green `running`/`connected`, red `not_running`, and gray `unknown`.
- Enable revoke only for an online administrator with a selected peer. The confirmation identifies both the peer and network, and submits their stored IDs.
- Handle empty lists, network removal during viewing, and daemon reconnection without exiting the TUI.

## Validation and rollout

- Test network isolation with identical peer names across networks, separate identities, independent permissions, port limits, revocation, and simultaneous proxies.
- Test label collisions, invitation-label tampering, concurrent init/join, failed joins, and rejection of old versions.
- Test helper startup races, seamless promotion during active traffic, foreground shutdown, live additions/removals, and network-specific startup failures.
- Test local/global confirmation behavior, non-admin rejection, invalid destruction signatures, offline delivery after restart, permanent destruction, and label reuse with a new UUID.
- Test status formats, global/CLI precedence, TUI focus and read-only permissions, and stale responses during network switching.
- Run `cargo fmt --check`, `cargo check --tests`, the full `cargo test` suite, and `git diff --check`.
- Document the required coordinated upgrade: stop old transports, move old configuration aside, initialize new networks, issue fresh invitations, and update SSH commands. Perform integration validation using temporary profiles, leaving the user’s existing networks untouched.
