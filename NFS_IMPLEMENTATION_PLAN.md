# Embedded NFSv4.2 Shares over ESP

## Summary

Add first-class, persistent file shares transported over iroh without requiring an NFS server or NFS userland packages on either machine.

```sh
esp share "Home network" files ~/Files
esp mount "Home network" server files
esp unmount ~/esp/Home-network/server-ABC123/files
```

The host runs an in-process NFS server. The client exposes a loopback TCP listener, forwards NFS traffic through a new ESP protocol, creates the mount directory, and mounts it using the operating system's kernel NFS client.

Support Linux and macOS. Implement NFSv4.1 compatibility for macOS and NFSv4.2 for Linux, based directly on RFC 8881 and RFC 7862 rather than depending on `embednfs`.

## Public Interfaces and Configuration

- Add commands:

  - `esp share NETWORK SHARE MOUNTPOINT [--access ro|rw] [--peers PEER,...]`
  - `esp unshare NETWORK SHARE`
  - `esp shares NETWORK [PEER]`
  - `esp mount NETWORK PEER SHARE [MOUNTPOINT]`
  - `esp unmount MOUNTPOINT [--force]`
  - `esp mounts`

- `esp share` is declarative and idempotent. Reusing a share name retains its stable share UUID and replaces its host mount point and access policy.
- `--access` defaults to `ro`. Without `--peers`, every active peer in the network receives that access. Supplying `--peers` changes the policy to an allowlist: the named peers receive the selected access and every other peer has no access.
- Accept peer names, connection IDs, or node IDs using the existing peer resolver. Normalize and persist the allowlist as node IDs. Allow comma-delimited values and repeated `--peers` flags.

  ```sh
  # Read-only for every peer.
  esp share "Home network" files ~/Files

  # Read-write for every peer.
  esp share "Home network" files ~/Files --access rw

  # Read-write only for peer1.
  esp share "Home network" files ~/Files --access rw --peers peer1
  ```
- Store shares in the relevant network YAML with backward-compatible `#[serde(default)]` fields:

  - Stable share UUID and validated name.
  - Canonical absolute host path.
  - Uniform access mode, `ro` or `rw`.
  - Optional peer allowlist; an absent allowlist means all active network peers.

- Store client mount registrations in the global ESP configuration:

  - Stable mount UUID, network and peer IDs, share UUID/name.
  - Absolute mount point, stable loopback port, mounting UID/GID.
  - Whether ESP created the directory and the last restoration error.

- Keep configuration version 3 because all new fields are additive. Introduce a separate `esp/nfs/cbor/1` ALPN.
- When no mount point is supplied, use `~/esp/<network>/<peer>-<connection-id>/<share>`. Sanitize display components, create directories as mode `0700`, and reject symlinks, non-directories, non-empty destinations, and existing mount points.
- `esp mount` starts or connects to the shared transport, persists the registration, binds its stable loopback port, then invokes a hidden copy of the executable through `sudo` for only the privileged mount operation.
- Linux uses `fsopen`/`fsconfig`/`fsmount`/`move_mount` directly. macOS uses its built-in NFS mount facility. No `nfsd`, `mount.nfs`, or third-party NFS package is required.
- `esp unmount` elevates only the unmount syscall, removes the registration and listener after success, and deletes an ESP-created mount directory only when empty.

## Implementation Changes

- Build an in-tree NFS subsystem with:

  - ONC RPC record framing, XDR codecs, `NULL`, and `COMPOUND`.
  - Bounded decoding: 4 MiB records, 64 operations per compound, 1 MiB advertised read/write sizes, 255-byte names, and 128-byte filehandles.
  - NFSv4.1/v4.2 session handling: `EXCHANGE_ID`, `CREATE_SESSION`, `SEQUENCE`, replay caching, connection binding, client/session destruction, and reclaim completion.
  - Filehandle/navigation operations, attributes, access checks, open/close state, read/write/commit, directory pagination, create/remove/rename, symlinks, hard links, byte-range locks, timestamps, and named attributes/xattrs.
  - `AUTH_SYS` presentation only; authenticated ESP membership and the share ACL remain the actual authorization boundary.
  - No delegations, callbacks, pNFS/layouts, Kerberos, or advanced v4.2 COPY/CLONE/ALLOCATE/SEEK operations in v1. Do not advertise them and return the correct `NFS4ERR_NOTSUPP` response when requested.
  - A 90-second lease and restart grace period, boot verifier changes, replay protection, and persisted client/open/lock recovery metadata.

- Implement a local-directory backend:

  - Run all host filesystem operations as the account running `esp`.
  - Present files as owned by the mounting client user; map all incoming NFS credentials to that single-user context.
  - Preserve file types, mode and executable bits, sizes, timestamps, links, and supported xattrs.
  - Reject remote ownership changes; permit mode, time, and truncate changes only for read-write mounts.
  - Resolve paths relative to an opened share-root descriptor. Use `openat2` confinement on Linux and component-by-component `openat`/`O_NOFOLLOW` validation on macOS.
  - Maintain stable filehandle and recovery metadata in private per-share Turso databases under `.esp`, using the embedded Rust `turso` engine. All database access is local; no cloud account, synchronization, or separate database service is required. Reconcile the index at startup and after external filesystem-change notifications.
  - Return `NFS4ERR_ROFS` for every mutation through a read-only share.

- Extend the transport:

  - The client listener sends a bounded CBOR setup request containing network ID, membership chain, target share, mount ID, and presentation UID/GID.
  - The receiver verifies membership/revocation, resolves the share, applies its current access mode and optional peer allowlist, replies `Ready` or `Error`, then switches the stream to raw RPC/XDR bytes.
  - Route NFS through its own ALPN rather than granting port 2049 in membership certificates.
  - Count NFS connections against existing process and per-peer quotas, but do not apply the generic one-hour TCP idle timeout. NFS leases and mount registration control lifetime.
  - Re-check access on each mutating operation. Revocation, removal from an allowlist, unsharing, or path replacement terminates affected sessions immediately.
  - Keep the outgoing helper alive while any persistent mount listener exists. Reload the same listener ports and mount registrations after daemon restart; report port conflicts without silently changing ports.
  - A machine reboot restores listeners when the user's ESP daemon service starts. Remount non-interactively only when mount privileges are available; otherwise report an actionable `needs_mount` error and let an explicit `esp mount` request prompt via sudo. ESP does not install a boot service or a sudo policy automatically.

- Update reports and documentation:

  - `esp shares NETWORK` reports local share path, UUID, availability, access mode, and either `all peers` or the resolved peer allowlist.
  - `esp shares NETWORK PEER` authenticates to that peer and lists only shares accessible to the requester.
  - `esp mounts` reports mount point, peer/share, listener port, mounted/restoring/error state, and access mode.
  - Document the required kernel NFS client support, sudo prompt, single-user ownership model, hard-mount behavior during outages, and Linux/macOS support boundary.

## Test Plan

- Unit-test XDR/RPC encoders and decoders against RFC vectors, malformed lengths, oversized compounds, invalid UTF-8, replayed slots, invalid state IDs, lease expiry, and unsupported operations.
- Test every filesystem operation against temporary directory trees, including paging, concurrent writes, rename-overwrite, hard links, symlinks, locks, xattrs, external host changes, stale handles, and path-escape attempts.
- Test access behavior for network-wide read-only, network-wide read-write, read-only and read-write peer allowlists, peers outside an allowlist, revoked peers, live downgrade, share removal, and path replacement.
- Extend transport integration tests for setup authentication, raw RPC bridging, half-closes, multiple NFS connections, quota exhaustion, reconnects, daemon promotion, daemon restart, grace/reclaim, and persistent listener restoration.
- Add privileged, opt-in end-to-end suites:

  - Linux NFSv4.2 mount using only ESP and kernel mount syscalls.
  - macOS NFSv4.1 mount using the built-in client.
  - Automatic mount-point creation and cleanup.
  - Read-only rejection and read-write CRUD.
  - Locks, Finder-style xattrs, large files, daemon crash/restart, peer revocation, forced unmount, and host-side external edits.

- Fuzz the network-facing CBOR handshake, RPC record parser, and COMPOUND decoder.

## Assumptions and Defaults

- The client kernel provides NFS support; ESP bundles the server and userspace orchestration, not a kernel filesystem driver.
- Share access defaults to read-only for all active network peers.
- Mounts use single-user identity mapping and mode `0700` mount directories.
- Mount registrations and local listener ports persist across daemon restarts.
- NFS mounts are hard mounts by default so transient ESP or network outages do not silently corrupt writes.
- NFSv4.2 is the maximum protocol version; v4.1 remains enabled for macOS interoperability.
- The host requires no elevation unless the selected directory is inaccessible to the account running the ESP daemon.

## Implementation and Validation Notes

- The metadata engine is embedded `turso`, not `rusqlite`, hosted Turso, or an external SQLite service.
- The internal `src/nfs` module and `src/shares` integration implement the commands and transport above within the main ESP crate. Filesystem confinement uses `cap-std` descriptor-relative operations, with non-following file opens and identity checks; filesystem notifications never follow export symlinks.
- The local bridge accepts only privileged source ports, and AUTH_SYS must identify the mounting UID or local root. On Linux, refuse to listen when `ip_unprivileged_port_start` allows unprivileged access to those ports.
- Metadata is isolated by network, share UUID, and export-root identity. Replacing a source directory invalidates old sessions even when the pathname stays the same.
- Native user xattrs are exposed through OPENATTR/named-attribute handles. Atomic xattr rename is explicitly unsupported; values remain in the backing filesystem.
- Filehandles without trustworthy birth timestamps are volatile across reboot rather than risking inode-reuse aliasing. Normal open descriptors are retained through unlink until CLOSE/lease expiry.
- Automated coverage includes XDR bounds, session replay, client isolation, live read-only changes, file operations, confinement, external renames, persistent handles, open/lock reclaim, named attributes, CLI policies, and real relay transport. Sustained fuzzing, power-loss fault injection, and comprehensive kernel interoperability remain release-validation work.
- The opt-in `kernel_nfs_mount` test is implemented but was not executed successfully in this environment: `sudo -n` required a password before the test could start. No macOS test host was available. Treat the feature as experimental until these platform gates pass.
