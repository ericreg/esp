# ESP virtual display development

ESP exposes a single Linux DRM/KMS virtual monitor and reads its composed
XRGB8888 frames through `/dev/esp-video`. Encoding, authentication, networking,
and the client window run in unprivileged userspace. No compositor-specific
capture service is used. This is an experimental implementation: compilation and
synthetic network tests do not establish hardware/compositor compatibility.

## Build

The default ESP build remains SSH-only. Feature combinations are:

| Feature | Includes |
|---|---|
| `video` | DRM discovery, video service, local status/stop, protocol tests; no codecs or windowing. |
| `video-codec` | Above plus Linux `share` and software VP8 through libvpx. |
| `video-viewer` | Above plus the native `view` window using winit/softbuffer. |

Install development files for libvpx 1.16.0 or newer and `pkg-config` to build
the codec/viewer features. For a private dependency build without system changes,
run `scripts/build-video-deps.sh /absolute/path/to/prefix`, then set
`PKG_CONFIG_PATH=/absolute/path/to/prefix/lib/pkgconfig` when invoking Cargo.
That helper builds a pinned, portable libvpx without assembly optimizations;
use an optimized library build for performance measurements.

```sh
cargo build --release --features video-viewer --locked
make -C drivers/esp_video
```

Match the kernel's compiler: a Clang-built kernel may require
`make -C drivers/esp_video LLVM=1`. To compile against another installed header
tree, pass `KDIR=/lib/modules/KERNEL_VERSION/build`. This module has been compiled
against the installed 6.18.55 and 7.2.9 CachyOS header trees. Isolated VMs running both kernels pass real pixel capture, repeated scanout
updates, exclusive ownership, owner-death cleanup, and module unload. It has not
been loaded into the host or validated with a running graphical desktop. Other kernel APIs may need changes.

## Load in an interactive test session

Loading a new graphics module changes the host graphics stack. Perform these
steps only when ready to test that machine. ESP never loads modules, installs
drivers, edits boot configuration, or reboots automatically.

```sh
sudo install -m 644 drivers/esp_video/70-esp-video.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo insmod drivers/esp_video/esp_video.ko
```

Build the module for the **running** kernel. Secure Boot/module-signing policy
may require signing it before loading. No reboot is part of the normal workflow.
The udev rule gives the active seat user access to the capture endpoint. DRM
output discovery also needs read access to the applicable `/dev/dri/card*` nodes.
Run ESP as the graphical user; do not run its transport or viewer as root.

## Share and view

Use the newly built binary (for example, `./target/release/esp`), or install that
build on your PATH before using the `esp` commands below. A running older ESP
helper/daemon must be stopped and restarted manually with the video-enabled build;
ESP reports this requirement without interrupting its existing connections.

```sh
esp video displays
esp video share my-network --display DISPLAY_ID --peer my-laptop
esp video view my-network my-desktop
esp video status my-network
esp video stop my-network
```

The host creates a disconnected-until-owned virtual connector, then connects it
at the selected source's physical pixel size. In normal display settings, mirror
that source to the virtual display. ESP asks you to type the source connector
name locally before registering any viewing grant, and waits for a driver frame.
The driver can verify that its output is active, but cannot prove cross-GPU clone
configuration. **This is user-confirmed mirroring, not automatic mirror
verification.** Do not change the mirror configuration while sharing; the virtual
output streams whatever the host renders into it. Automatic verification remains
a feasibility gate for a release claiming verified single-source mirroring.

The viewer opens a resizable window; F11 toggles fullscreen. It sends presentation
acknowledgements and health messages, with no keyboard/mouse forwarding. Closing
it leaves the host ready for the same explicitly allowed peer. Transient failures
retry the same share UUID for up to 30 seconds; explicit rejection ends retries.

Quality options on `share`: `--fps 1..30`, `--max-size WIDTHxHEIGHT` (at most
1920x1080), and `--bitrate 500..12000` in kbit/s. Defaults are 30 FPS and
4000 kbit/s. Congestion closes the current decoding timeline, requests a lower
encoder bitrate (then frame rate), and reconnects with a fresh keyframe.

The host requires a uniquely identifiable active graphical logind session and
polls its active/lock state. It stops on a lock signal, session loss, source
disconnection/mode change, virtual-output deactivation, owner exit, or revocation.
Lock reporting, cursor rendering, color, GPU buffer imports, and desktop adoption
of the virtual device still need interactive validation on each supported stack.
There is no current claim of production-ready host compatibility or measured
1080p30/latency performance. The macOS viewer needs native build/runtime testing.

Ctrl-C, `stop`, and process death close the capture file and disconnect the virtual
monitor; the DRM device remains registered until module removal. Once no share
owns it, remove the module with `sudo rmmod esp_video`. Existing physical display
configuration is never rewritten by ESP.

## Validation

```sh
cargo test --no-default-features --locked
cargo test --features video --locked
cargo test --all-features --locked
```

For an isolated kernel test (Linux x86_64 with KVM, QEMU, static libc, libdrm
headers, and cpio), build a module for the selected guest kernel and run:

```sh
drivers/esp_video/test-vm.sh /path/to/kernel-image /path/to/matching/esp_video.ko
```

The script uses no host graphics devices or network interface. Its guest init
loads and unloads the module, validates actual frame bytes, input bounds, repeated updates, and cropped scanout,
and verifies cleanup after SIGKILL. Only the VM is powered off afterward.

Rust tests exercise bounded framing, codec color round trips, mutual membership,
ephemeral grants, single-viewer limits, stop/revocation, stalled presentation,
and real direct and private forced-relay sessions using synthetic frames. They
do not load the module, change host displays, or contact public relays.

Before publishing host support, test actual monitor creation, manual mirror
configuration, first-frame capture, cursor/SDR correctness, lock/logout/unplug,
SIGKILL cleanup, slow viewers, and repeated start/stop with physical displays
preserved. Measure performance using a release build and an optimized libvpx.

The module uses GPL-2.0-or-later. libvpx's license and patent grant are recorded
under `third_party/libvpx`; other native viewer dependencies retain their upstream
licenses as recorded by Cargo.
