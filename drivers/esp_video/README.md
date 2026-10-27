# ESP virtual display development

ESP exposes a single Linux DRM/KMS virtual monitor and reads its composed
XRGB8888 frames through `/dev/esp-video`. Encoding, authentication, networking,
and the client window run in userspace. Foreground sharing is unprivileged;
the [machine-console service](../../CONSOLE_SERVICE.md) runs as root to access
login screens, framebuffer consoles, physical scanout, and uinput. No compositor-specific
capture service is used. This is an experimental implementation: compilation and
synthetic network tests do not establish hardware/compositor compatibility.

## Build

The default ESP build remains SSH-only. Feature combinations are:

| Feature | Includes |
|---|---|
| `video` | DRM discovery, video service, local status/stop, protocol tests; no codecs or windowing. |
| `video-codec` | Above plus Linux `share`/`serve` and software AV1 through rav1e/rav1d. |
| `video-viewer` | Above plus the native `view` window using winit/softbuffer. |

The codec crates are compiled into ESP; no system codec library is required.
Assembly optimizations are enabled by the default `video-asm` feature, with CPU
features selected at runtime. On x86-64, install NASM (2.15.05 or newer); on Apple
Silicon use Xcode Command Line Tools. For a Rust-only build, use
`--no-default-features --features video-viewer`. SSH-only builds do not compile
codec dependencies. The rav1d dependency pins upstream commit
`6c6f463785a546dea18fd9ca0f14634c2ee0557c`, which includes the ARM assembly
header missing from the published 1.1.0 crate and fixes a decoder-error cleanup
panic. Its C-compatible function interface still executes Rust, with optional
assembly; it does not link a system C codec library.

```sh
cargo build --release --features video-viewer --locked
make -C drivers/esp_video
```

Match the kernel's compiler: a Clang-built kernel may require
`make -C drivers/esp_video LLVM=1`. To compile against another installed header
tree, pass `KDIR=/lib/modules/KERNEL_VERSION/build`. The updated module has been
compiled and tested in isolated VMs against 6.18.55 and 7.3.0 CachyOS kernels.
Tests cover pixel capture, repeated scanout updates, exclusive ownership,
owner-death cleanup, module unload, fbcon text, and text/graphics transitions.
It has not been validated with a running graphical desktop. Other kernel APIs
may need changes. DRM fbdev emulation and framebuffer-console support must be
enabled for text-console capture.

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
Run foreground sharing and the viewer as the graphical user. The separate
system-console service deliberately requires root; see its setup guide.

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

When a requested video host is missing from the local peer list, the updated
helper refreshes the signed directory from known authenticated network admins
before retrying lookup. This lets an existing viewer learn about a newly enrolled
console identity without restarting the host's SSH service. Directory refresh
does not grant viewing or input permission; the console's explicit peer grant
still applies. Updating the executable does not update an already-running helper.

The host creates a disconnected-until-owned virtual connector, then connects it
at the selected source's physical pixel size. In normal display settings, mirror
that source to the virtual display. ESP asks you to type the source connector
name locally before registering any viewing grant, and waits for a driver frame.
The driver can verify that its output is active, but cannot prove cross-GPU clone
configuration. **This is user-confirmed mirroring, not automatic mirror
verification.** Do not change the mirror configuration while sharing; the virtual
output streams whatever the host renders into it. Automatic verification remains
a feasibility gate for a release claiming verified single-source mirroring.

The viewer opens a resizable window; F11 toggles fullscreen while input is released.
Foreground shares are view-only; console-service grants also permit input unless
configured with `--view-only`. Click to capture; Ctrl+Alt+G releases. Closing
it leaves the host ready for the same explicitly allowed peer. Transient failures
retry the same share UUID for up to 30 seconds; explicit rejection ends retries.

Press F10 to toggle the video aspect-ratio lock while remote input is released
(Ctrl+Alt+G releases it). On Mac, Fn+F10 may be needed. The title shows whether
resizing is free or locked. F10 is forwarded to the host when input is captured.
Fullscreen/maximized windows keep the display's shape and restore the lock on
returning to a normal window. macOS uses a native live-resize constraint; other
window managers may override proportional size requests.

Quality options on `share`: `--fps 1..30`, `--max-size WIDTHxHEIGHT` (at most
1920x1080), and `--bitrate 500..12000` in kbit/s. Defaults are 30 FPS and
4000 kbit/s. Brief congestion keeps the connection, input, and last image alive.
ESP skips dependent frames after a gap and resumes at a fresh AV1 keyframe,
reducing both bitrate and frame rate. A sustained stall still ends the session.
Console/VT changes, capture failure, and permission loss still clear the image.

Text-console capture requires the updated module's `ESP_VIDEO_CONSOLE_SNAPSHOT`
ioctl. It copies the framebuffer under `console_lock` and the fbdev mode lock,
then releases both locks before copying to userspace or converting/encoding.
This excludes fbcon redraws, scrolling, cursor updates, and VT changes during the
snapshot. Arbitrary userspace writes through a framebuffer mmap do not take
these locks and are outside this guarantee. Physical GPU scanout also retains
its separate driver-dependent consistency limits.

Upgrade the host service, client/helper, and kernel module together. No reboot
is required; see `CONSOLE_SERVICE.md` for stopping only the console service,
reloading the module, and restarting it without stopping ESP SSH.

Foreground `share` requires a uniquely identifiable active graphical logind session and
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
input forwarding/cleanup, and real direct and private forced-relay sessions using synthetic frames. They
do not load the module, change host displays, or contact public relays.

Before publishing host support, test actual monitor creation, manual mirror
configuration, first-frame capture, cursor/SDR correctness, lock/logout/unplug,
SIGKILL cleanup, slow viewers, and repeated start/stop with physical displays
preserved. Measure performance using a release build with assembly enabled.

The host uses rav1e speed 10, 16 requested tiles, low-latency mode and minimum
RDO lookahead (1). `--threads` controls the encoder worker limit (1–64); the default
is the available CPU count capped at six. For example:

```sh
esp video share work --display card0-DP-1 --peer laptop --threads 4
```

`--bitrate` remains an average target in kbit/s. Rate control and packet-size
checks remain active. The encoder buffers inputs; at 30 FPS the measured four
additional inputs represent about 133 ms before processing/network/presentation.
Static screens continue feeding the encoder so the last change is delivered.
Backpressure stops new inputs; encoded dependent frames are never dropped. A
viewer attachment or congestion reset starts a new independently decodable stream.
This is an AV1-only breaking change using the existing protocol identifiers.
Upgrade both endpoints and restart helpers; no codec negotiation or VP8 fallback
is provided.

The module uses GPL-2.0-or-later. rav1e and rav1d retain their upstream BSD-style
licenses; assembly sources retain their respective upstream notices. Cargo builds
these sources directly. Viewer dependencies retain their upstream licenses.
