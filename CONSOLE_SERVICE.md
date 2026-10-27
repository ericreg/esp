# ESP machine console

`esp video serve` is a Rust system service for the active Linux seat's screen and
keyboard/mouse. It runs independently of user login. A viewer sees the existing
console or graphical session, including a login or lock screen, rather than a
new remote desktop. The kernel virtual-display module remains C.

This implementation is experimental. Text/graphics transitions and keyboard
injection pass isolated VM tests; real display-manager adoption and the macOS
viewer still need interactive validation. A service cannot force an arbitrary
compositor to render on a second graphics device without compositor cooperation.

## Capture behavior

| Host state | `--source auto` |
|---|---|
| Physical output, active text VT | Read the framebuffer mapped to that VT, preserving its login or shell. |
| One active physical graphical output | Read its DRM scanout planes, including supported cursor/overlay planes. Do not change physical modes. |
| No physical output, active text VT | Connect the ESP virtual monitor and map the existing VT to its fbdev framebuffer. Restore prior mappings on orderly shutdown. |
| No physical output, graphical VT | Connect the virtual monitor and capture what the compositor renders there. Wait if it has not enabled the output. |
| VT switch, login/logout transition, or unavailable source | Reset the viewer connection/decoder. On unavailable capture, send black and disable input. |

`--source virtual` explicitly selects the ESP monitor. `--source drm:…` selects
one output ID from `esp video displays`; selection does not automatically fall
back to another physical output. With multiple active physical graphical outputs,
select one explicitly. This implementation serves one screen and one viewer.

The systemd unit orders startup before `display-manager.service` and
`getty.target`, and signals readiness after its first capture attempt (which
connects a headless virtual monitor). Starting the service on an already-running
desktop relies on the compositor handling hotplug. It does not install/start a
desktop environment, enable automatic login, or create a new getty. Configure the
machine's normal display manager or local getty as you would for a monitor.
Firmware, bootloader, and initramfs disk-unlock screens occur before this service
and are outside its coverage.

## Build and device prerequisites

```sh
cargo build --release --features video-viewer --locked
make -C drivers/esp_video KDIR=/lib/modules/$(uname -r)/build
```

Use `LLVM=1` for a Clang-built kernel if required. Build the module for the
**running** kernel; a module built for another installed kernel cannot be loaded.
The updated module requires DRM fbdev emulation and framebuffer console support
(`CONFIG_DRM_FBDEV_EMULATION`, `CONFIG_FRAMEBUFFER_CONSOLE`). `/dev/tty0` and
`/dev/fb*` must be available. Keyboard/mouse injection requires `CONFIG_INPUT_UINPUT`
and `/dev/uinput` (`modprobe uinput` where modular).

Install the module using your distribution's module installation/signing process.
Once the matching module is installed, `modprobe esp_video` loads it. To persist
loading, place `esp_video` and `uinput` on separate lines in a file under
`/etc/modules-load.d/`. No reboot is required if the matching driver can be loaded
safely. Replacing an already-owned display module requires stopping its owner and
an intentional unload/reload; the installer never does this automatically.

For physical GPU scanout, EGL/GBM from the host graphics stack are loaded at
runtime (`libEGL.so.1`, `libgbm.so.1`). They allow importing DMA-BUF modifiers such
as tiled layouts. Linear RGB buffers also have a CPU mapping path when EGL is
unavailable. Codecs remain compiled into ESP, with no system codec dependency.
AV1 uses rav1e, assembly where supported, and at most six encoder threads by
default. NASM is needed for the default x86-64 assembly build. A Rust-only codec
build uses `--no-default-features --features video-viewer`.

## Identity and installation

The console owns a full ESP endpoint. Give it a completed, enrolled network
configuration and an explicit peer name or node ID. The configuration contains
the private endpoint identity. **Do not run a user daemon/helper and this service
with the same identity at the same time.** Either enroll a dedicated console
identity, or deliberately migrate the existing identity after stopping all its
other owners. A dedicated console identity lets an existing SSH daemon continue
unchanged. The console itself enables no TCP port forwarding.

The selected peer must already belong to the network and appear in the host's
configuration; invitations cannot be redeemed through a video connection.
Resolve ambiguous names using the full node ID. Install from the repository:

```sh
sudo scripts/install-console-service.sh /absolute/path/to/network.yml LAPTOP_PEER
```

The script installs the release binary at `/usr/local/bin/esp`, copies the
configuration to `/var/lib/esp-console/network.yml` with mode 0600, installs the
unit and `/etc/esp/console.env`, and reloads systemd's unit definitions. It refuses
to overwrite an existing console identity. **It does not start the service,
stop existing ESP processes, load/unload drivers, or reboot.**

Review `/etc/esp/console.env` (peer, source and size), ensure the matching updated
driver and uinput are loaded and the identity is exclusive, then:

```sh
sudo systemctl enable --now esp-console.service
sudo systemctl status esp-console.service
sudo journalctl -u esp-console.service -f
```

The unit runs as root for DRM framebuffer export, VT mapping, and uinput access.
It uses a private configuration directory, read-only system paths, hidden home
directories, and a capability bounding set. `CAP_SYS_ADMIN` is still broad; this
first implementation does not separate device access into a small helper.
Do not enable `PrivateDevices`: the real console and graphics devices are needed.

All tuning options are available on `esp video serve --help`. To change encoder
settings or disable input, use `systemctl edit esp-console.service`, for example:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/esp video serve --config /var/lib/esp-console/network.yml --peer ${ESP_CONSOLE_PEER} --source ${ESP_CONSOLE_SOURCE} --size ${ESP_CONSOLE_SIZE} --threads 4 --fps 20 --bitrate 4000 --view-only
```

Restart the service to apply changes. Stop it with
`sudo systemctl stop esp-console.service`. The ordinary `esp video status/stop`
commands address a user's foreground share through that user's helper; use
systemd/journalctl for the system console. Stopping releases held input, closes
the grant, restores text-console mappings where possible, and disconnects its
virtual monitor. SIGKILL cannot run mapping restoration; restart/normal shutdown
should be preferred.

## Viewer and input

Build the same revision with `video-viewer` on Linux or macOS (Xcode Command Line
Tools on Mac). Restart older helpers as well as updating the executable. From
the configured peer:

```sh
esp video view NETWORK CONSOLE_HOST
```

- Click the video window to capture keyboard and relative mouse input. The first
  click acquires control; it is not forwarded as a host click.
- Press **Ctrl+Alt+G** to release control (Control+Option+G on Mac). Focus loss,
  disconnect, and window close also release control.
- F11 toggles local fullscreen while input is released. While captured, it goes
  to the host. Host shortcuts such as Ctrl+Alt+F2 can switch VTs; reconnect and
  click again after a console switch.
- Input uses physical key positions and the host keyboard layout. Command maps
  to Super, Option to Alt. Clipboard, text/IME injection, and client shortcuts
  intercepted by its OS are not forwarded.
- Mouse motion, five buttons and vertical/horizontal scrolling are supported.
  A text VT only displays a mouse cursor if the host normally provides one.

Input has its own reliable QUIC stream on the authenticated video connection.
The host accepts it only for a control-enabled grant to the configured peer.
Queues and rate limits are bounded. A dedicated input worker releases held keys
and buttons after two seconds without input heartbeat, independently of encoding.
Stale events from older viewer generations are rejected. A disconnect or source
change requires a fresh click before control resumes. A capture failure disables
input rather than allowing control against a stale image.

This console grant intentionally includes the login and lock screens and remains
available across logout. Foreground `esp video share` retains its separate
view-only, stop-on-lock behavior. Both endpoints require the new implementation;
the protocol identifiers are unchanged and there is no legacy negotiation.
Iroh prefers a direct path when reachable and can fall back to a relay; input
and video use the same authenticated connection.

## Updating capture and recovery without rebooting

Build both components for the running kernel:

```sh
cargo build --release --features video-viewer --locked
make -C drivers/esp_video KDIR=/lib/modules/$(uname -r)/build LLVM=1 -j"$(nproc)"
```

Then update only the console service and its module. This briefly disconnects
video; the separate user ESP SSH service stays running. Close any other local
ESP video capture first. If module removal reports that it is in use, stop and
identify the remaining owner; do not force module removal.

```sh
sudo systemctl stop esp-console.service
sudo modprobe -r esp_video &&
sudo install -Dm644 drivers/esp_video/esp_video.ko /usr/lib/modules/$(uname -r)/extra/esp_video.ko &&
sudo depmod -a &&
sudo modprobe esp_video &&
sudo install -m755 target/release/esp /usr/local/bin/esp &&
sudo systemctl start esp-console.service
```

The client also needs the updated viewer and local helper to accept keyframe
recovery across a sequence gap. Rebuild with `cargo install --path . --features
video-viewer --locked --force`, then restart the old local `esp proxy-transport`
helper when its SSH connections can be interrupted. Installing a binary does
not replace an already running helper.

Text framebuffer capture now requires the module's synchronized snapshot ioctl;
an older module produces an explicit rebuild/reload error. fbcon drawing and
mode changes are excluded during the kernel copy. Conversion and encoding run
after releasing the locks. Unsynchronized userspace mmap writes are outside this
guarantee; physical graphical GPU capture retains the limits below.

## Limits and validation

Physical capture currently supports SDR XRGB/ARGB/XBGR/ABGR 8-bit DRM planes with
integer source crops and supported DMA-BUF imports. It composites planes and the
cursor in z-order. Rotation, fractional crops, global plane alpha, YUV overlays,
HDR and final display color transforms are not supported. GPU scanout changes
can race capture; an unavailable/unsupported frame produces a logged error and
black output. This is not universal capture for every GPU/compositor. Source
dimensions are limited to 4096 pixels per axis and 16 megapixels; encoded output
is at most 1920×1080. Sources are fitted and letterboxed without changing the
physical monitor's mode.

Checked during development:

- Video/input protocol and direct/private-relay tests, including view-only
  rejection, disconnect release, bounded events and codec round trips.
- Isolated Linux 6.18.55 and 7.3.0 VMs: headless fbcon output, visible text updates,
  uinput typing into the existing VT, mouse motion/buttons/scroll, stale input
  rejection, watchdog release, synthetic graphical scanout, return to text, and
  driver lifecycle tests. Keyboard and mouse use separate devices so mouse
  buttons cannot inherit keyboard autorepeat.
- Offscreen DMA-BUF import/readback on both AMD cards in the development host,
  verifying RGB values and row orientation without changing any display mode.

Run the VM console extension with a matching release test executable:

```sh
cargo test --release --features video-viewer --locked --no-run
drivers/esp_video/test-vm.sh /path/to/kernel /path/to/esp_video.ko /path/to/test-executable
```

The ignored console test refuses to run without the VM test boot flag. Never
enable that flag on a host. The offscreen GPU test can be run separately with
`ESP_TEST_DRM_CARD=/dev/dri/cardN` and the ignored
`video::gpu::tests::offscreen_dmabuf_readback` test filter; it does not modeset.

Still required: native Mac viewer/input validation, actual GDM/login/logout and
Wayland/X11 adoption on supported desktop stacks, hardware cursor/overlay
validation, monitor hotplug, and measured end-to-end latency. Linux cross-checking
the complete Mac application requires an Apple SDK; testing the codec alone does
not establish native viewer compatibility.
