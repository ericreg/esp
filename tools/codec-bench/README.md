# ESP codec benchmark

Standalone Linux/macOS executable for the candidates discussed for ESP: pure-Rust
VP8 (`oxideav-vp8 0.2.7`), and AV1 (`rav1e 0.8.1` encoder + `rav1d 1.1.0` decoder).
The optional `asm` feature enables the AV1 libraries' architecture-specific assembly.
It does not change the VP8 implementation. This is a comparison of these specific
implementations/configurations, not an exhaustive survey of every Rust media crate.

No ESP daemon, display server, virtual display driver, system codec library, network
connection, or input capture is needed. The benchmark never loads drivers or reboots.
Dependencies are pinned in the independent Cargo.lock; ESP's dependencies are unchanged.
`rav1d` is pinned to upstream commit `782dab2135ea64a057c097088a13eb8ed3cc3320`,
the exact commit recorded in the 1.1.0 crate's `.cargo_vcs_info.json`. The registry
package omits `src/arm/asm-offsets.h`, breaking ARM assembly builds. The Git source
contains it; all 163 Rust/assembly files shared with the registry package were
verified byte-identical. No codec implementation is patched.

## Run the assembly ablation

Use a current stable Rust toolchain and the normal platform linker. On an Apple
Silicon Mac, use a native `aarch64-apple-darwin` Rust installation and Xcode Command
Line Tools, not an x86 Rust installation under Rosetta. The report records the target
and CPU model: a 2025 MacBook Pro is not enough information to assume its exact chip.

The x86 assembly build also needs NASM on PATH. The ARM64 build uses the platform
assembler/Clang; NASM is not needed on Apple Silicon. Codec libraries remain bundled
in the executable in both cases. No Homebrew codec packages are needed.

From the repository root:

```sh
# Builds both executables, then runs three alternating-order rounds.
tools/codec-bench/run-ablation.sh tools/codec-bench/results/local

# Print a Markdown table of per-case medians across rounds.
python3 tools/codec-bench/summarize.py tools/codec-bench/results/local/*.json
```

Defaults: 60 measured frames, 3 discarded warmup frames in a separate codec session,
30 FPS timeline, 720p and 1080p, four workloads, one AV1 thread, three rounds. Each
round has 16 cases per variant (96 cases total). This can take many minutes,
especially without assembly. Each case has a 600-second timeout including warmup;
failed cases are recorded and the rest continue. The script exits nonzero on failure.

For a quick functional run:

```sh
BENCH_REPEATS=1 tools/codec-bench/run-ablation.sh /tmp/codec-smoke \
  --sizes 320x180 --frames 4 --warmup 1
```

For the same full ablation on your Mac:

```sh
tools/codec-bench/run-ablation.sh tools/codec-bench/results/macbook
python3 tools/codec-bench/summarize.py tools/codec-bench/results/macbook/*.json
```

Keep the machine plugged in and idle. Record power/thermal conditions when comparing
machines. This harness does not change CPU governors, pin cores, disable boost, or
change macOS power modes. Use the same Rust version and build flags on both machines
where possible. Both variants use the same release profile and generic target;
assembly selects supported instructions at runtime. Rust-only still permits compiler
auto-vectorization and Rust intrinsics. It means no handwritten codec assembly,
not a promise that the CPU executes exclusively scalar instructions.

To inspect or run a single executable:

```sh
cargo build --manifest-path tools/codec-bench/Cargo.toml --locked --release \
  --target-dir tools/codec-bench/target/rust
cargo build --manifest-path tools/codec-bench/Cargo.toml --locked --release \
  --features asm --target-dir tools/codec-bench/target/asm

tools/codec-bench/target/rust/release/esp-codec-bench --help
tools/codec-bench/target/asm/release/esp-codec-bench \
  --codecs av1 --sizes 1920x1080 --threads 2 --frames 120 --repeats 3 \
  --output /tmp/av1-two-threads.json
```

VP8's standalone stream encoder is single-threaded regardless of `--threads`.
Use one thread for the controlled codec comparison, then test AV1 thread counts
separately for deployment. The AV1 encoder uses speed 10, low-latency mode, and
one frame of RDO lookahead (the minimum allowed by this release). Actual buffering
can exceed one frame; it is measured, not assumed. Keyframe cadence is 30 frames at
the default frame rate. Each measured session begins with a keyframe.

## Encode on AMD64, decode those exact packets on the Mac

Each ablation round exports `.espbench` files under
`RESULT_DIRECTORY/streams/{rust,asm}/round-N/`. These are bounded binary archives
with JSON configuration and raw codec packets. Fixture generation is deterministic,
so the Mac can regenerate reference pixels for quality checks without raw video files.
The exported files are ignored by Git; copy them separately when transferring the repo.

Copy the desired host corpus directory to your Mac, then:

```sh
# Example: copied host assembly-enabled streams are in ~/esp-host-streams.
tools/codec-bench/replay-corpus.sh ~/esp-host-streams \
  tools/codec-bench/results/mac-host-streams --threads 1
```

This runs both decoder builds against the identical host-produced packets, three
rounds in alternating order. No encoding occurs. You can replay host Rust streams
too, using a different results directory. Check a transferred source report against each Mac replay report:

```sh
python3 tools/codec-bench/verify-replay.py host-asm-1.json \
  tools/codec-bench/results/mac-host-streams/rust-1.json
python3 tools/codec-bench/verify-replay.py host-asm-1.json \
  tools/codec-bench/results/mac-host-streams/asm-1.json
```

The per-frame `decoded_checksum` lets you
check identical pixel output across decoder variants and machines. It is a diagnostic
FNV-1a checksum, not a cryptographic integrity check. Replay also validates frame count,
size, packet consumption, and reference-image PSNR. The encoder metadata remains in
the corpus; the report's assembly flag describes the local executable/decoder.

## Workloads and measurements

All inputs are deterministic, 8-bit planar YUV 4:2:0:

- `static-text`: unchanged small bitmap text, to expose inter-frame reuse.
- `scroll`: the same text scrolls four pixels per frame.
- `windows`: a colored window moves over text.
- `video`: translated gradients and deterministic texture with moving chroma.
  This is a synthetic high-motion stressor, not a natural-camera video corpus.

The codec timer includes input allocations/copies, encode/decode calls, and copying
output planes into an owned frame. It excludes fixture generation, quality scoring,
file I/O, setup, capture, RGB conversion, scaling, network transport, and rendering.
Setup is reported separately. Encode includes final flushing and checks that every
submitted frame emerges exactly once in order. Decode requires one immediate picture
per packet with `max_frame_delay=1`. Each case runs in a fresh subprocess; warmup
then measured sessions use new codec instances. Peak RSS includes warmup, saved
compressed packets, decoder allocations, and harness overhead, not just codec memory.

JSON contains:

- Encode/decode FPS from total timed work; serial codec FPS is a conservative sum
  of both stages, not a model of overlapped host/client execution.
- Per-submit encode and per-frame decode mean/p50/p95/max, raw samples, CPU time,
  frame-budget exceedance counts, peak process RSS, and separate flush duration.
- Encoder residence in cumulative codec-processing milliseconds, plus the number
  of additional source frames submitted before each packet became available.
  Residence excludes fixture generation and is **not end-to-end latency**. At 30 FPS,
  four extra inputs imply about 133 ms of input availability delay before accounting
  for processing/network/display. Submission timing alone can hide this buffering.
- Actual encoded bytes and Mbps normalized to the requested FPS, independent of
  how slowly the benchmark executes. Container/network overhead is excluded.
- PSNR-Y and sample-weighted PSNR-YUV computed from pooled squared error, on a
  full 255-value scale. JSON `null` PSNR means a perfect reconstruction/infinite PSNR.
- CPU, architecture, compiler, build target, codec versions, configuration, assembly
  variant, repeat number, failures and per-frame reconstruction checksums.

In decode-only reports `mode` is `decode-only`: encode metrics/buffering are zero
placeholders and should be ignored; serial FPS equals decode FPS. The summary table
shows an em dash for encode throughput in that mode.

Defaults use constant quantizers: VP8 qindex 32 and AV1 quantizer 100. These scales
are **not equivalent**, and this is not a matched-bitrate or matched-quality contest.
Within-codec assembly comparisons hold settings identical. For codec selection,
inspect measured bitrate and PSNR together; use `--vp8-q` (0..127), `--av1-q` (0..255)
and `--av1-speed` (0..10) to make rate/quality sweeps. Two-pass bitrate control is
intentionally excluded because it requires future frames. PSNR does not replace
visual assessment of text readability. Static frames are deliberately still encoded;
ESP's unchanged-frame suppression would reduce their real workload.

## Verification and limitations

```sh
cargo test --release --manifest-path tools/codec-bench/Cargo.toml --locked
cargo test --release --manifest-path tools/codec-bench/Cargo.toml --locked --features asm
```

Tests cover deterministic moving/static fixtures, statistics, multi-frame inter-codec
round trips, basic quality, corpus export/replay equivalence, and truncated/invalid corpus rejection. The archive/replay path supports comparing reconstruction
on the same packets independently of encoder decisions. `rav1d` exposes a C-compatible
public ABI implemented in Rust; the small unsafe adapter owns buffers/context through
Drop guards. No dav1d C library is linked. Both decoder bit-depth features are enabled
because rav1d 1.1.0's x86 assembly link references 16-bit symbols even in an 8-bit-only
build; all benchmark input/output remains 8-bit.

Neither variant uses GPU acceleration or VideoToolbox. Enabling assembly does not
mean hardware video encoding. macOS execution must be verified on the actual Mac;
Linux measurements cannot predict its ARM64 decoder speed.

Host measurements and interpretation: [Ryzen 5 9600X results](results/ryzen-9600x/RESULTS.md).

## Multi-thread scaling

```sh
# 1080p, AV1 only, fixed target of 16 tiles, 1/2/4/6/12 threads,
# assembly off/on, four workloads, three rounds: 120 cases.
tools/codec-bench/run-thread-scaling.sh tools/codec-bench/results/thread-scaling
python3 tools/codec-bench/summarize.py tools/codec-bench/results/thread-scaling/*.json
```

This holds the target tile count constant across thread counts, including the
one-thread control. `--av1-tiles` defaults to zero in the executable (the prior
codec-default behavior), while the scaling runner uses `BENCH_TILES=16`. Rav1e
chooses the actual grid from the target and frame dimensions; each decoded sample
records `tile_grid` as `[columns, rows]`. Increasing the thread-pool budget alone
does not create additional encoding tiles. The fixed layout allows parallel work
while separating worker-count scaling from layout/bitstream changes.

The thread count applies separately to the encoder and decoder. Their timings are
measured sequentially; these are not simultaneous host/client CPU measurements.
Use `encode_cpu_ms / encode_total_ms` to estimate average occupied CPU cores during
encoding, and the equivalent decode fields for decoding. The host has six physical
cores and twelve logical CPUs; twelve worker threads do not imply twelve physical
cores. CPU affinity, clocks, power management, and SMT settings remain unchanged.

Each repetition reverses the thread-count and variant order to reduce systematic
thermal/order bias. Defaults remain 60 measured frames plus three warmup frames.
The tile target can be changed for a *separate* experiment:

```sh
BENCH_TILES=0 tools/codec-bench/run-thread-scaling.sh results/default-layout
BENCH_TILES=8 tools/codec-bench/run-thread-scaling.sh results/eight-tile-target
```

Do not attribute differences between these layouts to threading alone: tiling can
change bitrate, reconstruction quality and cache behavior. Compare worker counts
within the same layout first. Raw JSON records both requested layout and actual
output grid. Existing archives without an `av1_tiles` field retain their original
zero/default setting when replayed.

For the ARM client, replay the *same host-encoded multi-tile corpus* across all
thread counts; this isolates decoder threading without changing the encoded stream:

```sh
tools/codec-bench/replay-thread-corpus.sh /path/to/host-thread-streams results/mac-decoder-threads
python3 tools/codec-bench/summarize.py results/mac-decoder-threads/*.json
```

The source corpus determines the actual layout in replay mode. A `BENCH_TILES`
setting cannot retile an existing stream. Decode-only encode columns are placeholders;
compare decode throughput, p95 and CPU time. Use `verify-replay.py` with the source
report to verify reconstruction for any thread-count report.

Host multi-thread measurements: [Ryzen 5 9600X thread scaling](results/ryzen-9600x-threads/RESULTS.md).
