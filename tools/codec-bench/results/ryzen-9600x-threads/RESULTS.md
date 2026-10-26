# AV1 thread scaling on Ryzen 5 9600X

120 successful cases and 7,200 measured frame round trips. Three repetitions of 1/2/4/6/12 threads, assembly disabled/enabled, and four 1080p workloads. All output packet sizes, reconstruction checksums and tile grids match across every thread count, variant and repetition.

Configuration: 1920×1080, 60 measured frames plus three discarded warmup frames per case, 30 FPS timeline, quantizer 100, speed 10, low-latency mode, RDO lookahead 1, fixed tile target 16. Actual emitted layout is 4×4 (16 tiles) for every measured frame. Both encoder and decoder use the specified worker budget, timed separately. CPU: six physical cores, twelve logical CPUs; no affinity/governor/SMT settings changed. Variants execute serially, reversing ordering between rounds.

## Assembly-enabled encoding

Median frames per second across three runs. The one-thread control has the same 16-tile layout as every multi-threaded case.

| Threads | Static text | Scrolling | Moving windows | Video stressor |
|---:|---:|---:|---:|---:|
| 1 | 25.7 | 15.7 | 18.0 | 4.0 |
| 2 | 41.7 | 27.4 | 29.8 | 7.2 |
| 4 | 62.8 | 44.1 | 45.8 | 13.4 |
| 6 | 69.6 | 49.5 | 50.0 | 16.9 |
| 12 | 71.9 | 53.3 | 53.9 | 19.8 |

## Rust-only encoding

| Threads | Static text | Scrolling | Moving windows | Video stressor |
|---:|---:|---:|---:|---:|
| 1 | 7.8 | 6.2 | 5.6 | 1.2 |
| 2 | 13.7 | 11.2 | 9.7 | 2.0 |
| 4 | 24.2 | 19.6 | 16.9 | 3.4 |
| 6 | 29.3 | 24.6 | 19.7 | 4.1 |
| 12 | 31.4 | 26.7 | 21.8 | 4.5 |

## CPU cost and scaling

Average occupied logical CPU cores during timed encoding (`CPU time / wall time`), assembly enabled. These are unpaced maximum-throughput measurements, not expected utilization at a capped 30 FPS.

| Threads | Static text | Scrolling | Moving windows | Video stressor |
|---:|---:|---:|---:|---:|
| 1 | 1.00 | 1.00 | 1.00 | 1.00 |
| 2 | 1.66 | 1.77 | 1.70 | 1.81 |
| 4 | 2.55 | 2.90 | 2.66 | 3.36 |
| 6 | 2.96 | 3.38 | 3.01 | 4.43 |
| 12 | 4.25 | 4.74 | 4.30 | 7.37 |

## Interpretation

- **Fastest tested: 12 threads + assembly.** It reaches approximately 53–72 FPS on the desktop workloads and 20 FPS on the synthetic video stressor.
- **Practical desktop starting point: 4–6 threads + assembly.** Four threads already exceed 30 FPS in all desktop workloads; six gives more headroom. This is a codec-only result, excluding capture/conversion/network/rendering costs.
- Twelve versus six threads adds only about 3–17% encoding throughput, depending on workload. CPU time per frame rises about 30–41%. Choose twelve when maximum throughput matters more than CPU efficiency.
- Pure Rust improves with threading, but still does not sustain 1080p30 on all desktop workloads. The best measured Rust-only video throughput is about 4.5 FPS.
- Four extra input frames are buffered at every thread count and in both variants. At 30 FPS, that implies roughly 133 ms of input availability delay; threading does not remove that structural delay.
- Decoding also benefits from threads, but more is not universally faster: the Rust-only desktop decoder tends to plateau around 4–6 threads, while assembly-enabled decoding is already fast at one thread. The Mac needs its own measurements; do not use host decoding results as an ARM performance estimate.
- This sweep holds tiling fixed. The earlier benchmark used the codec default layout; do not attribute the difference between those layouts to threading alone. Bitrate and quality are unchanged *within* this sweep, but differ slightly from the earlier default-layout results.

## Reproduce

```sh
tools/codec-bench/run-thread-scaling.sh results/threads --frames 60 --warmup 3
python3 tools/codec-bench/summarize-threads.py results/threads/*.json
```

On this host, the assembly build uses NASM 3.01 from `/tmp/esp-codec-bench-nasm/local/bin` (prepend it to PATH). On Apple Silicon, use the native ARM64 Rust toolchain and Xcode Command Line Tools; NASM is not needed.

Thirty raw JSON reports and the generated timing table are retained locally and excluded from version control. The commands above regenerate reports and summarize timing, CPU cost, bitrate and quality. [Harness and Mac replay instructions](../../README.md).

## Verification and Mac client experiment

Release tests pass for both variants, including multi-tile inter-frame round trips
and archive replay. Clippy (warnings denied), formatting, and shell/Python syntax
checks pass. Both ARM64 macOS variants pass compilation checks; native Mac execution
remains pending.

The exported 12-thread assembly streams were independently replayed at all five
decoder thread counts with assembly off/on: 40 cases and 2,400 frames, every checksum
matching the host source. Source reports, replay reports, encoded streams and the
Mac bundle are local artifacts excluded from version control.

The locally generated Mac bundle contains these streams under `tools/codec-bench/host-thread-streams`:

```sh
tools/codec-bench/replay-thread-corpus.sh \
  tools/codec-bench/host-thread-streams results/mac-decoder-threads
python3 tools/codec-bench/summarize.py results/mac-decoder-threads/*.json
```

This tests client decoding alone against identical packets. For local encoding and
decoding on the Mac, use `run-thread-scaling.sh` instead.
