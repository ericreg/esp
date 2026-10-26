# Ryzen 5 9600X codec benchmark results

96 successful cases: three rounds × two assembly variants × two codecs × two resolutions × four workloads; 5,760 measured frame round trips, plus discarded warmup.

Linux x86_64, AMD Ryzen 5 9600X (6 cores / 12 logical CPUs), rustc 1.98.1. One codec thread, 60 measured frames per case, three separate warmup frames, 30 FPS media timeline, keyframes at frames 0 and 30. VP8 qindex 32; AV1 quantizer 100, speed 10, low-latency mode, minimum lookahead 1. No target-cpu=native flag. Harness variants ran serially; builds completed before the measurements. Ordinary OS activity was not isolated.

Values below are medians of three runs. VP8 has no assembly backend in this crate; its second variant is an unchanged control. Quantizer scales differ, so these are not matched-quality or matched-bitrate comparisons.

## AV1 assembly ablation

| Size | Workload | Rust encode FPS | Assembly encode FPS | Encode speedup | Rust decode FPS | Assembly decode FPS | Decode speedup | Mbps at 30 FPS | PSNR-Y dB |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1280×720 | static-text | 17.0 | 56.7 | 3.33× | 400.5 | 1278.6 | 3.19× | 2.074 | 40.57 |
| 1280×720 | scroll | 12.6 | 31.0 | 2.46× | 394.7 | 1259.6 | 3.19× | 2.090 | 40.81 |
| 1280×720 | windows | 10.4 | 32.6 | 3.14× | 245.7 | 905.5 | 3.68× | 3.378 | 42.06 |
| 1280×720 | video | 2.7 | 9.8 | 3.68× | 112.2 | 550.1 | 4.90× | 2.837 | 39.34 |
| 1920×1080 | static-text | 7.9 | 26.7 | 3.40× | 190.7 | 624.7 | 3.28× | 3.129 | 42.27 |
| 1920×1080 | scroll | 6.2 | 16.6 | 2.65× | 189.7 | 623.3 | 3.29× | 3.179 | 42.53 |
| 1920×1080 | windows | 5.6 | 18.5 | 3.31× | 134.1 | 531.9 | 3.97× | 3.961 | 43.78 |
| 1920×1080 | video | 1.2 | 4.3 | 3.69× | 50.4 | 248.6 | 4.94× | 6.218 | 39.41 |

## VP8 Rust baseline

| Size | Workload | Encode FPS | Decode FPS | Mbps at 30 FPS | PSNR-Y dB |
|---|---|---:|---:|---:|---:|
| 1280×720 | static-text | 9.6 | 1515.4 | 2.235 | 41.47 |
| 1280×720 | scroll | 8.6 | 1327.9 | 2.586 | 41.49 |
| 1280×720 | windows | 8.7 | 742.4 | 5.049 | 41.60 |
| 1280×720 | video | 5.7 | 310.0 | 8.917 | 37.18 |
| 1920×1080 | static-text | 4.4 | 775.0 | 4.083 | 43.22 |
| 1920×1080 | scroll | 4.1 | 703.9 | 4.597 | 43.25 |
| 1920×1080 | windows | 4.1 | 442.6 | 6.058 | 43.37 |
| 1920×1080 | video | 2.6 | 148.5 | 18.100 | 37.29 |

## What this means for ESP

- Assembly improves AV1 encoding by roughly 2.5–3.7× and decoding by roughly 3.2–4.9× at these settings. It does not eliminate encoder buffering.
- AV1 waits for up to four additional inputs before emitting a packet in both variants. At 30 FPS that represents about 133 ms of input availability delay, before processing, network and presentation costs. A setting of one lookahead frame does not imply one-frame total buffering.
- Neither tested single-threaded encoder sustains 1080p30 on all workloads. VP8 produces about 2.6–4.4 FPS; AV1 with assembly about 4.3–26.7 FPS. Multi-threaded AV1 results are documented in the [thread scaling experiment](../ryzen-9600x-threads/RESULTS.md). Other presets remain separate experiments, supported by CLI options.
- Mean decode speed hides keyframe spikes. Rust-only AV1 has some 1080p decode calls over 33 ms; all measured assembly-enabled AV1 decode calls stay under 33 ms on this host. This is not evidence of ARM64 Mac performance.
- Packet sizes and decoded checksums match across all six runs, including both variants. This establishes deterministic reconstruction for these fixtures, not general codec conformance.
- The video workload is synthetic; the text is bitmap text. Quality is PSNR, not a visual readability assessment. Static frames are intentionally encoded rather than suppressed.

## Reproduce and inspect

```sh
PATH=/tmp/esp-codec-bench-nasm/local/bin:$PATH \
  tools/codec-bench/run-ablation.sh tools/codec-bench/results/ryzen-9600x \
  --frames 60 --warmup 3 --threads 1
```

The private NASM 3.01 path is specific to this run; on another x86 host put NASM on PATH. No codec packages were installed. Both executables link only the normal system runtime libraries, not system codec libraries.

Raw per-frame JSON reports, generated timing tables, and encoded streams are local artifacts and are excluded from version control. Run the commands above to regenerate reports, then use `summarize.py` to inspect median per-case timings. Configuration and timing definitions are in the [benchmark README](../../README.md).

The initial shell wrapper reported an end-of-run parse error because it was edited while running. All six executable runs had already completed and written their 16 successful cases each; those counts and records were checked independently. The current wrapper is syntax-checked and is verified again by the replay run. This error did not interrupt a timed case.

The measured suite used the published rav1d 1.1.0 package. ARM64 build checking then exposed its missing assembly header. The final manifest pins its exact release commit (`782dab2135ea64a057c097088a13eb8ed3cc3320`), which contains the header. All 163 common Rust/assembly source files are byte-identical; host packets are replayed using the final dependency source. No algorithm or settings changed.

## Final verification

- Release tests pass for both variants (fixture determinism, statistics, inter-frame round trips, archive/replay equivalence and malformed archive handling).
- Both `aarch64-apple-darwin` variants pass `cargo check`; the assembly check also successfully builds the ARM assembly using Clang. This is not a native Mac link/runtime test.
- The final pinned-source decoder variants replayed the host's 16 exported assembly-suite streams: 960 frames each, 1,920 total. Every reconstructed checksum matches the source run. Replay reports are retained locally and excluded from version control.
- The current ablation/replay wrapper exits successfully. A separate forced-timeout test confirms it kills the worker, saves the error and returns failure.
- Formatting, Clippy with warnings denied, and shell/Python helper syntax checks pass.

On the Mac, use `replay-corpus.sh` for the host-to-client experiment first; use
`run-ablation.sh` for a full local encode/decode comparison. See the
[portable harness instructions](../../README.md). Actual Mac timings remain pending.
