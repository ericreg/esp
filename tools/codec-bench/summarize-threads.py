#!/usr/bin/env python3
"""Summarize a fixed-layout threading sweep, including CPU use and scaling."""
import argparse
import collections
import json
import statistics

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("reports", nargs="+")
a = p.parse_args()
groups = collections.defaultdict(list)
references = {}
changed = []
for path in a.reports:
    with open(path) as f:
        report = json.load(f)
    for case in report["cases"]:
        if case["error"]:
            raise SystemExit(f'{path}: {case["error"]}')
        q, m = case["request"], case["result"]
        s = q["settings"]
        if q["codec"] != "av1" or m["mode"] != "encode-decode":
            raise SystemExit("Expected AV1 encode/decode cases")
        # Include full measurement settings so unlike experiments never merge.
        base = (report["cpu"], s["width"], s["height"], s.get("av1_tiles", 0),
                s["av1_q"], s["av1_speed"], s["fps"], q["frames"], q["warmup"])
        variant = "asm" if report["assembly_enabled"] else "rust"
        groups[base, variant, q["workload"], s["threads"]].append(m)
        identity = (base, q["workload"])
        output = [(f["bytes"], f["decoded_checksum"], f.get("tile_grid")) for f in m["samples"]]
        if identity in references and references[identity] != output:
            changed.append((path, q["workload"]))
        references[identity] = output

last_base = None
for key in sorted(groups):
    base, variant, work, threads = key
    if base != last_base:
        print(f"\nCPU: {base[0]}; {base[1]}×{base[2]}, tile target {base[3]}, q{base[4]}, speed {base[5]}, "
              f"{base[7]} frames at {base[6]} FPS, {base[8]} warmup frames.\n")
        print("| Variant | Workload | Threads | Grid | Runs | Enc FPS | Speedup vs 1T | Enc p95 ms | Enc CPU cores | Dec FPS | Dec p95 ms | Dec CPU cores | Mbps | PSNR-Y | Buffer frames |")
        print("|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        last_base = base
    rows = groups[key]
    def med(field, nested=None):
        values = [r[field][nested] if nested else r[field] for r in rows]
        return statistics.median(float("inf") if v is None else v for v in values)
    control = groups.get((base, variant, work, 1))
    speedup = med("encode_fps") / statistics.median(r["encode_fps"] for r in control) if control else float("nan")
    cores = statistics.median(r["encode_cpu_ms"] / r["encode_total_ms"] for r in rows)
    dec_cores = statistics.median(r["decode_cpu_ms"] / r["decode_total_ms"] for r in rows)
    grid = rows[0]["samples"][0].get("tile_grid")
    print(f'| {variant} | {work} | {threads} | {grid} | {len(rows)} | {med("encode_fps"):.1f} | '
          f'{speedup:.2f}× | {med("encode_call_ms", "p95"):.1f} | {cores:.2f} | {med("decode_fps"):.1f} | '
          f'{med("decode_ms", "p95"):.1f} | {dec_cores:.2f} | {med("bitrate_mbps_at_target_fps"):.3f} | '
          f'{med("psnr_y_db"):.2f} | {med("max_additional_inputs_before_packet"):.0f} |')
print("\nOutput consistency:", "All thread counts, assembly variants and repeats have matching packet sizes, decoded checksums and tile grids." if not changed else f"Differences detected: {changed}")
