#!/usr/bin/env python3
"""Print medians across repeated cases. Python stdlib only; accepts report files."""
import argparse
import collections
import json
import statistics

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("reports", nargs="+")
args = parser.parse_args()
groups = collections.defaultdict(list)
failures = []
for path in args.reports:
    with open(path) as f:
        report = json.load(f)
    for case in report["cases"]:
        req, result = case["request"], case["result"]
        s = req["settings"]
        key = (report["cpu"], "asm" if report["assembly_enabled"] else "rust",
               req["codec"], f'{s["width"]}x{s["height"]}', req["workload"], s["threads"],
               s["vp8_q"], s["av1_q"], s["av1_speed"], req["frames"], s["fps"],
               s.get("av1_tiles", 0), "decode-only" if req["replay"] else "encode-decode")
        if result is None:
            failures.append((key, case["error"]))
        else:
            groups[key].append(result)
print("| CPU | Variant | Codec | Q / speed | Size | Workload | Threads | Tile target | Frames / target FPS | N | Encode FPS | Decode FPS | Enc p95 ms | Dec p95 ms | Mbps | PSNR-Y dB | Buffered frames |")
print("|---|---|---|---|---|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|")
for key, rows in sorted(groups.items()):
    def med(field, nested=None):
        values = [r[field][nested] if nested else r[field] for r in rows]
        return statistics.median(float("inf") if v is None else v for v in values)
    cpu, variant, codec, size, work, threads, *_ = key
    quality = f"{key[6]} / —" if codec == "vp8" else f"{key[7]} / {key[8]}"
    enc = "—" if key[-1] == "decode-only" else f'{med("encode_fps"):.1f}'
    print(f'| {cpu} | {variant} | {codec} | {quality} | {size} | {work} | {threads} | {key[11]} | {key[9]} / {key[10]} | {len(rows)} | {enc} | '
          f'{med("decode_fps"):.1f} | {med("encode_call_ms", "p95"):.1f} | '
          f'{med("decode_ms", "p95"):.1f} | {med("bitrate_mbps_at_target_fps"):.3f} | '
          f'{med("psnr_y_db"):.2f} | {med("max_additional_inputs_before_packet"):.0f} |')
for key, error in failures:
    print(f"\nFAILED {key}: {error}")
