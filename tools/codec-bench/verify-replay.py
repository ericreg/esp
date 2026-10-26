#!/usr/bin/env python3
"""Verify a replay report reconstructs exactly the pixels in its source report."""
import argparse
import json

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source_report")
parser.add_argument("replay_report")
args = parser.parse_args()
with open(args.source_report) as f:
    source = json.load(f)
with open(args.replay_report) as f:
    replay = json.load(f)

def key(case):
    req = case["request"]
    s = req["settings"]
    return (req["codec"], req["workload"], req["frames"], s["width"], s["height"],
            s["fps"], s["vp8_q"], s["av1_q"], s["av1_speed"], s.get("av1_tiles", 0))

reference = {}
for case in source["cases"]:
    if case["result"] is None:
        raise SystemExit(f'Source contains a failed case: {case["error"]}')
    checksums = [s["decoded_checksum"] for s in case["result"]["samples"]]
    k = key(case)
    if k in reference and reference[k] != checksums:
        raise SystemExit(f"Source repeats disagree: {k}")
    reference[k] = checksums
frames = 0
seen = set()
for case in replay["cases"]:
    if case["result"] is None:
        raise SystemExit(f'Replay contains a failed case: {case["error"]}')
    if case["result"]["mode"] != "decode-only":
        raise SystemExit("Second report must be decode-only (same packets, not a re-encode)")
    k = key(case)
    if k not in reference:
        raise SystemExit(f"No source match for {k}")
    checksums = [s["decoded_checksum"] for s in case["result"]["samples"]]
    if checksums != reference[k]:
        raise SystemExit(f"Decoded pixel mismatch: {k}")
    frames += len(checksums)
    seen.add(k)
if not seen or seen != set(reference):
    raise SystemExit(f"Incomplete replay: {len(seen)} of {len(reference)} source cases")
print(f"Verified {frames} frames in {len(replay['cases'])} replay cases; all decoded checksums match.")
