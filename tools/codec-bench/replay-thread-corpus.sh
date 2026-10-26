#!/bin/sh
# Decode the same host packets at 1/2/4/6/12 threads, assembly off/on.
set -eu
bench_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -lt 2 ]; then
    echo 'usage: replay-thread-corpus.sh CORPUS_DIRECTORY RESULT_DIRECTORY [benchmark options]' >&2
    exit 2
fi
corpus=$1
results=$2
shift 2
found=0
for file in "$corpus"/*.espbench; do
    [ -f "$file" ] || continue
    set -- "$@" --decode-stream "$file"
    found=1
done
if [ "$found" -eq 0 ]; then echo "No .espbench files in $corpus" >&2; exit 2; fi
exec "$bench_dir/run-thread-scaling.sh" "$results" "$@"
