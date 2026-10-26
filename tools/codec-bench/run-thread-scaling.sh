#!/bin/sh
# Fixed tile layout, varying worker budget. Runs serially to avoid contention.
# Usage: run-thread-scaling.sh RESULT_DIRECTORY [benchmark options]
set -eu
bench_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
result_dir=${1:-"$bench_dir/results/thread-scaling"}
if [ "$#" -gt 0 ]; then shift; fi
mkdir -p "$result_dir"
result_dir=$(CDPATH= cd -- "$result_dir" && pwd)
rounds=${BENCH_REPEATS:-3}
case "$rounds" in ''|*[!0-9]*) echo 'BENCH_REPEATS must be a positive integer' >&2; exit 2 ;; esac
[ "$rounds" -gt 0 ] || exit 2
cargo build --manifest-path "$bench_dir/Cargo.toml" --locked --release --target-dir "$bench_dir/target/rust"
cargo build --manifest-path "$bench_dir/Cargo.toml" --locked --release --features asm --target-dir "$bench_dir/target/asm"
failed=0
round=1
while [ "$round" -le "$rounds" ]; do
    if [ $((round % 2)) -eq 1 ]; then
        counts="1 2 4 6 12"
        variants="rust asm"
    else
        counts="12 6 4 2 1"
        variants="asm rust"
    fi
    for threads in $counts; do
        for variant in $variants; do
            "$bench_dir/target/$variant/release/esp-codec-bench" \
                --sizes 1920x1080 --codecs av1 --av1-tiles "${BENCH_TILES:-16}" \
                "$@" --threads "$threads" --repeats 1 \
                --output "$result_dir/$variant-t$threads-r$round.json" || failed=1
        done
    done
    round=$((round + 1))
done
printf '\nThread scaling results: %s\n' "$result_dir"
exit "$failed"
