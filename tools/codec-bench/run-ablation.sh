#!/bin/sh
# Run from any directory. First argument is the result directory; remaining
# arguments are forwarded to the benchmark. No sudo or machine configuration.
set -eu
bench_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
result_dir=${1:-"$bench_dir/results/local"}
if [ "$#" -gt 0 ]; then shift; fi
mkdir -p "$result_dir"
result_dir=$(CDPATH= cd -- "$result_dir" && pwd)
# Same compiler flags for both builds. Do not add target-cpu=native to just one.
cargo build --manifest-path "$bench_dir/Cargo.toml" --locked --release --target-dir "$bench_dir/target/rust"
cargo build --manifest-path "$bench_dir/Cargo.toml" --locked --release --features asm --target-dir "$bench_dir/target/asm"
round=1
rounds=${BENCH_REPEATS:-3}
case "$rounds" in ''|*[!0-9]*) echo 'BENCH_REPEATS must be a positive integer' >&2; exit 2 ;; esac
if [ "$rounds" -lt 1 ]; then echo 'BENCH_REPEATS must be positive' >&2; exit 2; fi
failed=0
while [ "$round" -le "$rounds" ]; do
    if [ $((round % 2)) -eq 1 ]; then variants="rust asm"; else variants="asm rust"; fi
    for variant in $variants; do
        "$bench_dir/target/$variant/release/esp-codec-bench" "$@" --repeats 1 \
            --export-streams "$result_dir/streams/$variant/round-$round" \
            --output "$result_dir/$variant-$round.json" || failed=1
    done
    round=$((round + 1))
done
printf '\nResults: %s\n' "$result_dir"
exit "$failed"
