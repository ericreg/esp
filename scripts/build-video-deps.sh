#!/bin/sh
# Build the pinned codec privately. No sudo, driver installation or reboot.
set -eu
if [ "$#" -ne 1 ]; then
    echo "usage: $0 /absolute/install/prefix" >&2
    exit 2
fi
case "$1" in /*) prefix=$1 ;; *) echo "prefix must be absolute" >&2; exit 2 ;; esac
vpx_commit=1024874c5919305883187e2953de8fcb4c3d7fa6
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
git -C "$build_dir" init -q
git -C "$build_dir" fetch --depth 1 https://chromium.googlesource.com/webm/libvpx "$vpx_commit"
git -C "$build_dir" checkout --detach FETCH_HEAD
test "$(git -C "$build_dir" rev-parse HEAD)" = "$vpx_commit"
cd "$build_dir"
./configure --prefix="$prefix" --target=generic-gnu --disable-examples \
    --disable-tools --disable-docs --disable-unit-tests --disable-vp9 \
    --disable-shared --enable-pic
make -j "${ESP_VIDEO_BUILD_JOBS:-4}"
make install
printf '\nCodec installed. Build ESP with PKG_CONFIG_PATH=%s/lib/pkgconfig\n' "$prefix"
