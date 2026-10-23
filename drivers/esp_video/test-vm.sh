#!/bin/sh
# Load/test only inside a VM. No host driver load or host reboot.
set -eu
if [ "$#" -ne 2 ]; then
    echo "usage: $0 /path/to/kernel-image /path/to/matching/esp_video.ko" >&2
    exit 2
fi
kernel_image=$(realpath "$1")
module_file=$(realpath "$2")
test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
guest_dir=$(mktemp -d)
trap 'rm -rf "$guest_dir"' EXIT HUP INT TERM
mkdir "$guest_dir/root"
${CC:-cc} -static -O2 -Wall -Wextra $(pkg-config --cflags libdrm) \
    "$test_dir/test_guest.c" -o "$guest_dir/root/init"
cp "$module_file" "$guest_dir/root/esp_video.ko"
(cd "$guest_dir/root" && printf 'init\nesp_video.ko\n' | cpio -o -H newc) > "$guest_dir/initrd"
set -- "${QEMU:-qemu-system-x86_64}" -enable-kvm -cpu host -m 512M -smp 2 \
    -nodefaults -no-user-config -vga none -nic none -display none -serial stdio \
    -no-reboot -kernel "$kernel_image" -initrd "$guest_dir/initrd" \
    -append 'console=ttyS0 rdinit=/init panic=-1 loglevel=4'
if [ -n "${QEMU_DATA_DIR:-}" ]; then set -- "$@" -L "$QEMU_DATA_DIR"; fi
timeout 45 "$@" > "$guest_dir/log" 2>&1
cat "$guest_dir/log"
grep -q '^ESP_DRIVER_TEST_PASSED' "$guest_dir/log"
if grep -Eq 'BUG:|WARNING:|ESP_DRIVER_TEST_FAILED|Kernel panic' "$guest_dir/log"; then exit 1; fi
