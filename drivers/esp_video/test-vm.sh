#!/bin/sh
# Load/test only inside a VM. No host driver load or host reboot.
set -eu
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 /path/to/kernel-image /path/to/matching/esp_video.ko [Rust-test-executable]" >&2
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
if [ "$#" -eq 3 ]; then
    cp "$3" "$guest_dir/root/console-test"
    ldd "$3" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' > "$guest_dir/libs"
    while IFS= read -r lib; do
        mkdir -p "$guest_dir/root$(dirname "$lib")"
        cp "$lib" "$guest_dir/root$lib"
    done < "$guest_dir/libs"
    uinput_module="$(dirname "$kernel_image")/kernel/drivers/input/misc/uinput.ko.zst"
    zstd -dc "$uinput_module" > "$guest_dir/root/uinput.ko"
fi
(cd "$guest_dir/root" && find . -print | cpio -o -H newc) > "$guest_dir/initrd"
set -- "${QEMU:-qemu-system-x86_64}" -enable-kvm -cpu host -m 512M -smp 2 \
    -nodefaults -no-user-config -vga none -nic none -display none -serial stdio \
    -no-reboot -kernel "$kernel_image" -initrd "$guest_dir/initrd" \
    -append 'console=ttyS0 rdinit=/init panic=-1 loglevel=4 esp_console_test=1'
if [ -n "${QEMU_DATA_DIR:-}" ]; then set -- "$@" -L "$QEMU_DATA_DIR"; fi
vm_status=0
timeout 45 "$@" > "$guest_dir/log" 2>&1 || vm_status=$?
cat "$guest_dir/log"
[ "$vm_status" -eq 0 ] || exit "$vm_status"
grep -q '^ESP_DRIVER_TEST_PASSED' "$guest_dir/log"
if grep -Eq 'BUG:|WARNING:|ESP_DRIVER_TEST_FAILED|Kernel panic' "$guest_dir/log"; then exit 1; fi
