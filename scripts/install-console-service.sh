#!/bin/sh
# Run explicitly as root after reviewing CONSOLE_SERVICE.md. Never reboots.
set -eu
if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 2 ]; then
    echo "usage: sudo $0 /path/to/network.yml PEER" >&2
    exit 2
fi
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
config=$(realpath "$1")
peer=$2
case "$peer" in *[!a-zA-Z0-9_.:-]*|'') echo 'Use a peer node ID or a simple peer name.' >&2; exit 2;; esac
if [ -e /var/lib/esp-console/network.yml ]; then
    echo 'Existing console identity preserved. Update it deliberately; installer will not overwrite it.' >&2
    exit 1
fi
"$repo/target/release/esp" video serve --help >/dev/null
install -d -m 700 /var/lib/esp-console
install -d -m 755 /etc/esp
install -d -m 755 /usr/local/bin
install -m 600 "$config" /var/lib/esp-console/network.yml
install -m 755 "$repo/target/release/esp" /usr/local/bin/esp.new
mv /usr/local/bin/esp.new /usr/local/bin/esp
printf 'ESP_CONSOLE_PEER=%s\nESP_CONSOLE_SOURCE=auto\nESP_CONSOLE_SIZE=1920x1080\n' "$peer" > /etc/esp/console.env
chmod 600 /etc/esp/console.env
install -m 644 "$repo/packaging/systemd/esp-console.service" /etc/systemd/system/esp-console.service
systemctl daemon-reload
printf '%s\n' 'Installed, not started. Ensure the network identity is not used by another daemon.' 'Load the matching ESP display module and uinput, then: systemctl enable --now esp-console.service'
