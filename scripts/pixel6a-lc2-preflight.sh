#!/usr/bin/env bash
# Read-only Pixel 6a preflight for the LC-2 physical install matrix.
# 该脚本只记录 Android、slot、AVB 与 fastboot 分区事实；不执行 flash/erase。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADB="${PIXEL6A_ADB:-adb}"
FASTBOOT="${PIXEL6A_FASTBOOT:?set PIXEL6A_FASTBOOT to an Android platform-tools fastboot binary}"
OUT="${PIXEL6A_PREFLIGHT_OUT:-$ROOT/evidence/pixel6a-lc2-preflight-$(date '+%Y%m%d-%H%M%S')}"
TIMEOUT="${PIXEL6A_PREFLIGHT_TIMEOUT:-120}"

mkdir -p "$OUT"

wait_for_android() {
    local limit=$1
    for _ in $(seq 1 "$limit"); do
        if "$ADB" devices | awk 'NR > 1 && $2 == "device" { found=1 } END { exit !found }' &&
            [ "$("$ADB" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

if [ -z "${PIXEL6A_SERIAL:-}" ]; then
    mapfile -t DEVICES < <("$ADB" devices | awk 'NR > 1 && $2 == "device" { print $1 }')
    [ "${#DEVICES[@]}" -eq 1 ] || {
        echo "pixel6a-lc2-preflight: expected exactly one ADB device, found ${#DEVICES[@]}" >&2
        exit 75
    }
    SERIAL="${DEVICES[0]}"
else
    SERIAL="$PIXEL6A_SERIAL"
fi

if [ -n "${PIXEL6A_FASTBOOT_LIBS:-}" ]; then
    export LD_LIBRARY_PATH="$PIXEL6A_FASTBOOT_LIBS${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
[ -x "$FASTBOOT" ] || {
    echo "pixel6a-lc2-preflight: fastboot is not executable: $FASTBOOT" >&2
    exit 2
}
wait_for_android "$TIMEOUT" || {
    echo "pixel6a-lc2-preflight: Android did not reach boot_completed=1" >&2
    exit 1
}

product=$("$ADB" -s "$SERIAL" shell getprop ro.product.device | tr -d '\r')
[ "$product" = bluejay ] || {
    echo "pixel6a-lc2-preflight: expected bluejay, found $product" >&2
    exit 1
}

{
    echo "serial=$SERIAL"
    echo "product=$product"
    echo "fingerprint=$("$ADB" -s "$SERIAL" shell getprop ro.build.fingerprint | tr -d '\r')"
    echo "release=$("$ADB" -s "$SERIAL" shell getprop ro.build.version.release | tr -d '\r')"
    echo "sdk=$("$ADB" -s "$SERIAL" shell getprop ro.build.version.sdk | tr -d '\r')"
    echo "slot=$("$ADB" -s "$SERIAL" shell getprop ro.boot.slot_suffix | tr -d '\r')"
    echo "verifiedbootstate=$("$ADB" -s "$SERIAL" shell getprop ro.boot.verifiedbootstate | tr -d '\r')"
    echo "flash_locked=$("$ADB" -s "$SERIAL" shell getprop ro.boot.flash.locked | tr -d '\r')"
    echo "boot_completed=$("$ADB" -s "$SERIAL" shell getprop sys.boot_completed | tr -d '\r')"
    "$ADB" -s "$SERIAL" shell df -k /data | awk 'NR == 2 { print "data_available_kib=" $4 }'
    "$ADB" -s "$SERIAL" shell ls -l /dev/block/by-name |
        awk '$NF ~ /\/(userdata|metadata|super|boot_a|boot_b)$/ { print "android_partition=" $NF }' |
        sed "s#/dev/block/by-name/##"
} >"$OUT/android-before.txt"

IN_FASTBOOT=0
restore_android() {
    if [ "$IN_FASTBOOT" -eq 1 ]; then
        "$FASTBOOT" -s "$SERIAL" reboot >/dev/null 2>&1 || true
    fi
    wait_for_android "$TIMEOUT" || true
}
trap restore_android EXIT

"$ADB" -s "$SERIAL" reboot bootloader
for _ in $(seq 1 60); do
    if "$FASTBOOT" -s "$SERIAL" devices | grep -q "$SERIAL"; then
        IN_FASTBOOT=1
        break
    fi
    sleep 1
done
[ "$IN_FASTBOOT" -eq 1 ] || {
    echo "pixel6a-lc2-preflight: device did not enter fastboot" >&2
    exit 1
}

{
    echo "serial=$SERIAL"
    for var in product current-slot unlocked is-userspace \
        partition-size:userdata partition-size:metadata partition-size:super \
        partition-size:boot_a partition-size:boot_b; do
        echo "getvar:$var=$("$FASTBOOT" -s "$SERIAL" getvar "$var" 2>&1 | tr '\n' ' ')"
    done
} >"$OUT/fastboot-state.txt"

IN_FASTBOOT=1
"$FASTBOOT" -s "$SERIAL" reboot >"$OUT/reboot.log" 2>&1
wait_for_android "$TIMEOUT" || {
    echo "pixel6a-lc2-preflight: Android did not recover after fastboot reboot" >&2
    exit 1
}
IN_FASTBOOT=0

"$ADB" -s "$SERIAL" shell getprop ro.build.fingerprint >"$OUT/android-after.txt"
"$ADB" -s "$SERIAL" shell getprop ro.boot.slot_suffix >>"$OUT/android-after.txt"
"$ADB" -s "$SERIAL" shell getprop sys.boot_completed >>"$OUT/android-after.txt"

cat >"$OUT/README.md" <<EOF
# Pixel 6a LC-2 preflight

Date: $(date '+%Y-%m-%d')

This run performed no \`flash\`, \`erase\`, or persistent partition write.
It recorded the Android build/slot/AVB state, fastboot-visible partition sizes,
and verified that a fastboot round trip returned to \`boot_completed=1\`.

Persistent LC-2 installation still requires a public UFS access backend in the
Driver Host. This preflight is not an install, update, rollback, or power-loss
acceptance result.
EOF

echo "pixel6a-lc2-preflight: PASS evidence=$OUT"
