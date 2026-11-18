#!/usr/bin/env bash
# Build the Pixel 6a physical runtime rehearsal and optionally boot it without
# flashing a partition. The image is injected into the exact stock PE carrier;
# no Pixel device driver is built by this script.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

STOCK_IMAGE="${PIXEL6A_STOCK_IMAGE:?set PIXEL6A_STOCK_IMAGE to the matching stock kernel Image}"
STOCK_BOOT="${PIXEL6A_STOCK_BOOT:?set PIXEL6A_STOCK_BOOT to the matching stock boot.img}"
OUT="${PIXEL6A_RUNTIME_OUT:-$ROOT/evidence/pixel6a-runtime-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${PIXEL6A_RUNTIME_TARGET:-$ROOT/target/pixel6a-runtime}"
LZ4="${PIXEL6A_LZ4:?set PIXEL6A_LZ4 to a compatible lz4 executable}"
MKBOOTIMG="${PIXEL6A_MKBOOTIMG:?set PIXEL6A_MKBOOTIMG to a compatible mkbootimg executable}"
FASTBOOT="${PIXEL6A_FASTBOOT:?set PIXEL6A_FASTBOOT to an Android platform-tools fastboot binary}"
ADB="${PIXEL6A_ADB:-adb}"
ELF="${PIXEL6A_RUNTIME_ELF:-$TARGET/aarch64-unknown-none-softfloat/release/jasper-kernel}"
FEATURES="${PIXEL6A_RUNTIME_FEATURES:-pixel6a-runtime-verify}"

for path in "$STOCK_IMAGE" "$STOCK_BOOT" "$LZ4" "$MKBOOTIMG"; do
    [ -f "$path" ] || {
        echo "pixel6a-runtime: missing input $path" >&2
        exit 2
    }
done
[ -x "$FASTBOOT" ] || {
    echo "pixel6a-runtime: fastboot is not executable: $FASTBOOT" >&2
    exit 2
}
if [ -n "${PIXEL6A_FASTBOOT_LIBS:-}" ]; then
    export LD_LIBRARY_PATH="$PIXEL6A_FASTBOOT_LIBS${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

mkdir -p "$OUT"

if [ "${PIXEL6A_SKIP_BUILD:-0}" != 1 ]; then
    env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" \
        build --locked --release --target-dir "$TARGET" \
        --target aarch64-unknown-none-softfloat \
        -p jasper-kernel --no-default-features \
        --features "$FEATURES" \
        >"$OUT/kernel-build.log" 2>&1
fi
[ -f "$ELF" ] || {
    echo "pixel6a-runtime: missing kernel ELF $ELF" >&2
    exit 2
}

IMAGE="$OUT/pixel6a-runtime-Image"
PAYLOAD="$OUT/pixel6a-runtime-kernel-Image"
COMPRESSED="$OUT/pixel6a-runtime-kernel-Image.lz4"
PARTIAL_BOOT="$OUT/pixel6a-runtime-payload.img"
BOOT="$OUT/pixel6a-runtime-boot.img"

bash "$ROOT/scripts/aarch64-image.sh" "$ELF" "$IMAGE" >"$OUT/image.log" 2>&1

python3 - "$STOCK_IMAGE" "$IMAGE" "$PAYLOAD" <<'PY'
import struct
import sys

stock_path, jasper_path, output_path = sys.argv[1:]
offset = 0x2000000
section_index = 1
stock = bytearray(open(stock_path, "rb").read())
payload = open(jasper_path, "rb").read()
code0 = struct.unpack_from("<I", payload, 0)[0]
if code0 & 0xFC000000 != 0x14000000:
    raise SystemExit("Jasper Image code0 is not a branch")
branch_words = code0 & 0x03FFFFFF
if branch_words & (1 << 25):
    branch_words -= 1 << 26
entry_rel = branch_words * 4
if entry_rel <= 0 or entry_rel >= 0x4000:
    raise SystemExit(f"Jasper Image branch target is outside bounded text: 0x{entry_rel:x}")

pe = struct.unpack_from("<I", stock, 0x3C)[0]
optional_size = struct.unpack_from("<H", stock, pe + 20)[0]
section = pe + 24 + optional_size + section_index * 40
section_va = struct.unpack_from("<I", stock, section + 12)[0]
section_raw_size = struct.unpack_from("<I", stock, section + 16)[0]
payload_end = offset + len(payload)
original_size = struct.unpack_from("<I", stock, pe + 24 + 56)[0]
required_size = max(original_size, (payload_end + 0xFFFF) & ~0xFFFF)
if len(stock) < required_size:
    stock.extend(b"\0" * (required_size - len(stock)))

needed_size = (payload_end - section_va + 0xFFFF) & ~0xFFFF
if needed_size > section_raw_size:
    struct.pack_into("<I", stock, section + 8, needed_size)
    struct.pack_into("<I", stock, section + 16, needed_size)
struct.pack_into("<I", stock, pe + 24 + 16, offset + entry_rel)
struct.pack_into("<I", stock, pe + 24 + 56, required_size)
struct.pack_into("<Q", stock, 0x10, required_size)
initialized = struct.unpack_from("<I", stock, pe + 24 + 8)[0]
if needed_size > section_raw_size:
    struct.pack_into("<I", stock, pe + 24 + 8, initialized + needed_size - section_raw_size)
characteristics = struct.unpack_from("<I", stock, section + 36)[0]
struct.pack_into("<I", stock, section + 36, characteristics | 0x80000000 | 0x20000000)
stock[offset : offset + len(payload)] = payload
open(output_path, "wb").write(stock)
print(
    f"patched PE entry=RVA 0x{offset + entry_rel:x} "
    f"payload={len(payload)} bytes size=0x{required_size:x}"
)
PY

"$LZ4" -l -9 -f "$PAYLOAD" "$COMPRESSED" >"$OUT/lz4.log" 2>&1
"$MKBOOTIMG" --header_version 4 --pagesize 4096 \
    --kernel "$COMPRESSED" --output "$PARTIAL_BOOT" >"$OUT/mkbootimg.log" 2>&1

cp "$STOCK_BOOT" "$BOOT"
payload_bytes=$(stat -c %s "$PARTIAL_BOOT")
dd if="$PARTIAL_BOOT" of="$BOOT" bs=4096 \
    count=$(((payload_bytes + 4095) / 4096)) conv=notrunc status=none

sha256sum "$ELF" "$IMAGE" "$BOOT" >"$OUT/artifacts.sha256"
echo "pixel6a-runtime: image PASS output=$OUT boot=$BOOT"

if [ "${PIXEL6A_BOOT:-0}" != 1 ]; then
    exit 0
fi

adb_count=$("$ADB" devices | awk 'NR > 1 && $2 == "device" { count++ } END { print count + 0 }')
[ "$adb_count" -eq 1 ] || {
    echo "pixel6a-runtime: expected exactly one Android ADB device, found $adb_count" >&2
    exit 75
}
"$ADB" shell getprop ro.product.device | grep -qx bluejay
"$ADB" reboot bootloader
fastboot_ready=0
for _ in $(seq 1 60); do
    if "$FASTBOOT" devices | grep -q .; then
        fastboot_ready=1
        break
    fi
    sleep 1
done
[ "$fastboot_ready" -eq 1 ] || {
    echo "pixel6a-runtime: device did not enter fastboot within 60s" >&2
    exit 1
}
"$FASTBOOT" getvar current-slot >"$OUT/preflight.txt" 2>&1
"$FASTBOOT" getvar unlocked >>"$OUT/preflight.txt" 2>&1

set +e
boot_start=$(date +%s.%N)
"$FASTBOOT" boot "$BOOT" >"$OUT/fastboot.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/fastboot.rc"
[ "$rc" -eq 0 ] || exit "$rc"

# A failed runtime halts with interrupts masked after disabling the UEFI
# watchdog. The success path is the only path that emits PSCI reset, so it must
# first leave fastboot and then reappear in fastboot within 30 seconds.
disconnected=0
for _ in $(seq 1 50); do
    if ! "$FASTBOOT" devices | grep -q .; then
        disconnected=1
        break
    fi
    sleep 0.2
done
[ "$disconnected" -eq 1 ] || {
    echo "pixel6a-runtime: image never left fastboot" >&2
    exit 1
}

returned=0
for _ in $(seq 1 150); do
    if "$FASTBOOT" devices | grep -q .; then
        returned=1
        break
    fi
    sleep 0.2
done
[ "$returned" -eq 1 ] || {
    echo "pixel6a-runtime: runtime did not reach PSCI reset within 30s" >&2
    exit 1
}
return_time=$(date +%s.%N)
awk -v s="$boot_start" -v n="$return_time" 'BEGIN { printf "runtime_return_seconds=%.2f\n", n-s }' |
    tee "$OUT/runtime-return.txt"

"$FASTBOOT" reboot >"$OUT/recovery.log" 2>&1
for _ in $(seq 1 90); do
    if "$ADB" devices | awk 'NR > 1 && $2 == "device" { found=1 } END { exit !found }' &&
        [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] &&
        "$ADB" shell getprop ro.product.device | grep -qx bluejay; then
        "$ADB" shell getprop ro.build.fingerprint >"$OUT/post-boot-fingerprint.txt"
        echo "pixel6a-runtime: DEVICE PASS runtime_reset=true android_recovered=true evidence=$OUT"
        exit 0
    fi
    sleep 1
done

echo "pixel6a-runtime: runtime reset observed but Android did not recover within 90s" >&2
exit 1
