#!/usr/bin/env bash
# Build the Pixel 6a physical runtime rehearsal and optionally boot it without
# flashing a partition. The image is injected into the exact stock PE carrier;
# no Pixel device driver is built by this script.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

STOCK_IMAGE="${PIXEL6A_STOCK_IMAGE:-/home/auth/Documents/jasper/pixel6a-evidence/factory-image/kernel-Image}"
STOCK_BOOT="${PIXEL6A_STOCK_BOOT:-/home/auth/Documents/jasper/pixel6a-evidence/factory-image/boot.img}"
OUT="${PIXEL6A_RUNTIME_OUT:-$ROOT/evidence/pixel6a-runtime-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${PIXEL6A_RUNTIME_TARGET:-$ROOT/target/pixel6a-runtime}"
LZ4="${PIXEL6A_LZ4:-/home/auth/Documents/jasper/.tools/pixel6a-platform-tools/lz4/usr/bin/lz4}"
MKBOOTIMG="${PIXEL6A_MKBOOTIMG:-/home/auth/Documents/jasper/.tools/pixel6a-platform-tools/mkbootimg/usr/bin/mkbootimg}"
ELF="${PIXEL6A_RUNTIME_ELF:-$TARGET/aarch64-unknown-none-softfloat/release/jasper-kernel}"

for path in "$STOCK_IMAGE" "$STOCK_BOOT" "$LZ4" "$MKBOOTIMG"; do
    [ -f "$path" ] || {
        echo "pixel6a-runtime: missing input $path" >&2
        exit 2
    }
done

mkdir -p "$OUT"

if [ "${PIXEL6A_SKIP_BUILD:-0}" != 1 ]; then
    env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" \
        build --locked --release --target-dir "$TARGET" \
        --target aarch64-unknown-none-softfloat \
        -p jasper-kernel --no-default-features \
        --features pixel6a-runtime-verify \
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

# ABL invokes the PE entry on its selected boot CPU. The existing hardware
# probes accept any MPIDR.Aff0 by replacing only the bounded bootstrap gate.
python3 - "$IMAGE" <<'PY'
import sys

path = sys.argv[1]
data = bytearray(open(path, "rb").read())
pattern = bytes.fromhex("a90038d5291d4092")
entry = data.find(pattern, 0, 0x4000)
if entry < 0:
    raise SystemExit("Jasper _start MPIDR sequence not found")
if data[entry + 9 : entry + 12] != bytes.fromhex("0400b5"):
    raise SystemExit("unexpected MPIDR branch bytes; refusing blind patch")
data[entry + 8 : entry + 12] = bytes.fromhex("1f2003d5")
open(path, "wb").write(data)
print(f"entry_offset=0x{entry:x}")
PY

python3 - "$STOCK_IMAGE" "$IMAGE" "$PAYLOAD" <<'PY'
import struct
import sys

stock_path, jasper_path, output_path = sys.argv[1:]
offset = 0x2000000
section_index = 1
stock = bytearray(open(stock_path, "rb").read())
payload = open(jasper_path, "rb").read()
entry_rel = payload.find(bytes.fromhex("a90038d5291d4092"), 0, 0x4000)
if entry_rel < 0:
    raise SystemExit("patched Jasper entry not found")

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

adb_count=$(adb devices | awk 'NR > 1 && $2 == "device" { count++ } END { print count + 0 }')
[ "$adb_count" -eq 1 ] || {
    echo "pixel6a-runtime: expected exactly one Android ADB device, found $adb_count" >&2
    exit 75
}
adb shell getprop ro.product.device | grep -qx bluejay
adb reboot bootloader
timeout 60 bash -c 'until fastboot devices | grep -q .; do sleep 1; done'
fastboot getvar current-slot >"$OUT/preflight.txt" 2>&1
fastboot getvar unlocked >>"$OUT/preflight.txt" 2>&1

set +e
fastboot boot "$BOOT" >"$OUT/fastboot.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/fastboot.rc"
[ "$rc" -eq 0 ] || exit "$rc"

# The success contract is the runtime marker followed by PSCI reset and normal
# return to the same Android build. A failed kernel remains in fastboot or is
# returned there by the bootloader watchdog.
for _ in $(seq 1 90); do
    if adb devices | awk 'NR > 1 && $2 == "device" { found=1 } END { exit !found }' &&
        [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] &&
        adb shell getprop ro.product.device | grep -qx bluejay; then
        adb shell getprop ro.build.fingerprint >"$OUT/post-boot-fingerprint.txt"
        echo "pixel6a-runtime: DEVICE PASS android_returned=true evidence=$OUT"
        exit 0
    fi
    sleep 1
done

fastboot getvar current-slot >"$OUT/failure-state.txt" 2>&1 || true
echo "pixel6a-runtime: Android did not return within 90s; runtime failed" >&2
exit 1
