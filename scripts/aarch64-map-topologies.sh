#!/usr/bin/env bash
# Verify one AArch64 image discovers distinct direct-map/RAM facts under
# multiple QEMU memory topologies, including one above the former 4 GiB bound.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${AARCH64_MAP_OUT:-$ROOT/evidence/aarch64-map-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${AARCH64_MAP_TARGET:-/tmp/jasper-hc05-target}"
MEMORY_MIB="${AARCH64_MAP_MIB:-128 1024 5120}"
CPUS="${AARCH64_MAP_CPUS:-4-7}"
TIMEOUT="${AARCH64_MAP_TIMEOUT:-120}"
IMAGE="$OUT/jasper-image"
mkdir -p "$OUT"

CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  -p jasper-kernel --target aarch64-unknown-none-softfloat --no-default-features \
  >"$OUT/build.log" 2>&1
bash scripts/aarch64-image.sh \
  "$TARGET/aarch64-unknown-none-softfloat/release/jasper-kernel" "$IMAGE" \
  >"$OUT/image.log" 2>&1
sha256sum "$IMAGE" >"$OUT/image.sha256"

FACTS=""
for mib in $MEMORY_MIB; do
  case "$mib" in
    ''|*[!0-9]*) echo "invalid AARCH64_MAP_MIB entry: $mib" >&2; exit 2 ;;
  esac
  RUN="$OUT/${mib}M"
  mkdir -p "$RUN"
  exec 9>/tmp/jasper-os-qemu.lock
  flock 9
  set +e
  nice -n 10 taskset -c "$CPUS" timeout "$TIMEOUT" qemu-system-aarch64 \
    -M virt -cpu cortex-a72 -m "${mib}M" -kernel "$IMAGE" \
    -append "console=ttyAMA0" -semihosting \
    -serial "file:$RUN/serial.log" -display none -monitor none -no-reboot \
    >"$RUN/qemu.log" 2>&1
  RC=$?
  set -e
  flock -u 9
  exec 9>&-
  printf 'memory_mib=%s qemu_rc=%s\n' "$mib" "$RC" >"$RUN/summary.txt"
  grep -a '^\[JSR-DTB\] memory=' "$RUN/serial.log" | tee -a "$RUN/summary.txt"
  grep -a '^\[JSR-FRAME\] regions=' "$RUN/serial.log" | tee -a "$RUN/summary.txt"
  grep -a '^\[JSR-FRAME\] alloc frames=3 addrs=0x40000000' "$RUN/serial.log" \
    >>"$RUN/summary.txt"
  usable="$(sed -n 's/^\[JSR-FRAME\].*usable_mib=\([0-9][0-9]*\).*/\1/p' "$RUN/serial.log")"
  test -n "$usable"
  FACTS="${FACTS}${mib}:${usable} "
done

requested="$(printf '%s\n' $MEMORY_MIB | sort -nu | wc -l)"
distinct="$(printf '%s\n' $FACTS | awk -F: '{print $2}' | sort -nu | wc -l)"
if [ "$requested" -ne "$distinct" ]; then
  echo "AArch64 memory discovery produced identical facts for distinct topologies" >&2
  exit 1
fi
printf '%s\n' $FACTS | tee "$OUT/memory-facts.txt"

echo "aarch64-map-topologies: PASS evidence=$OUT"
