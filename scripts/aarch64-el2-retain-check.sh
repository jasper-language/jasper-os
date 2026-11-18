#!/usr/bin/env bash
# Verify that AArch64 keeps a resident EL2 handler while the kernel runs at EL1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"

OUT="${AARCH64_EL2_OUT:-$ROOT/evidence/aarch64-el2-retain-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${AARCH64_EL2_TARGET:-$ROOT/target/aarch64-el2-retain}"
IMAGE="$OUT/jasper-Image"
ELF="$TARGET/aarch64-unknown-none-softfloat/release/jasper-kernel"
LIMIT="${AARCH64_EL2_TIMEOUT:-30}"
QEMU_CPUS="${AARCH64_EL2_QEMU_CPUS:-6-7}"
mkdir -p "$OUT" "$TARGET"

QEMU="$(command -v qemu-system-aarch64 || true)"
[ -n "$QEMU" ] || {
  echo "aarch64-el2-retain: qemu-system-aarch64 is unavailable" >&2
  exit 75
}

env -u CARGO_TARGET_DIR \
  JASPER_BUILD_ALLOW_VBOX="${JASPER_BUILD_ALLOW_VBOX:-0}" \
  JASPER_BUILD_CPUS="${JASPER_BUILD_CPUS:-4-7}" \
  "$ROOT/scripts/guarded-cargo.sh" build --locked --release \
  --target-dir "$TARGET" --target aarch64-unknown-none-softfloat \
  -p jasper-kernel --no-default-features \
  --features aarch64-el2-retain-verify >"$OUT/build.log" 2>&1

bash scripts/aarch64-image.sh "$ELF" "$IMAGE" >"$OUT/image.log" 2>&1

set +e
timeout "$LIMIT" taskset -c "$QEMU_CPUS" "$QEMU" \
  -M virt,virtualization=on -cpu cortex-a72 -smp 2 -m 256M \
  -kernel "$IMAGE" -append "console=ttyAMA0 el2-retain=1" \
  -semihosting -serial stdio -display none -monitor none -no-reboot \
  >"$OUT/serial.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/qemu.rc"

grep -aFq \
  '[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true' \
  "$OUT/serial.log"
grep -aFq \
  '[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true vm_exit=true vcpu_context=true driver_vm=false' \
  "$OUT/serial.log"
grep -aFq \
  '[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0' \
  "$OUT/serial.log"

python3 - "$OUT/serial.log" "$rc" <<'PY'
import re
import sys
from pathlib import Path

log, rc = Path(sys.argv[1]), int(sys.argv[2])
text = log.read_text(errors="replace")
if rc != 35:
    raise SystemExit(f"aarch64-el2-retain: expected rc=35 with registered baseline, got {rc}")
line = next((item for item in text.splitlines() if "[JSR-EXIT] failure" in item), None)
if line is None:
    raise SystemExit("aarch64-el2-retain: missing structured failure line")
failed = {name: int(value) for name, value in re.findall(r"([a-z0-9_]+_failed)=(\d+)", line)}
expected = {"pci_failed": 3, "krn0_failed": 1}
if {name: value for name, value in failed.items() if value} != expected:
    raise SystemExit(f"aarch64-el2-retain: unexpected failure baseline: {failed}")
PY

echo "aarch64-el2-retain: PASS bsp=true ap=true hvc=true stage2=true vm_exit=true vcpu_context=true driver_vm=false evidence=$OUT"
