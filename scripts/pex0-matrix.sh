#!/usr/bin/env bash
# Build one image and run the PEX-0 matrix on an otherwise idle host.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

CORES="${PEX0_CPUS:-4-11}"
ROUNDS="${PEX0_ROUNDS:-3}"
SMPS="${PEX0_SMPS:-1,2,4,8}"
TIMEOUT="${PEX0_TIMEOUT:-300}"
IDLE_WAIT="${PEX0_IDLE_WAIT:-60}"
OUT="${PEX0_OUT:-$ROOT/evidence/pex0-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target/pex0}"
IMAGE="${PEX0_IMAGE:-$OUT/kernel.img}"
XTASK="${PEX0_XTASK:-$ROOT/target/release/xtask}"

mkdir -p "$OUT"
if pgrep -f '[q]emu-system-' >/dev/null; then
  echo "PEX-0: another QEMU is running; refusing a contaminated measurement" >&2
  exit 2
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "PEX-0: /dev/kvm is required; TCG is not performance evidence" >&2
  exit 2
fi

if [ -z "${PEX0_IMAGE:-}" ]; then
  CARGO_TARGET_DIR="$TARGET" taskset -c "$CORES" cargo build --locked --release \
    --target x86_64-unknown-none -p jasper-kernel --features pex0-verify \
    >"$OUT/build.log" 2>&1
  if [ ! -x "$XTASK" ]; then
    taskset -c "$CORES" cargo build --locked --release -p xtask \
      >>"$OUT/build.log" 2>&1
    XTASK="$ROOT/target/release/xtask"
  fi
  "$XTASK" "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$IMAGE" \
    >"$OUT/image.log" 2>&1
fi

python3 scripts/pex0-matrix.py \
  --image "$IMAGE" \
  --out "$OUT" \
  --rounds "$ROUNDS" \
  --smps "$SMPS" \
  --cpus "$CORES" \
  --idle-wait-seconds "$IDLE_WAIT" \
  ${PEX0_RESUME:+--resume} \
  --timeout "$TIMEOUT"
