#!/usr/bin/env bash
# Run PEX-4 selection-path density and latency measurements on host KVM.
# 在宿主 KVM 上运行 PEX-4 选择路径密度与延迟测量。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PEX4_IMAGE:?set PEX4_IMAGE to the image produced by pex4-build.sh}"
OUT="${PEX4_OUT:-$ROOT/evidence/pex4-kvm-$(date '+%Y%m%d-%H%M%S')}"
CORES="${PEX4_CPUS:-4-11}"
SMPS="${PEX4_SMPS:-1,2,4,8}"
ROUNDS="${PEX4_ROUNDS:-3}"
TIMEOUT="${PEX4_TIMEOUT:-300}"

mkdir -p "$OUT"
test -s "$IMAGE" || {
  echo "PEX-4: image is missing or empty: $IMAGE" >&2
  exit 2
}
if pgrep -f '[q]emu-system-' >/dev/null; then
  echo "PEX-4: another QEMU is running; refusing contaminated evidence" >&2
  exit 2
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "PEX-4: /dev/kvm is required; TCG is not performance evidence" >&2
  exit 2
fi

exec flock /tmp/jasper-full.lock \
  python3 "$ROOT/scripts/pex4-matrix.py" \
    --image "$IMAGE" \
    --out "$OUT" \
    --cpus "$CORES" \
    --smps "$SMPS" \
    --rounds "$ROUNDS" \
    --timeout "$TIMEOUT"
