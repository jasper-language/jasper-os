#!/usr/bin/env bash
# Run PEX-7 real frame allocation on host KVM CPUs 4-11.
# 在宿主 KVM CPU 4-11 上运行 PEX-7 真实页帧分配矩阵。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PEX7_IMAGE:?set PEX7_IMAGE to the image produced by pex7-kernel-build.sh}"
OUT="${PEX7_OUT:-$ROOT/evidence/pex7-kernel-$(date '+%Y%m%d-%H%M%S')}"
CORES="${PEX7_CPUS:-4-11}"
SMPS="${PEX7_SMPS:-1,2,4,8}"
ROUNDS="${PEX7_ROUNDS:-3}"
TIMEOUT="${PEX7_TIMEOUT:-300}"

mkdir -p "$OUT"
test -s "$IMAGE" || {
  echo "PEX-7: image is missing or empty: $IMAGE" >&2
  exit 2
}
if pgrep -f '[q]emu-system-' >/dev/null; then
  echo "PEX-7: another QEMU is running; refusing contaminated evidence" >&2
  exit 2
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "PEX-7: /dev/kvm is required; TCG is not performance evidence" >&2
  exit 2
fi

exec flock /tmp/jasper-full.lock \
  python3 "$ROOT/scripts/pex7-kernel-matrix.py" \
    --image "$IMAGE" \
    --out "$OUT" \
    --cpus "$CORES" \
    --smps "$SMPS" \
    --rounds "$ROUNDS" \
    --timeout "$TIMEOUT"
