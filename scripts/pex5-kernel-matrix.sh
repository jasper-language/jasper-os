#!/usr/bin/env bash
# Run PEX-5 real-kernel growth on host KVM CPUs 4-11.
# 在宿主 KVM CPU 4-11 上运行 PEX-5 真实内核增长矩阵。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PEX5_IMAGE:?set PEX5_IMAGE to the image produced by pex5-kernel-build.sh}"
OUT="${PEX5_OUT:-$ROOT/evidence/pex5-kernel-$(date '+%Y%m%d-%H%M%S')}"
CORES="${PEX5_CPUS:-4-11}"
SMPS="${PEX5_SMPS:-1,2,4,8}"
ROUNDS="${PEX5_ROUNDS:-3}"
TIMEOUT="${PEX5_TIMEOUT:-300}"

mkdir -p "$OUT"
test -s "$IMAGE" || {
  echo "PEX-5: image is missing or empty: $IMAGE" >&2
  exit 2
}
if pgrep -f '[q]emu-system-' >/dev/null; then
  echo "PEX-5: another QEMU is running; refusing contaminated evidence" >&2
  exit 2
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "PEX-5: /dev/kvm is required; TCG is not performance evidence" >&2
  exit 2
fi

exec flock /tmp/jasper-full.lock \
  python3 "$ROOT/scripts/pex5-kernel-matrix.py" \
    --image "$IMAGE" \
    --out "$OUT" \
    --cpus "$CORES" \
    --smps "$SMPS" \
    --rounds "$ROUNDS" \
    --timeout "$TIMEOUT"
