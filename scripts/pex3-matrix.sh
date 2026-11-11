#!/usr/bin/env bash
# Run the PEX-3 central/sharded KVM matrix on host CPUs 4-11.
# 在宿主 CPU 4-11 上运行 PEX-3 中央/分片 KVM 矩阵。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${PEX3_IMAGE:?set PEX3_IMAGE to the image produced by pex3-build.sh}"
OUT="${PEX3_OUT:-$ROOT/evidence/pex3-kvm-$(date '+%Y%m%d-%H%M%S')}"
CORES="${PEX3_CPUS:-4-11}"
SMPS="${PEX3_SMPS:-2,4,8}"
ROUNDS="${PEX3_ROUNDS:-3}"
TIMEOUT="${PEX3_TIMEOUT:-300}"

mkdir -p "$OUT"
test -s "$IMAGE" || {
  echo "PEX-3: image is missing or empty: $IMAGE" >&2
  exit 2
}
if pgrep -f '[q]emu-system-' >/dev/null; then
  echo "PEX-3: another QEMU is running; refusing a contaminated measurement" >&2
  exit 2
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "PEX-3: /dev/kvm is required; TCG is not performance evidence" >&2
  exit 2
fi

exec flock /tmp/jasper-full.lock \
  python3 "$ROOT/scripts/pex3-matrix.py" \
    --image "$IMAGE" \
    --out "$OUT" \
    --cpus "$CORES" \
    --smps "$SMPS" \
    --rounds "$ROUNDS" \
    --timeout "$TIMEOUT"
