#!/usr/bin/env bash
# Repeat the real 8-vCPU p999 guest under host KVM and retain every raw result.
# IMAGE=<prebuilt p999 image> reuses an existing image; otherwise this script builds one.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"
CORES="${JASPER_CORES:-4-11}"
ROUNDS="${ROUNDS:-5}"
LIMIT="${LIMIT:-300}"
OUT="${OUT:-evidence/kvm-p999-repeat/$(date '+%Y%m%d-%H%M%S')}"
IMAGE="${IMAGE:-}"
mkdir -p "$OUT"

{
  echo "accelerator=kvm"
  echo "cpu_affinity=$CORES"
  echo "rounds=$ROUNDS"
  echo "host_load=$(cut -d' ' -f1-3 /proc/loadavg)"
  qemu-system-x86_64 --version | head -1
  command -v lscpu >/dev/null && lscpu | grep -E '^(Model name|CPU\(s\)|Thread|Core|Socket|CPU max MHz|CPU min MHz|CPU MHz)' || true
} > "$OUT/environment.txt"

if [ -z "$IMAGE" ]; then
  TARGET=target/kvm-p999-repeat
  CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
    --target x86_64-unknown-none -p jasper-kernel --features krn3-p999-verify \
    > "$OUT/build.log" 2>&1
  cargo build --locked --release -p xtask >> "$OUT/build.log" 2>&1
  IMAGE="$OUT/kernel.img"
  target/release/xtask "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$IMAGE" \
    > "$OUT/image.log" 2>&1
fi

rc=0
: > "$OUT/latency.txt"
for n in $(seq 1 "$ROUNDS"); do
  python3 scripts/boot-trace.py --img "$IMAGE" --out "$OUT/run-$n" \
    --timeout "$LIMIT" --nice 5 --io-class 2 --smp 8 --accel kvm --cpus "$CORES" \
    > "$OUT/run-$n.result" 2>&1 || rc=1
  grep -a '^\[JSR-WAKE-LATENCY\]' "$OUT/run-$n.serial" | sed "s/^/run=$n /" >> "$OUT/latency.txt" || rc=1
  grep -a '^\[JSR-WAKE-PHASE\]' "$OUT/run-$n.serial" | sed "s/^/run=$n /" >> "$OUT/latency.txt" || rc=1
  grep -aq 'complete=true' "$OUT/run-$n.serial" || rc=1
  grep -aEq '^\[JSR-SCALE-FAIL\]' "$OUT/run-$n.serial" && rc=1
  rm -f "$OUT/run-$n.img"
done

cat "$OUT/latency.txt"
[ "$rc" -eq 0 ] || { echo "KVM p999 repeat: FAIL"; exit 1; }
echo "KVM p999 repeat: PASS rounds=$ROUNDS"
