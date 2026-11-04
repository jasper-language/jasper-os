#!/usr/bin/env bash
# =============================================================================
# timer-progress-check.sh —— 定时器中断活锁的回归检查（只在虚拟机内运行）
#
# QEMU -icount 让虚拟时钟按指令数走：shift 越大，相对指令的时钟中断越密，确定性地模拟处理器相对时钟很慢。
# 修复前 shift=8 稳定卡在第 552 行、shift=10 卡在第 64 行（每次中断都打断同一条用户指令）。
# 判据：每个 shift 都在时限内走到第 LINES 行。
# 用法：timer-progress-check.sh [镜像]；环境变量 SHIFTS、LINES、LIMIT 可调。
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
IMG="${1:-images/jasper-kernel.img}"
SHIFTS="${SHIFTS:-5 6 7 8 9 10}"
LINES="${LINES:-1200}"
LIMIT="${LIMIT:-280}"
OUT="${OUT:-evidence/timer-progress}"
mkdir -p "$OUT"
WORK=$(mktemp -d /tmp/timer-progress-XXXXXX)
trap 'rm -rf "$WORK"' EXIT
for n in $SHIFTS; do
  cp "$IMG" "$WORK/k$n.img"
  python3 scripts/boot-trace.py --img "$WORK/k$n.img" --out "$OUT/s$n" --timeout "$LIMIT" --nice 10 --io-class 2 \
    --icount "$n" --stop-at-lines "$LINES" --stall-secs 60 > "$OUT/s$n.result" 2>&1 &
done
wait
rc=0
for n in $SHIFTS; do
  lines=$(wc -l < "$OUT/s$n.serial")
  if [ "$lines" -ge "$LINES" ]; then echo "shift=$n PASS lines=$lines $(cut -d' ' -f4 "$OUT/s$n.result")"
  else echo "shift=$n FAIL lines=$lines $(cat "$OUT/s$n.result")"; rc=1; fi
done
exit $rc
