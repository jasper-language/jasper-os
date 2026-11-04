#!/usr/bin/env bash
# =============================================================================
# timer-progress-check.sh —— 定时器中断活锁的回归检查（只在虚拟机内运行）
#
# QEMU -icount 让虚拟时钟按指令数走：shift 越大，相对指令的时钟中断越密，确定性地模拟处理器相对时钟很慢。
# 修复前单处理器 shift=8 稳定卡在第 552 行、shift=10 卡在第 64 行（每次中断都打断同一条用户指令）；
# 其他处理器的周期定时器接入前进保证之前，4 处理器 shift=9 稳定卡在第 437 行（各处理器的定时器事务排满调度器锁）。
# 判据：每个组合都在时限内走到第 LINES 行。
# 用法：timer-progress-check.sh [镜像]；环境变量 CASES（处理器数:shift）、LINES、LIMIT 可调。
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
IMG="${1:-images/jasper-kernel.img}"
CASES="${CASES:-1:5 1:6 1:7 1:8 1:9 1:10 4:9 8:9}"
LINES="${LINES:-1200}"
LIMIT="${LIMIT:-280}"
OUT="${OUT:-evidence/timer-progress}"
mkdir -p "$OUT"
WORK=$(mktemp -d /tmp/timer-progress-XXXXXX)
trap 'rm -rf "$WORK"' EXIT
for c in $CASES; do
  cpus=${c%:*}; n=${c#*:}
  cp "$IMG" "$WORK/k$cpus-$n.img"
  python3 scripts/boot-trace.py --img "$WORK/k$cpus-$n.img" --out "$OUT/p$cpus-s$n" --timeout "$LIMIT" --nice 10 --io-class 2 \
    --smp "$cpus" --icount "$n" --stop-at-lines "$LINES" --stall-secs 60 > "$OUT/p$cpus-s$n.result" 2>&1 &
done
wait
rc=0
for c in $CASES; do
  cpus=${c%:*}; n=${c#*:}; r="$OUT/p$cpus-s$n"
  lines=$(wc -l < "$r.serial")
  if [ "$lines" -ge "$LINES" ]; then echo "cpus=$cpus shift=$n PASS lines=$lines $(cut -d' ' -f4 "$r.result")"
  else echo "cpus=$cpus shift=$n FAIL lines=$lines $(cat "$r.result")"; rc=1; fi
done
exit $rc
