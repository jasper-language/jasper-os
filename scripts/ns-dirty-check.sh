#!/usr/bin/env bash
# =============================================================================
# ns-dirty-check.sh —— 高精度期限事件脏集合的不变量校验（只在虚拟机内运行）
#
# 构建 ns-dirty-audit 内核：每轮刷新之后全表校验「没有待同步标记的槽位，已发布节点等于应发布事件；
# 没有待重读标记的在线处理器，缓存的根等于堆顶」，不一致直接恐慌。任务表的可变访问自动标脏，这里验证的是
# 表外输入（弹出节点、退出移除、启用高精度模式）有没有漏登记。
# 判据：每个处理器组合都走完启动（退出码 33 或 37），audits>0，audit_mismatch=0，没有恐慌。
# 默认启动很少走到高精度睡眠到期与预算到期，所以再跑一次 RT2 专项（4 处理器）：判据同上，并要求 RT2 三行结论全部通过。
# 用法：ns-dirty-check.sh；环境变量 CPUS（处理器数列表，可为空）、RT2（0 跳过专项）、LIMIT（秒）、OUT 可调。
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
CPUS="${CPUS-1 4 8}"
RT2="${RT2:-1}"
LIMIT="${LIMIT:-900}"
OUT="${OUT:-evidence/ns-dirty}"
TARGET=target/ns-dirty-audit
QEMU_LOCK=(flock /tmp/jasper-os-qemu.lock)
if [ "${JASPER_QEMU_LOCK_HELD:-0}" = 1 ]; then
  # 调用方已持全局锁：改用子锁仍让三个客户机串行，同时避免重复加同一把锁。
  QEMU_LOCK=(flock /tmp/jasper-os-qemu-children.lock)
fi
mkdir -p "$OUT"
cargo build --locked --release -p xtask > "$OUT/build.log" 2>&1 || { echo "FAIL xtask 构建失败"; exit 1; }
if [ -n "$CPUS" ]; then
  CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features ns-dirty-audit >> "$OUT/build.log" 2>&1 \
    || { echo "FAIL 校验内核构建失败"; exit 1; }
  target/release/xtask "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" > "$OUT/image.log" 2>&1 || { echo "FAIL 镜像生成失败"; exit 1; }
fi
for n in $CPUS; do
  cp "$OUT/kernel.img" "$OUT/k$n.img"
  "${QEMU_LOCK[@]}" python3 scripts/boot-trace.py --img "$OUT/k$n.img" --out "$OUT/p$n" --timeout "$LIMIT" --nice 10 --io-class 2 --smp "$n" \
    > "$OUT/p$n.result" 2>&1 &
done
wait
rc=0
for n in $CPUS; do
  s="$OUT/p$n.serial"
  line=$(grep -am1 -E '^\[JSR-NS-SYNC\]' "$s" || true)
  if grep -aqE '^\[JSR-EXIT\] (success|timing-only)' "$s" \
     && ! { grep -aE 'panicked at|KERNEL PANIC|^\[JSR-PANIC\]' "$s" | grep -avE '^\[JSR-USERTEXT\] task=rt-panic bytes=[0-9]+ text=panic: panicked at user/rtdemo/src/main.rs:[0-9]+:[0-9]+:'; } \
     && [[ "$line" =~ audit_mismatch=0\ audits=[1-9] ]]; then
    echo "cpus=$n PASS $line"
  else
    echo "cpus=$n FAIL $(cat "$OUT/p$n.result" | head -2 | tr '\n' ' ') ${line:-缺 JSR-NS-SYNC}；末行：$(tail -n1 "$s" | cut -c1-160)"
    rc=1
  fi
  rm -f "$OUT/k$n.img"
done
if [ "$RT2" != 0 ]; then
  T2=target/ns-dirty-audit-rt2
  if ! CARGO_TARGET_DIR="$T2" cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features ns-dirty-audit,rt2-verify >> "$OUT/build.log" 2>&1 \
     || ! target/release/xtask "$T2/x86_64-unknown-none/release/jasper-kernel" "$OUT/rt2.img" >> "$OUT/image.log" 2>&1; then
    echo "cpus=4+rt2 FAIL 专项内核构建失败"; exit 1
  fi
  python3 scripts/boot-trace.py --img "$OUT/rt2.img" --out "$OUT/rt2" --timeout "$LIMIT" --nice 10 --io-class 2 --smp 4 --icount 5 > "$OUT/rt2.result" 2>&1
  s="$OUT/rt2.serial"
  line=$(grep -am1 -E '^\[JSR-NS-SYNC\]' "$s" || true)
  if grep -aq 'rc=33 ' "$OUT/rt2.result" && ! grep -aqE 'panicked at|KERNEL PANIC|^\[JSR-PANIC\]' "$s" \
     && grep -aFq '[JSR-RT2-INTEGRATION] ns_sleep=true bsp_ap=true cpl3=true ns_budget=true exit_cancel=true resources=true failed=0' "$s" \
     && grep -aFq '[JSR-RT2-IRQ] delivered=true no_legacy_credit=true periodic_restored=true failed=0' "$s" \
     && [[ "$line" =~ audit_mismatch=0\ audits=[1-9] ]]; then
    echo "cpus=4+rt2 PASS $line"
  else
    echo "cpus=4+rt2 FAIL $(head -2 "$OUT/rt2.result" | tr '\n' ' ') ${line:-缺 JSR-NS-SYNC}；$(grep -aE 'JSR-PANIC|panicked at' "$s" | head -1 | cut -c1-160)"
    rc=1
  fi
  rm -f "$OUT/rt2.img"
fi
exit $rc
