#!/usr/bin/env bash
# =============================================================================
# ns-dirty-check.sh —— 高精度期限事件脏集合的不变量校验（只在虚拟机内运行）
#
# 构建 ns-dirty-audit 内核：每轮刷新之后全表校验「没有待同步标记的槽位，已发布节点等于应发布事件；
# 没有待重读标记的在线处理器，缓存的根等于堆顶」，不一致直接恐慌。任务表的可变访问自动标脏，这里验证的是
# 表外输入（弹出节点、退出移除、启用高精度模式）有没有漏登记。
# 判据：每个处理器组合都走完启动（退出码 33 或 37），audits>0，audit_mismatch=0，没有恐慌。
# 用法：ns-dirty-check.sh；环境变量 CPUS（处理器数列表）、LIMIT（秒）、OUT 可调。
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
CPUS="${CPUS:-1 4 8}"
LIMIT="${LIMIT:-900}"
OUT="${OUT:-evidence/ns-dirty}"
TARGET=target/ns-dirty-audit
mkdir -p "$OUT"
cargo build --locked --release -p xtask > "$OUT/build.log" 2>&1 || { echo "FAIL xtask 构建失败"; exit 1; }
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features ns-dirty-audit >> "$OUT/build.log" 2>&1 \
  || { echo "FAIL 校验内核构建失败"; exit 1; }
target/release/xtask "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" > "$OUT/image.log" 2>&1 || { echo "FAIL 镜像生成失败"; exit 1; }
for n in $CPUS; do
  cp "$OUT/kernel.img" "$OUT/k$n.img"
  python3 scripts/boot-trace.py --img "$OUT/k$n.img" --out "$OUT/p$n" --timeout "$LIMIT" --nice 10 --io-class 2 --smp "$n" \
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
exit $rc
