#!/usr/bin/env bash
# =============================================================================
# run-limit-batch-suite.sh —— 主线全量复绿第六片的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Kani → Loom。
# 范围：kernel-core/src/sched/limit.rs 的 CpuLimit::charge_batch 与 late_ticks（新写：高精度模式下处理器事件
# 被推迟、一次补交多个 tick 时整组按批计费，「扣费前余额已不为正」的部分记为迟到）。
# Loom N/A：CpuLimit 是调度器锁内的普通值，charge_batch 无共享可变状态；并发面（调度器锁下的计费与窗口快照
# 同一事务）由 QEMU S-2 / SMP-2 运行覆盖，见登记表 MAIN-GREEN-07。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/main-green/limit-batch-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/main-green/limit-batch-suite
mkdir -p "$out"
HARNESSES="batch_charge_total_full_domain batch_charge_equals_single_charges"

sha256sum \
  kernel-core/src/sched/limit.rs \
  kernel/src/sched/scheduler.rs \
  kernel/src/balance_demo.rs \
  verification/toolbox/verus/limit_batch.rs \
  verification/toolbox/verus/limit_batch_bad.rs \
  verification/toolbox/tests/limit_batch.rs \
  verification/toolbox/fuzz/fuzz_targets/limit_batch.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
cargo kani --version > "$out/kani-version.log"
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/limit_batch.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：把第一个 tick 也按余额判迟到，余额已不为正时迟到 = ticks，后置条件推不出。
if "$VERUS" --triggers-mode silent verification/toolbox/verus/limit_batch_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 limit_batch_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test -p kernel-core --lib sched::limit:: > "$out/core-limit.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test limit_batch -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test limit_batch \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run limit_batch -- -runs=1000000 -max_len=40) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani =="
for h in $HARNESSES; do
  cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
done

echo "== 6/6 Loom =="
echo "N/A：charge_batch 是调度器锁内的纯值计算，无共享可变状态；替代证据见登记表 MAIN-GREEN-07" > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -q 'error: postcondition not satisfied' "$out/verus-bad.log"
grep -q '9 passed; 0 failed' "$out/core-limit.log"
grep -q '2 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
for h in $HARNESSES; do
  grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
done

printf 'Limit batch suite: Verus/Proptest/Miri/fuzz/Kani passed, Loom N/A\n' | tee "$out/PASS"
