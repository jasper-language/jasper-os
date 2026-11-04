#!/usr/bin/env bash
# =============================================================================
# run-share-guard-suite.sh —— 主线全量复绿第七片的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/sched/timeshare.rs 的 preempt_rule / Owed 与 TimeSharePolicy::should_preempt（新写：
# 补给最低份额的档在本片第一个 tick 记账之前不被「更高档在等」抢占；修正前补给派发后的任何重新判定都会立即
# 换下它，欠账不偿还，S-2 QoS 用例后台档 150 tick 无进展）。
# Loom N/A：TimeSharePolicy 是每核运行队列锁内的普通值，preempt_rule 为纯函数，无共享可变状态；
# 并发面（调度器锁下的判定与切换）由 QEMU S-2 / SCHED-1 运行覆盖，见登记表 MAIN-GREEN-08。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/main-green/share-guard-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/main-green/share-guard-suite
mkdir -p "$out"
HARNESSES="preempt_rule_guard_full_domain"

sha256sum \
  kernel-core/src/sched/timeshare.rs \
  kernel-core/src/sched/tests.rs \
  verification/toolbox/verus/share_guard.rs \
  verification/toolbox/verus/share_guard_bad.rs \
  verification/toolbox/tests/share_guard.rs \
  verification/toolbox/fuzz/fuzz_targets/share_guard.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
if kani_enabled; then
  cargo kani --version > "$out/kani-version.log"
fi
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/share_guard.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：保护写成 used <= 1（两个 tick），记过 tick 后更高档在等仍不抢占，后置条件推不出。
if "$VERUS" --triggers-mode silent verification/toolbox/verus/share_guard_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 share_guard_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test -p kernel-core --lib sched::tests:: > "$out/core-sched.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test share_guard -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test share_guard \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run share_guard -- -runs=1000000 -max_len=600) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani（$KANI_STATUS）=="
if kani_enabled; then
  for h in $HARNESSES; do
    cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
  done
fi

echo "== 6/6 Loom =="
echo "N/A：preempt_rule 是纯函数、TimeSharePolicy 为每核队列锁内的普通值，无共享可变状态；替代证据见登记表 MAIN-GREEN-08" > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -q 'error: postcondition not satisfied' "$out/verus-bad.log"
grep -Eq 'test result: ok\. [0-9]+ passed; 0 failed' "$out/core-sched.log"
grep -q 'rescued_dispatch_is_not_preempted_before_its_tick ... ok' "$out/core-sched.log"
grep -q '2 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
if kani_enabled; then
  for h in $HARNESSES; do
    grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
  done
fi

printf '%s\n' "Share guard suite: Verus/Proptest/Miri/fuzz passed, Loom N/A; $KANI_STATUS" | tee "$out/PASS"
