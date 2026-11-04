#!/usr/bin/env bash
# =============================================================================
# run-idle-credit-suite.sh —— 主线全量复绿第二片的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/timer_units.rs::CreditLedger（新写：高精度模式下空闲期间的 tick 在任务切入前结算为空闲，
# 随下一次事件交付；补链其内部既有 PeriodicCredit::advance 的「不截断」）；kernel/src/sched/scheduler.rs 的接线
# （prepare_switch 由空闲切入时 settle_idle_credits，highres_event 交付 delivered）。
# Loom N/A：CreditLedger 是每核状态，只在调度器全局锁内读写；替代证据为全量 accept 的 4 / 8 处理器 SMP-2（见登记表）。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/main-green/idle-credit-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/main-green/idle-credit-suite
mkdir -p "$out"
HARNESSES="idle_settle_conserves_and_bounds_charge_bounded failures_leave_ledger_unchanged"

sha256sum \
  kernel-core/src/timer_units.rs \
  kernel/src/sched/scheduler.rs \
  verification/toolbox/verus/idle_credit.rs \
  verification/toolbox/verus/idle_credit_bad.rs \
  verification/toolbox/tests/idle_credit.rs \
  verification/toolbox/fuzz/fuzz_targets/idle_credit.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
if kani_enabled; then
  cargo kani --version > "$out/kani-version.log"
fi
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/idle_credit.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：切入前不结算空闲（修复前的行为），「切入任务只记切入后的 tick」推不出。
if "$VERUS" --triggers-mode silent verification/toolbox/verus/idle_credit_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 idle_credit_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test -p kernel-core --lib timer_units:: > "$out/core-timer-units.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test idle_credit -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test idle_credit \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run idle_credit -- -runs=1000000 -max_len=64) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani（$KANI_STATUS）=="
if kani_enabled; then
  for h in $HARNESSES; do
    cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
  done
fi

echo "== 6/6 Loom =="
echo "N/A：每核状态只在调度器全局锁内读写，无无锁并发；替代证据见登记表 MAIN-GREEN-04" > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|precondition not satisfied|requires not satisfied|assertion failed)' "$out/verus-bad.log"
grep -q '4 passed; 0 failed' "$out/core-timer-units.log"
grep -q '3 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
if kani_enabled; then
  for h in $HARNESSES; do
    grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
  done
fi

printf '%s\n' "Idle-credit suite: Verus/Proptest/Miri/fuzz passed, Loom N/A; $KANI_STATUS" | tee "$out/PASS"
