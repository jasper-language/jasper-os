#!/usr/bin/env bash
# =============================================================================
# run-ns-budget-suite.sh —— 纳秒预算的验证链（补链：现有代码）
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/ns_budget.rs。接入路径（Scheduler 的纳秒预算结算）由 accept 的 RT2 真实启动覆盖。
# 所有命令在构建虚拟机内执行；输出在 evidence/ns-budget/suite。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/ns-budget/suite
mkdir -p "$out"

sha256sum \
  kernel-core/src/ns_budget.rs \
  verification/toolbox/verus/ns_budget.rs \
  verification/toolbox/verus/ns_budget_bad.rs \
  verification/toolbox/tests/ns_budget.rs \
  verification/toolbox/fuzz/fuzz_targets/ns_budget.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/5 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/ns_budget.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：周期数少算一个，推不出 next 严格大于 end。
if "$VERUS" verification/toolbox/verus/ns_budget_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 ns_budget_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/5 Proptest =="
cargo test -p kernel-core ns_budget > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test ns_budget -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/5 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test ns_budget \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/5 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run ns_budget -- -runs=1000000 -max_len=512) > "$out/fuzz.log" 2>&1

echo "== 5/5 Loom（Kani：$KANI_STATUS）=="
# N/A：Budget 是调用方串行化的值类型，模块内没有原子、锁或共享状态，Loom 没有交错可探索。
# 替代证据：RT2 真实启动（调用方持调度器锁）。
printf 'N/A: value type serialized by its caller; no atomics or shared state in the module\n' > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|assertion failed|invariant not satisfied)' "$out/verus-bad.log"
grep -q '2 passed; 0 failed' "$out/core.log"
grep -q '4 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"

printf '%s\n' "Ns budget suite: Verus/Proptest/Miri/fuzz passed; Loom N/A (value type, no shared state); $KANI_STATUS" | tee "$out/PASS"
