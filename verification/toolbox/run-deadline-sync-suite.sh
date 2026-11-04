#!/usr/bin/env bash
# =============================================================================
# run-deadline-sync-suite.sh —— 高精度期限事件增量同步（issue #2 第一切片）的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/deadline_forest.rs 的 sync / SyncOutcome / SyncStats（新写），
# 以及同文件既有的 set / remove / pop_due（补链：Kani 两个 harness + 差分测试）。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/issue2/deadline-sync-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/issue2/deadline-sync-suite
mkdir -p "$out"
HARNESSES="sync_unchanged_empty sync_unchanged_s0_c0 sync_unchanged_s0_c1 sync_unchanged_s1_c0 sync_unchanged_s1_c1 sync_success_empty sync_success_s0_c0 sync_success_s0_c1 sync_success_s1_c0 sync_success_s1_c1 set_rejects_stale_generation_atomically pop_due_returns_earliest_only_when_due"

sha256sum \
  kernel-core/src/deadline_forest.rs \
  kernel-core/src/deadline.rs \
  kernel/src/sched/scheduler.rs \
  verification/toolbox/verus/deadline_sync.rs \
  verification/toolbox/verus/deadline_sync_bad.rs \
  verification/toolbox/tests/deadline_sync.rs \
  verification/toolbox/fuzz/fuzz_targets/deadline_sync.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
if kani_enabled; then
  cargo kani --version > "$out/kani-version.log"
fi
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/deadline_sync.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：只比较时刻的「无变化」判定推不出所有者相同。
if "$VERUS" verification/toolbox/verus/deadline_sync_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 deadline_sync_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test -p kernel-core deadline_forest > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test deadline_sync -- \
  --skip under_miri --skip race > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test deadline_sync \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run deadline_sync -- -runs=1000000 -max_len=4096) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani（$KANI_STATUS）=="
if kani_enabled; then
  for h in $HARNESSES; do
    cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
  done
fi

echo "== 6/6 Loom =="
cargo test --manifest-path verification/toolbox/Cargo.toml --test deadline_sync race > "$out/loom.log" 2>&1

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|assertion failed)' "$out/verus-bad.log"
grep -q '3 passed; 0 failed' "$out/core.log"
grep -q '3 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
if kani_enabled; then
  for h in $HARNESSES; do
    grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
  done
fi
grep -q '1 passed; 0 failed' "$out/loom.log"

printf '%s\n' "Deadline sync suite: Verus/Proptest/Miri/fuzz/Loom passed; $KANI_STATUS" | tee "$out/PASS"
