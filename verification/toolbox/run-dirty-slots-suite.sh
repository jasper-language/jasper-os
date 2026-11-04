#!/usr/bin/env bash
# =============================================================================
# run-dirty-slots-suite.sh —— 期限事件脏位图的验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/dirty_slots.rs，以及「只同步脏槽位」与全表扫描在期限森林上的等价性。接入路径（kernel/src/sched/slots.rs、scheduler.rs）由
# scripts/ns-dirty-check.sh 的每轮全表校验覆盖。所有命令在构建虚拟机内执行；输出在 evidence/dirty-slots/suite。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/dirty-slots/suite
mkdir -p "$out"

sha256sum \
  kernel-core/src/dirty_slots.rs \
  verification/toolbox/verus/dirty_slots.rs \
  verification/toolbox/verus/dirty_slots_bad.rs \
  verification/toolbox/tests/dirty_slots.rs \
  verification/toolbox/fuzz/fuzz_targets/dirty_slots.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/5 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/dirty_slots.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：不按 from 屏蔽低位。
if "$VERUS" verification/toolbox/verus/dirty_slots_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 dirty_slots_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/5 Proptest =="
cargo test -p kernel-core dirty_slots > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test dirty_slots -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/5 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test dirty_slots \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/5 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run dirty_slots -- -runs=1000000 -max_len=512) > "$out/fuzz.log" 2>&1

echo "== 5/5 Loom（Kani：$KANI_STATUS）=="
# N/A：位图只在全局调度锁内访问，纯函数之外没有共享可变状态，Loom 没有交错可探索。
# 替代证据：scripts/ns-dirty-check.sh 的每轮全表校验（真实多处理器启动）。
printf 'N/A: bitmap touched only under the global scheduler lock; no thread interleaving\n' > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|assertion failed|invariant not satisfied)' "$out/verus-bad.log"
grep -q '4 passed; 0 failed' "$out/core.log"
grep -q '2 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"

printf '%s\n' "Dirty slots suite: Verus/Proptest/Miri/fuzz passed; Loom N/A (global lock); $KANI_STATUS" | tee "$out/PASS"
