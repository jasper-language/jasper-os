#!/usr/bin/env bash
# =============================================================================
# run-timer-progress-suite.sh —— 定时器前进保证的验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/timer_progress.rs。接入路径（kernel/src/sched/mod.rs、kernel/src/irq.rs）由
# scripts/timer-progress-check.sh 的真实启动覆盖。所有命令在构建虚拟机内执行；输出在 evidence/timer-progress/suite。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/timer-progress/suite
mkdir -p "$out"

sha256sum \
  kernel-core/src/timer_progress.rs \
  verification/toolbox/verus/timer_progress.rs \
  verification/toolbox/verus/timer_progress_bad.rs \
  verification/toolbox/tests/timer_progress.rs \
  verification/toolbox/fuzz/fuzz_targets/timer_progress.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/5 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/timer_progress.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：开销记成一半，推不出留出的时间不少于开销。
if "$VERUS" verification/toolbox/verus/timer_progress_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 timer_progress_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/5 Proptest =="
cargo test -p kernel-core timer_progress > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test timer_progress -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/5 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test timer_progress \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/5 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run timer_progress -- -runs=1000000 -max_len=512) > "$out/fuzz.log" 2>&1

echo "== 5/5 Loom（Kani：$KANI_STATUS）=="
# N/A：状态只由所属处理器在关中断时访问，纯函数之外没有共享可变状态，Loom 没有交错可探索。
# 替代证据：scripts/timer-progress-check.sh 的真实启动。
printf 'N/A: per-CPU state touched only with interrupts off; no thread interleaving\n' > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|assertion failed|invariant not satisfied)' "$out/verus-bad.log"
grep -q '4 passed; 0 failed' "$out/core.log"
grep -q '3 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"

printf '%s\n' "Timer progress suite: Verus/Proptest/Miri/fuzz passed; Loom N/A (per-CPU, IRQ off); $KANI_STATUS" | tee "$out/PASS"
