#!/usr/bin/env bash
# =============================================================================
# run-deadline-phase-suite.sh —— issue #2 第三片的期限时间点单元/属性链
#
# 范围：kernel-core/src/raw_timing.rs::DeadlineTimeline 的六点顺序、共享
# 纳秒时钟约束与五个累计区间。Kani harness 已登记，按发版门禁运行；日常
# 只跑 production 单元、Proptest 和 Miri。所有命令经 vm-run.sh 执行。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
out=evidence/issue2/deadline-phase-suite
mkdir -p "$out"

sha256sum \
  kernel-core/src/raw_timing.rs \
  kernel/src/task.rs \
  kernel/src/irq.rs \
  kernel/src/sched/mod.rs \
  kernel/src/sched/scheduler.rs \
  verification/toolbox/tests/deadline_phases.rs \
  > "$out/source.sha256"
rustc --version > "$out/rustc-version.log"

cargo test -p kernel-core raw_timing > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test deadline_phases > "$out/proptest.log" 2>&1
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml \
  --test deadline_phases fixed_timeline_under_miri > "$out/miri.log" 2>&1

if kani_enabled; then
  cargo kani -p kernel-core --harness ordered_shared_timeline_preserves_all_six_points \
    > "$out/kani-ordered.log" 2>&1
  cargo kani -p kernel-core --harness reversed_endpoint_is_rejected \
    > "$out/kani-reversed.log" 2>&1
  grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-ordered.log"
  grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-reversed.log"
fi

grep -Eq '[1-9][0-9]* passed; 0 failed' "$out/core.log"
grep -q '3 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"

printf '%s\n' \
  "Deadline phase suite: unit/Proptest/Miri passed; $KANI_STATUS" \
  | tee "$out/PASS"
