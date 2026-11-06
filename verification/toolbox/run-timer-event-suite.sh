#!/usr/bin/env bash
# =============================================================================
# run-timer-event-suite.sh —— 统一定时事件契约（issue #3 第一切片）的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/timer_event.rs（仲裁器、身份表、所有者预算、周期边界），
# 以及改为复用 next_boundary 的既有 deadline::next_period。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/timer/timer-event-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/timer/timer-event-suite
mkdir -p "$out"

sha256sum \
  kernel-core/src/timer_event.rs \
  kernel-core/src/timer_units.rs \
  kernel-core/src/deadline.rs \
  kernel/src/task.rs \
  kernel/src/ring.rs \
  kernel/src/sched/scheduler.rs \
  kernel/src/sched/mod.rs \
  kernel/src/rt2_demo.rs \
  kernel/src/ring_demo.rs \
  verification/toolbox/verus/timer_event.rs \
  verification/toolbox/verus/timer_event_bad.rs \
  verification/toolbox/tests/timer_event.rs \
  verification/toolbox/fuzz/fuzz_targets/timer_event.rs \
  verification/timer_identity_integration.tla \
  verification/timer_identity_integration.cfg \
  verification/timer_identity_integration_stale.cfg \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
if kani_enabled; then
  cargo kani --version > "$out/kani-version.log"
fi
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/timer_event.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：把容差加到精确请求上不能推出「精确请求不被推迟」。
if "$VERUS" verification/toolbox/verus/timer_event_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 timer_event_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test --manifest-path verification/toolbox/Cargo.toml --test timer_event -- \
  --skip under_miri --skip race > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test timer_event \
  timer_lifecycle_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run timer_event -- -runs=1000000 -max_len=4096) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani（$KANI_STATUS）=="
if kani_enabled; then
  for h in arbiter_never_later_than_any_latest_instant closed_identity_never_touches_successor \
           one_shot_expiry_is_delivered_at_most_once next_boundary_is_first_future_phase_point; do
    cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
  done
fi

echo "== 6/6 Loom =="
cargo test --manifest-path verification/toolbox/Cargo.toml --test timer_event race > "$out/loom.log" 2>&1

echo "== model: TLA+ identity integration =="
bash verification/run-timer-identity-integration-tlc.sh > "$out/tla.log" 2>&1

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|assertion failed)' "$out/verus-bad.log"
grep -q '6 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
if kani_enabled; then
  for h in arbiter_never_later_than_any_latest_instant closed_identity_never_touches_successor \
           one_shot_expiry_is_delivered_at_most_once next_boundary_is_first_future_phase_point; do
    grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
  done
fi
grep -q '2 passed; 0 failed' "$out/loom.log"
grep -q 'Timer identity integration TLA: positive PASS; stale mutation rejected' "$out/tla.log"

printf '%s\n' "Timer event suite: Verus/Proptest/Miri/fuzz/Loom/TLA passed; $KANI_STATUS" | tee "$out/PASS"
