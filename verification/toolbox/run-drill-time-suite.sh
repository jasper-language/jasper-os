#!/usr/bin/env bash
# =============================================================================
# run-drill-time-suite.sh —— 主线全量复绿第一片的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/drill.rs（新写：refill_consistent / preempt_step_continues，M1.1 与 M1.4 演练判据；
# 第三片 hog_continues，SMP-2 铺满/窃取的覆盖延长；第五片 dispatch_mask，SMP-2 跨核上限按分派判分散）、
# kernel-core/src/timer_units.rs::counter_ns（补链：自 kernel/src/hrtime.rs 既有换算抽出，原只有部分性质登记）。
# Loom N/A：三者都是纯函数，无共享可变状态；替代证据为 QEMU 定点三次复跑（见登记表）。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/main-green/drill-time-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/main-green/drill-time-suite
mkdir -p "$out"
HARNESSES="uncalibrated_is_none floor_is_exact_and_monotone_bounded refill_judgement_full_domain preempt_loop_terminates_full_domain hog_loop_bounded_full_domain dispatch_mask_exact_up_to_eight"

sha256sum \
  kernel-core/src/drill.rs \
  kernel-core/src/timer_units.rs \
  kernel/src/hrtime.rs \
  verification/toolbox/verus/drill_time.rs \
  verification/toolbox/verus/drill_time_bad.rs \
  verification/toolbox/verus/drill_hog_bad.rs \
  verification/toolbox/verus/drill_dispatch_bad.rs \
  kernel/src/balance_demo.rs \
  verification/toolbox/tests/drill_time.rs \
  verification/toolbox/fuzz/fuzz_targets/drill_time.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
if kani_enabled; then
  cargo kani --version > "$out/kani-version.log"
fi
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/drill_time.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：判据去掉「已扣额度 ≤ 流逝 tick」后，后置条件推不出。
if "$VERUS" --triggers-mode silent verification/toolbox/verus/drill_time_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 drill_time_bad.rs 竟然通过验证" >&2
  exit 1
fi
# 负例：去掉截止的延长判据不再有界，decreases 推不出。
if "$VERUS" --triggers-mode silent verification/toolbox/verus/drill_hog_bad.rs > "$out/verus-hog-bad.log" 2>&1; then
  echo "负例 drill_hog_bad.rs 竟然通过验证" >&2
  exit 1
fi

# 负例：把空闲核（busy = 0）也算作分派过，逐位后置条件推不出。
if "$VERUS" --triggers-mode silent verification/toolbox/verus/drill_dispatch_bad.rs > "$out/verus-dispatch-bad.log" 2>&1; then
  echo "负例 drill_dispatch_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test -p kernel-core --lib drill:: > "$out/core-drill.log" 2>&1
cargo test -p kernel-core --lib timer_units:: > "$out/core-timer-units.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test drill_time -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test drill_time \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run drill_time -- -runs=1000000 -max_len=40) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani（$KANI_STATUS）=="
if kani_enabled; then
  for h in $HARNESSES; do
    cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
  done
fi

echo "== 6/6 Loom =="
echo "N/A：纯函数，无共享可变状态；替代证据见登记表 MAIN-GREEN-01..03、05、06" > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|precondition not satisfied|assertion failed)' "$out/verus-bad.log"
grep -q 'error: decreases not satisfied' "$out/verus-hog-bad.log"
grep -q 'error: postcondition not satisfied' "$out/verus-dispatch-bad.log"
grep -q '4 passed; 0 failed' "$out/core-drill.log"
grep -q '4 passed; 0 failed' "$out/core-timer-units.log"
grep -q '6 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
if kani_enabled; then
  for h in $HARNESSES; do
    grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
  done
fi

printf '%s\n' "Drill/time suite: Verus/Proptest/Miri/fuzz passed, Loom N/A; $KANI_STATUS" | tee "$out/PASS"
