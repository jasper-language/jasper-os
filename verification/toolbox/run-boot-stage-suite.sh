#!/usr/bin/env bash
# =============================================================================
# run-boot-stage-suite.sh —— 启动阶段图、跟踪器与静态启动计划（issue #7）的验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/boot_stage.rs（Stage / GRAPH / graph_well_formed / closure / Tracker / plan_check），
# kernel/src/kmain.rs 的 stage 包装（经内核定点验收覆盖），以及既有的 kernel-core/src/capacity.rs
# 启动容量记录 encode / parse（补链：原无验证链；Capacity 阶段读取的不可信输入）。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/issue7/boot-stage-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/issue7/boot-stage-suite
mkdir -p "$out"
HARNESSES="tracker_invariants_hold_for_any_sequence graph_and_closure_are_consistent parse_accepts_only_canonical_records encode_parse_round_trip"

sha256sum \
  kernel-core/src/boot_stage.rs \
  kernel-core/src/capacity.rs \
  kernel/src/kmain.rs \
  kernel/src/acceptance.rs \
  kernel/src/production.rs \
  verification/toolbox/verus/boot_stage.rs \
  verification/toolbox/verus/boot_stage_bad.rs \
  verification/toolbox/tests/boot_stage.rs \
  verification/toolbox/fuzz/fuzz_targets/boot_stage.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
if kani_enabled; then
  cargo kani --version > "$out/kani-version.log"
fi
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/boot_stage.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：begin 漏掉依赖检查推不出「成功 ⇒ 直接依赖全部完成」。
if "$VERUS" verification/toolbox/verus/boot_stage_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 boot_stage_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test -p kernel-core --lib boot_stage > "$out/core.log" 2>&1
cargo test -p kernel-core --lib capacity > "$out/core-capacity.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test boot_stage -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test boot_stage \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run boot_stage -- -runs=1000000 -max_len=128) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani（$KANI_STATUS）=="
if kani_enabled; then
  for h in $HARNESSES; do
    # 单个 harness 上限 10 分钟、虚拟内存 3.5 GB，全虚拟机同时只跑一个。
    # Per-harness cap: 10 minutes and 3.5 GB of address space; one at a time in the VM.
    flock /tmp/jasper-kani.lock bash -c "ulimit -v 3500000; timeout 600 cargo kani -p kernel-core --harness $h" > "$out/kani-$h.log" 2>&1
  done
fi

echo "== 6/6 Loom =="
# N/A：跟踪器只由引导处理器上的内核主流程独占持有（kmain 的局部变量，不是静态量、不跨核共享），
# 阶段图是编译期常量，capacity 解析是纯函数；没有共享可变状态或线程交错可供 Loom 探索。
# 替代证据：const 断言 graph_well_formed(&GRAPH)；Kani 对任意 ≤12 步操作序列证明跟踪器不变量；
# 内核定点验收中 16 个阶段按序完成（done_mask=0xffff）。
printf 'N/A: tracker is a BSP-local value, graph is const, parse is pure; no shared mutable state\n' > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|assertion failed|invariant not satisfied)' "$out/verus-bad.log"
grep -q '7 passed; 0 failed' "$out/core.log"
grep -Eq '[1-9][0-9]* passed; 0 failed' "$out/core-capacity.log"
grep -q '5 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
if kani_enabled; then
  for h in $HARNESSES; do
    grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
  done
fi

printf '%s\n' "Boot stage suite: Verus/Proptest/Miri/fuzz passed; Loom N/A (BSP-local value); $KANI_STATUS" | tee "$out/PASS"
