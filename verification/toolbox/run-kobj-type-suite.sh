#!/usr/bin/env bash
# =============================================================================
# run-kobj-type-suite.sh —— 内核对象类型登记表与销毁分派（issue #4 第一、二切片）的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/kobj_type.rs（Kind / Contract / REGISTRY / Destroy 钩子关系 / check_grant /
# kind_for_handle / edge_ordered / registry_well_formed），内核销毁钩子表及其所属模块入口，
# 以及既有的 kernel-core/src/object.rs Rights 位运算
# （from_bits_truncate / union / intersect / difference / contains / is_empty，补链：原无验证链）。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/issue4/kobj-type-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/issue4/kobj-type-suite
mkdir -p "$out"
HARNESSES="grant_check_matches_spec_for_all_inputs ordered_edges_admit_no_cycle"

sha256sum \
  kernel-core/src/kobj_type.rs \
  kernel-core/src/object.rs \
  kernel/src/kobj.rs \
  kernel/src/proc/mod.rs \
  kernel/src/ring.rs \
  kernel/src/ipc.rs \
  kernel/src/exit_state.rs \
  verification/toolbox/verus/kobj_type.rs \
  verification/toolbox/verus/kobj_type_bad.rs \
  verification/toolbox/tests/kobj_type.rs \
  verification/toolbox/fuzz/fuzz_targets/kobj_type.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
if kani_enabled; then
  cargo kani --version > "$out/kani-version.log"
fi
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/kobj_type.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：漏掉可转移性检查推不出「允许 ⇒ 含 TRANSFER 时可转移」。
if "$VERUS" verification/toolbox/verus/kobj_type_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 kobj_type_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test -p kernel-core --lib kobj_type > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test kobj_type -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test kobj_type \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run kobj_type -- -runs=1000000 -max_len=64) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani（$KANI_STATUS）=="
if kani_enabled; then
  for h in $HARNESSES; do
    cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
  done
fi

echo "== 6/6 Loom =="
# N/A：登记表是编译期常量、检查是纯函数，没有共享可变状态或线程交错可供 Loom 探索。
# 替代证据：内核侧以 const 断言 registry_well_formed 与 closing 钩子表一致（编译即检查）；
# check_grant 只在对象表锁内被调用（admit_handle），并发由对象表锁串行化，锁序由内核锁序检查覆盖。
printf 'N/A: pure const table + pure functions, no shared mutable state\n' > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|assertion failed|invariant not satisfied)' "$out/verus-bad.log"
grep -q '5 passed; 0 failed' "$out/core.log"
grep -q '4 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
if kani_enabled; then
  for h in $HARNESSES; do
    grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
  done
fi

printf '%s\n' "Kobj type suite: Verus/Proptest/Miri/fuzz passed; Loom N/A (pure const); $KANI_STATUS" | tee "$out/PASS"
