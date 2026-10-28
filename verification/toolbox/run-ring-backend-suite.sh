#!/usr/bin/env bash
# =============================================================================
# run-ring-backend-suite.sh —— 异步 Ring 后端登记表（issue #5 第一切片）的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Kani → Loom。
# 范围：kernel-core/src/ring_backend.rs（新写：Kind / Contract / Route / route / routes_well_formed），
# 以及既有的 kernel-core/src/quota.rs reserve_u32 / reserve_usize（补链：原只有 Kani）。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/issue5/ring-backend-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/issue5/ring-backend-suite
mkdir -p "$out"
HARNESSES="route_agrees_with_table_and_well_formed_implies_unique contract_buffer_and_instant_rules quota_admission_never_wraps_or_exceeds_limit"

sha256sum \
  kernel-core/src/ring_backend.rs \
  kernel-core/src/quota.rs \
  kernel/src/ring.rs \
  verification/toolbox/verus/ring_backend.rs \
  verification/toolbox/verus/ring_backend_bad.rs \
  verification/toolbox/tests/ring_backend.rs \
  verification/toolbox/fuzz/fuzz_targets/ring_backend.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
cargo kani --version > "$out/kani-version.log"
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/ring_backend.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：漏查第一条路由推不出「无匹配 ⇔ 未找到」。
if "$VERUS" verification/toolbox/verus/ring_backend_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 ring_backend_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test -p kernel-core ring_backend > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test ring_backend -- \
  --skip under_miri > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test ring_backend \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run ring_backend -- -runs=1000000 -max_len=128) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani =="
for h in $HARNESSES; do
  cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
done

echo "== 6/6 Loom =="
# N/A：登记表是编译期常量、查找是纯函数，没有共享可变状态或线程交错可供 Loom 探索。
# 替代证据：内核侧 ROUTES 为 const 并以 const 断言 routes_well_formed（编译即检查）；
# quota 准入是纯函数，调用方在对象表锁内串行使用（锁序由内核锁序检查覆盖）。
printf 'N/A: pure const table + pure functions, no shared mutable state\n' > "$out/loom.log"

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|assertion failed|invariant not satisfied)' "$out/verus-bad.log"
grep -q '4 passed; 0 failed' "$out/core.log"
grep -q '3 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
for h in $HARNESSES; do
  grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
done

printf 'Ring backend suite: Verus/Proptest/Miri/fuzz/Kani passed; Loom N/A (pure const)\n' | tee "$out/PASS"
