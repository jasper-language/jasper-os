#!/usr/bin/env bash
# =============================================================================
# run-ring-backend-suite.sh —— 异步 Ring 后端登记表与生命周期（issue #5 第二切片）的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：Kind / Contract / Route、quota 准入，以及取消/交付/关闭/退出下的后端恰好释放一次。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/issue5/ring-backend-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
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
  kernel/src/ring_demo.rs \
  scripts/accept.sh \
  verification/ring_backend_lifecycle.tla \
  verification/ring_backend_lifecycle.cfg \
  verification/ring_backend_lifecycle_double_release.cfg \
  verification/ring_backend_lifecycle_early_publish.cfg \
  verification/run-ring-backend-lifecycle-tlc.sh \
  verification/toolbox/verus/ring_backend.rs \
  verification/toolbox/verus/ring_backend_bad.rs \
  verification/toolbox/tests/ring_backend.rs \
  verification/toolbox/fuzz/fuzz_targets/ring_backend.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
if kani_enabled; then
  cargo kani --version > "$out/kani-version.log"
fi
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
bash verification/run-ring-backend-lifecycle-tlc.sh > "$out/tla.log" 2>&1

echo "== 2/6 Proptest =="
cargo test -p kernel-core ring_backend > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test ring_backend -- \
  --skip under_miri --skip loom_ > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test ring_backend \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run ring_backend -- -runs=1000000 -max_len=128) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani（$KANI_STATUS）=="
if kani_enabled; then
  for h in $HARNESSES; do
    cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
  done
fi

echo "== 6/6 Loom =="
cargo test --manifest-path verification/toolbox/Cargo.toml --test ring_backend loom_ -- \
  --test-threads=1 > "$out/loom.log" 2>&1

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|assertion failed|invariant not satisfied)' "$out/verus-bad.log"
grep -q 'positive PASS; double-release and early-publication negatives rejected' "$out/tla.log"
grep -q '4 passed; 0 failed' "$out/core.log"
grep -q '3 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
grep -q '3 passed; 0 failed' "$out/loom.log"
if kani_enabled; then
  for h in $HARNESSES; do
    grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
  done
fi

printf '%s\n' "Ring backend suite: Verus/Proptest/Miri/fuzz/Loom passed; $KANI_STATUS" | tee "$out/PASS"
