#!/usr/bin/env bash
# =============================================================================
# run-assembly-suite.sh —— 服务装配、可撤回发布与模块健康（issue #6 第一至三切片）的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Loom（Kani 发版时验证）。
# 范围：kernel-core/src/{assembly,service_gate}.rs（生命周期、健康、发布租约、audit）
# 与 kernel/src/assembly.rs（真实模块激活、发布协议）。旧 ModuleManager 已退役。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/issue6/assembly-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/issue6/assembly-suite
mkdir -p "$out"
# 只跑本次改动对应的 harness 时用 KANI_HARNESSES 指定；空串表示本次不跑 Kani（沿用原证据，登记绑定的提交号）。
# KANI_HARNESSES selects the harnesses for this change; empty keeps the earlier evidence.
HARNESSES="${KANI_HARNESSES-published_mask_never_reports_unready audit_rejects_any_divergent_mask health_changes_never_publish_unavailable_service}"

sha256sum \
  kernel-core/src/assembly.rs \
  kernel-core/src/service_gate.rs \
  kernel/src/assembly.rs \
  verification/toolbox/verus/assembly.rs \
  verification/toolbox/verus/assembly_bad.rs \
  verification/toolbox/tests/assembly.rs \
  verification/toolbox/fuzz/fuzz_targets/assembly.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
if kani_enabled; then
  cargo kani --version > "$out/kani-version.log"
fi
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" --triggers-mode silent verification/toolbox/verus/assembly.rs > "$out/verus.log" 2>&1
# 负例必须验证失败：停用时漏掉「没有就绪模块依赖它」的前置条件，就绪集合闭包推不出。
if "$VERUS" --triggers-mode silent verification/toolbox/verus/assembly_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例 assembly_bad.rs 竟然通过验证" >&2
  exit 1
fi

echo "== 2/6 Proptest =="
cargo test -p kernel-core --lib assembly > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test assembly -- \
  --skip under_miri --skip loom > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test assembly \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run assembly -- -runs=1000000 -max_len=32) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani（$KANI_STATUS）=="
: > "$out/kani-result.txt"
if kani_enabled; then
  for h in $HARNESSES; do
    # 单个 harness 上限 10 分钟、虚拟内存 3.5 GB，全虚拟机同时只跑一个。
    # Per-harness cap: 10 minutes and 3.5 GB of address space; one at a time in the VM.
    # 撞上限无结论记「未判定」继续；只有检查项 FAILURE 才算反例（内存耗尽同样打印 VERIFICATION:- FAILED）。
    # A cap is recorded as undecided; only a failed check is a counterexample (OOM also prints VERIFICATION:- FAILED).
    rc=0
    flock /tmp/jasper-kani.lock bash -c "ulimit -v 3500000; timeout 600 cargo kani -p kernel-core --harness $h" > "$out/kani-$h.log" 2>&1 || rc=$?
    if grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"; then
      echo "$h SUCCESSFUL" >> "$out/kani-result.txt"
    elif grep -q 'Status: FAILURE' "$out/kani-$h.log"; then
      echo "$h FAILED" >> "$out/kani-result.txt"
      exit 1
    else
      echo "$h 未判定 rc=$rc" >> "$out/kani-result.txt"
    fi
  done
fi

echo "== 6/6 Loom =="
cargo test --manifest-path verification/toolbox/Cargo.toml --test assembly publication_protocol_loom \
  > "$out/loom.log" 2>&1

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|precondition not satisfied|assertion failed|invariant not satisfied)' "$out/verus-bad.log"
grep -q '7 passed; 0 failed' "$out/core.log"
grep -q '3 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
cat "$out/kani-result.txt"
grep -q '1 passed; 0 failed' "$out/loom.log"

printf '%s\n' "Assembly suite: Verus/Proptest/Miri/fuzz/Loom passed; $KANI_STATUS" | tee "$out/PASS"
