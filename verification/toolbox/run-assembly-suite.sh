#!/usr/bin/env bash
# =============================================================================
# run-assembly-suite.sh —— 服务装配契约（issue #6 第一切片）的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Kani → Loom。
# 范围：kernel-core/src/assembly.rs（新写：Assembly / Binding / Policy / State / audit / mask_has），
# kernel/src/assembly.rs（新写：绑定表与发布协议），以及既有的 kernel-core/src/module.rs
# ModuleManager（load / unload / unload_all，补链：原无验证链；Loom N/A：&mut 单所有者，无共享可变状态）。
# 所有命令在构建虚拟机内执行；输出保存在 evidence/issue6/assembly-suite。
# 工具路径由环境变量提供：VERUS 指向 Verus 可执行文件，Z3 默认取同目录的 z3。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/issue6/assembly-suite
mkdir -p "$out"
HARNESSES="published_mask_never_reports_unready audit_rejects_any_divergent_mask loaded_set_stays_dependency_closed"

sha256sum \
  kernel-core/src/assembly.rs \
  kernel-core/src/module.rs \
  kernel/src/assembly.rs \
  verification/toolbox/verus/assembly.rs \
  verification/toolbox/verus/assembly_bad.rs \
  verification/toolbox/tests/assembly.rs \
  verification/toolbox/fuzz/fuzz_targets/assembly.rs \
  verification/toolbox/fuzz/fuzz_targets/module_mgr.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
cargo kani --version > "$out/kani-version.log"
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
cargo test -p kernel-core --lib module::tests > "$out/core-module.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test assembly -- \
  --skip under_miri --skip loom > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test assembly \
  fixed_sequence_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run assembly -- -runs=1000000 -max_len=32) > "$out/fuzz.log" 2>&1
(cd verification/toolbox/fuzz && cargo fuzz run module_mgr -- -runs=1000000 -max_len=64) > "$out/fuzz-module-mgr.log" 2>&1

echo "== 5/6 Kani =="
: > "$out/kani-result.txt"
for h in $HARNESSES; do
  # 单个 harness 上限 10 分钟、虚拟内存 3.5 GB，全虚拟机同时只跑一个。
  # Per-harness cap: 10 minutes and 3.5 GB of address space; one at a time in the VM.
  # 撞上限无结论记「未判定」继续；得到反例照旧阻塞。Hitting a cap is recorded as undecided; a counterexample blocks.
  rc=0
  flock /tmp/jasper-kani.lock bash -c "ulimit -v 3500000; timeout 600 cargo kani -p kernel-core --harness $h" > "$out/kani-$h.log" 2>&1 || rc=$?
  if grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"; then
    echo "$h SUCCESSFUL" >> "$out/kani-result.txt"
  elif grep -q 'VERIFICATION:- FAILED' "$out/kani-$h.log"; then
    echo "$h FAILED" >> "$out/kani-result.txt"
    exit 1
  else
    echo "$h 未判定 rc=$rc" >> "$out/kani-result.txt"
  fi
done

echo "== 6/6 Loom =="
cargo test --manifest-path verification/toolbox/Cargo.toml --test assembly publication_protocol_loom \
  > "$out/loom.log" 2>&1

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error: (postcondition not satisfied|precondition not satisfied|assertion failed|invariant not satisfied)' "$out/verus-bad.log"
grep -q '5 passed; 0 failed' "$out/core.log"
grep -q '4 passed; 0 failed' "$out/core-module.log"
grep -q '3 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#1000000.*DONE' "$out/fuzz.log"
grep -q '#1000000.*DONE' "$out/fuzz-module-mgr.log"
cat "$out/kani-result.txt"
grep -q '1 passed; 0 failed' "$out/loom.log"

printf 'Assembly suite: Verus/Proptest/Miri/fuzz/Loom passed; Kani per kani-result.txt\n' | tee "$out/PASS"
