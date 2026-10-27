#!/usr/bin/env bash
# =============================================================================
# run-abi-suite.sh —— 原生 ABI 世代（issue #8）的六步验证链
#
# 顺序固定：Verus/Z3 → Proptest → Miri → cargo-fuzz → Kani → Loom。
# 第六步 Loom 对本切片不适用：被测函数是纯函数，没有共享状态或并发交错；
# 脚本只记录 N/A 原因，绝不记为 PASS。替代证据是真实 QEMU 装载演练
# （`kernel::abi_demo` + `scripts/accept.sh` 的 ABI 检查）。
#
# 所有命令在构建虚拟机内执行；输出保存在 evidence/abi/abi-generation-suite。
# 工具路径由环境变量提供（不把本机路径写进仓库）：VERUS 指向 Verus 可执行文件，
# Z3 默认取与 VERUS 同目录的 z3。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${VERUS:?请用 VERUS 环境变量指向 Verus 可执行文件}"
Z3="${Z3:-$(dirname "$VERUS")/z3}"
out=evidence/abi/abi-generation-suite
mkdir -p "$out"

sha256sum \
  abi/abi-version.txt \
  kernel-core/build.rs \
  kernel-core/src/abi_version.rs \
  kernel-core/src/elf.rs \
  kernel-core/src/abi.rs \
  kernel/build.rs \
  kernel/src/proc/mod.rs \
  kernel/src/proc/spawn.rs \
  kernel/src/syscall/mod.rs \
  kernel/src/abi_demo.rs \
  verification/toolbox/verus/abi_version.rs \
  verification/toolbox/tests/abi_version.rs \
  verification/toolbox/fuzz/fuzz_targets/abi_note.rs \
  > "$out/source.sha256"

rustc --version > "$out/rustc-version.log"
cargo kani --version > "$out/kani-version.log"
cargo fuzz --version > "$out/fuzz-version.log"
"$Z3" --version > "$out/z3-version.log"
# Verus 不同发行版对 --version 的支持不一致；版本证据以 Z3 与编译器版本为主，这里尽力记录。
"$VERUS" --version > "$out/verus-version.log" 2>&1 || true

echo "== 1/6 Verus/Z3 =="
"$VERUS" verification/toolbox/verus/abi_version.rs > "$out/verus.log" 2>&1

echo "== 2/6 Proptest =="
cargo test --manifest-path verification/toolbox/Cargo.toml --test abi_version > "$out/proptest.log" 2>&1

echo "== 3/6 Miri =="
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test abi_version \
  note_roundtrip_under_miri > "$out/miri.log" 2>&1

echo "== 4/6 cargo-fuzz =="
(cd verification/toolbox/fuzz && cargo fuzz run abi_note -- -runs=10000) > "$out/fuzz.log" 2>&1

echo "== 5/6 Kani =="
cargo kani -p kernel-core --features abi-fv \
  --harness abi_compatibility_is_exactly_same_major_and_minor_bound > "$out/kani-compat.log" 2>&1
cargo kani -p kernel-core --features abi-fv \
  --harness abi_note_encode_parse_roundtrip > "$out/kani-note.log" 2>&1
cargo kani -p kernel-core --features abi-fv \
  --harness abi_packed_rejects_reserved_high_bits > "$out/kani-packed.log" 2>&1

echo "== 6/6 Loom =="
cat > "$out/loom-na.log" <<'EOF'
N/A：ABI 世代判定（compatible/check_image/parse_note/encode_note）是纯函数，
不读写共享状态，也没有锁、原子或线程交错可供 Loom 枚举。
替代证据：Proptest 全输入域性质 + cargo-fuzz 畸形输入 + Kani 有界证明 + 真实 QEMU 装载演练。
EOF

grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -q '7 passed; 0 failed' "$out/proptest.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#10000.*DONE' "$out/fuzz.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-compat.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-note.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-packed.log"
grep -q '^N/A：' "$out/loom-na.log"

printf 'ABI generation suite: Verus/Proptest/Miri/fuzz/Kani passed; Loom N/A (pure functions)\n' | tee "$out/PASS"
