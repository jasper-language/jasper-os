#!/usr/bin/env bash
# issue #1：系统调用能力集合与 spawn 准入的六步验证链（Verus → Proptest → Miri → cargo-fuzz → Loom；Kani 发版时验证）。
# Six-tool chain for the syscall capability set and spawn admission. Run inside the build VM.
# 用法：VERUS=<verus 可执行文件> [STEPS="1 2 3 4 5 6"] bash verification/toolbox/run-issue1-syscall-set-suite.sh
# STEPS 可分批运行（每批写各自日志）；PASS 只在六步日志齐全且全部通过时写出。
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/kani-gate.sh"
cd "$(dirname "$0")/../.."
out=evidence/issue1/syscall-set-suite
mkdir -p "$out"
verus=${VERUS:?需要 VERUS=<verus 可执行文件路径>}
steps=" ${STEPS:-1 2 3 4 5 6} "
want() { [[ "$steps" == *" $1 "* ]]; }
if ! git rev-parse HEAD > "$out/head.txt" 2>/dev/null; then
  printf '%s\n' "${SOURCE_HEAD:?linked worktree has no Git metadata in the build VM; set SOURCE_HEAD}" > "$out/head.txt"
fi
sha256sum kernel-core/src/syscall_set.rs kernel-core/src/spawn_abi.rs \
  verification/toolbox/verus/syscall_set.rs verification/toolbox/verus/syscall_set_bad.rs \
  verification/toolbox/tests/syscall_set.rs verification/toolbox/fuzz/fuzz_targets/spawn_desc.rs > "$out/source.sha256"
{ rustc --version; "$verus" --version 2>&1 | head -2; cargo fuzz --version; cargo +nightly miri --version; } > "$out/versions.log" 2>&1

# 1. Verus/Z3：正例全部验证，负例（只比较字 0 的子集判定）必须失败。
if want 1; then
"$verus" verification/toolbox/verus/syscall_set.rs > "$out/verus-positive.log" 2>&1
grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus-positive.log"
set +e
"$verus" verification/toolbox/verus/syscall_set_bad.rs > "$out/verus-negative.log" 2>&1
status=$?
set -e
[[ "$status" -ne 0 ]]
grep -q 'failed precondition' "$out/verus-negative.log"
fi

# 2. Proptest：生产代码对照 BTreeSet 参考模型（默认 256 例/性质，失败自动收缩）。
if want 2; then
cargo test --manifest-path verification/toolbox/Cargo.toml --test syscall_set > "$out/proptest.log" 2>&1
grep -q '5 passed; 0 failed' "$out/proptest.log"
fi

# 3. Miri：kernel-core 内的能力集合/参数块单元测试与工具箱固定链测试。
if want 3; then
cargo +nightly miri test -p kernel-core --lib -- syscall_set:: spawn_abi:: > "$out/miri-core.log" 2>&1
grep -Eq 'test result: ok\. [1-9][0-9]* passed; 0 failed' "$out/miri-core.log"
# 两个 proptest 性质在 Miri 解释执行下超过 10 分钟（每例逐个探测 264 个 ID），不纳入；
# 其随机覆盖由第 2/4/5 步承担，Miri 只跑 kernel-core 单元测试（含边界与穷举）与固定多级链。
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test syscall_set \
  -- --exact multi_level_spawn_never_escalates > "$out/miri-toolbox.log" 2>&1
grep -q '1 passed; 0 failed' "$out/miri-toolbox.log"
fi

# 4. cargo-fuzz：任意字节参数块 + 两个集合。
if want 4; then
(cd verification/toolbox/fuzz && cargo fuzz run spawn_desc -- -runs=200000 -max_len=256) > "$out/fuzz.log" 2>&1
grep -q '#200000.*DONE' "$out/fuzz.log"
fi

# 5. Kani：生产 Rust 实现级有界证明（发版时验证）。
if want 5; then
if kani_enabled; then
  for h in contains_matches_word_bit_for_every_id from_id_is_exact_singleton_or_explicit_none \
           set_algebra_is_pointwise subset_is_sound_and_complete encode_decode_roundtrip \
           decode_accepts_only_v2_header_and_roundtrips check_ok_iff_all_admission_rules_hold; do
    cargo kani -p kernel-core --harness "$h" > "$out/kani-$h.log" 2>&1
    grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
  done
fi
fi

# 6. Loom：N/A —— SyscallSet 是无共享可变状态的 Copy 值，spawn_abi 为纯函数；无原子量、锁或线程交错可检查。
if want 6; then
printf 'N/A: SyscallSet is a Copy value without shared mutable state; spawn_abi::check is pure\n' > "$out/loom-na.txt"

fi

for f in verus-positive verus-negative proptest miri-core miri-toolbox fuzz; do [[ -s "$out/$f.log" ]] || { echo "缺少 $f 日志，尚未完成全部六步"; exit 0; }; done
[[ -s "$out/loom-na.txt" ]] || exit 0
if kani_enabled; then [[ $(grep -l "VERIFICATION:- SUCCESSFUL" "$out"/kani-*.log 2>/dev/null | wc -l) -eq 7 ]] || { echo "Kani 七项尚未全部通过"; exit 0; }; fi
printf '%s\n' "issue #1 syscall-set: Verus positive+negative, Proptest, Miri, fuzz completed; Loom N/A; $KANI_STATUS" | tee "$out/PASS"
