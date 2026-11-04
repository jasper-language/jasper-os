#!/usr/bin/env bash
# JB-OS2 `.jaso` L1：绑定判定与模块表六步链（仅在构建虚拟机经 vm-run.sh 运行）：
# Verus/Z3 → Proptest → Miri → cargo-fuzz → Kani → Loom（N/A，见登记表）。
set -euo pipefail
cd "$(dirname "$0")/../.."
out=evidence/jb-os2/loader-suite
rm -rf "$out"
mkdir -p "$out"
sha256sum jaso/src/binding.rs jaso/src/lifecycle.rs jaso/src/kernel_gate.rs jaso/src/l1_tests.rs jaso/src/conformance.rs jaso/src/pack.rs \
  user/rt/src/loader.rs user/rt/src/module.rs user/jasodemo/src/main.rs user/jasodemo/build.rs modules/l1demo/src/main.rs \
  verification/toolbox/tests/jaso_l1.rs verification/toolbox/fuzz/fuzz_targets/jaso_binding.rs \
  verification/toolbox/verus/jaso_l1.rs verification/toolbox/verus/jaso_l1_bad.rs > "$out/source.sha256"
verus=/home/jasper/verus/verus
export PATH=/home/jasper/verus:$PATH
"$verus" verification/toolbox/verus/jaso_l1.rs > "$out/verus.log" 2>&1
if "$verus" verification/toolbox/verus/jaso_l1_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例意外通过" >&2; exit 1
fi
cargo test -p jaso --features pack > "$out/host.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test jaso_l1 > "$out/proptest.log" 2>&1
cargo +nightly miri test -p jaso --features pack --lib -- l1_tests::binding_accepts l1_tests::binding_rejects l1_tests::binding_must l1_tests::dependencies l1_tests::unload > "$out/miri.log" 2>&1
(cd verification/toolbox/fuzz && mkdir -p corpus/jaso_binding && \
  cargo fuzz run jaso_binding corpus/jaso_binding seeds/jaso_binding -- -runs=2000000 -seed=1) > "$out/fuzz.log" 2>&1
for h in dotted_cursor_stays_in_bounds type_depth_cap_is_enforced; do
  timeout -k 30 1200 cargo kani -p jaso --harness "$h" > "$out/kani-$h.log" 2>&1
done
grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error|verified, [1-9]' "$out/verus-bad.log"
grep -q 'test result: ok. 57 passed' "$out/host.log"
grep -q 'test result: ok. 3 passed; 0 failed' "$out/proptest.log"
grep -q 'test result: ok. 5 passed; 0 failed' "$out/miri.log"
grep -q 'Done 2000000 runs' "$out/fuzz.log"
for h in dotted_cursor_stays_in_bounds type_depth_cap_is_enforced; do
  grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
done
printf 'JB-OS2 loader Verus/Proptest/Miri/fuzz/Kani completed; Loom N/A (see PROPERTIES.md)\n' | tee "$out/PASS"
