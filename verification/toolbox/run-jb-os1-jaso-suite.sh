#!/usr/bin/env bash
# JB-OS1 `.jaso` format 1 读取器六步链（仅在构建虚拟机经 vm-run.sh 运行）：
# Verus/Z3 → Proptest → Miri → cargo-fuzz → Kani → Loom（Loom 不适用，见登记表）。
set -euo pipefail
cd "$(dirname "$0")/../.."
out=evidence/jb-os1/jaso-suite
mkdir -p "$out"
sha256sum jaso/src/lib.rs jaso/src/platform.rs jaso/src/manifest.rs jaso/src/code.rs jaso/src/build.rs jaso/src/migrate.rs \
  jaso/src/kani_proofs.rs verification/toolbox/tests/jaso.rs verification/toolbox/fuzz/fuzz_targets/jaso_parse.rs \
  verification/toolbox/verus/jaso_bounds.rs verification/toolbox/verus/jaso_bounds_bad.rs > "$out/source.sha256"
verus=/home/jasper/verus/verus
export PATH=/home/jasper/verus:$PATH
"$verus" verification/toolbox/verus/jaso_bounds.rs > "$out/verus.log" 2>&1
if "$verus" verification/toolbox/verus/jaso_bounds_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例意外通过" >&2; exit 1
fi
cargo test -p jaso --features pack > "$out/host.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test jaso > "$out/proptest.log" 2>&1
cargo +nightly miri test -p jaso --features pack --lib -- tests::roundtrip tests::platform_rejections tests::extensions \
  tests::managed_images tests::multiple_images_and_selection tests::migrate_format0 tests::version_ranges_and_dependencies \
  > "$out/miri.log" 2>&1
(cd verification/toolbox/fuzz && mkdir -p corpus/jaso_parse && cargo fuzz run jaso_parse corpus/jaso_parse seeds/jaso_parse -- -runs=2000000 -seed=1) > "$out/fuzz.log" 2>&1
for h in range_within_is_exact extension_layout_is_bounded platform_record_rules export_entry_is_bounded; do
  cargo kani -p jaso --harness "$h" > "$out/kani-$h.log" 2>&1
done
grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error|verified, [1-9]' "$out/verus-bad.log"
grep -q 'test result: ok. 56 passed' "$out/host.log"
grep -q 'test result: ok. 8 passed; 0 failed' "$out/proptest.log"
grep -q 'test result: ok. 7 passed; 0 failed' "$out/miri.log"
grep -q 'Done 2000000 runs' "$out/fuzz.log"
for h in range_within_is_exact extension_layout_is_bounded platform_record_rules export_entry_is_bounded; do
  grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-$h.log"
done
printf 'JB-OS1 jaso format 1 Verus/Proptest/Miri/fuzz/Kani completed; Loom N/A (no shared state)\n' | tee "$out/PASS"
