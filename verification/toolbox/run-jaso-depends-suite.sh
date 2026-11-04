#!/usr/bin/env bash
# `core.depends` 线性查重六步链（仅在构建虚拟机经 vm-run.sh 运行）：
# Verus/Z3 → Proptest → Miri → cargo-fuzz；Kani、Loom 不适用，见登记表。
set -euo pipefail
cd "$(dirname "$0")/../.."
out=evidence/jaso-depends
rm -rf "$out"
mkdir -p "$out"
sha256sum jaso/src/manifest.rs verification/toolbox/tests/jaso.rs verification/toolbox/fuzz/fuzz_targets/jaso_parse.rs \
  verification/toolbox/verus/jaso_depends.rs verification/toolbox/verus/jaso_depends_bad.rs > "$out/source.sha256"
verus=/home/jasper/verus/verus
export PATH=/home/jasper/verus:$PATH
"$verus" verification/toolbox/verus/jaso_depends.rs > "$out/verus.log" 2>&1
if "$verus" verification/toolbox/verus/jaso_depends_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例意外通过" >&2; exit 1
fi
cargo test -p jaso --features pack > "$out/host.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test jaso > "$out/proptest.log" 2>&1
cargo +nightly miri test -p jaso --features pack --lib -- tests::version_ranges_and_dependencies tests::manifest_rules > "$out/miri.log" 2>&1
(cd verification/toolbox/fuzz && mkdir -p corpus/jaso_parse && cargo fuzz run jaso_parse corpus/jaso_parse seeds/jaso_parse -- -runs=1000000 -seed=1) > "$out/fuzz.log" 2>&1
grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error|verified, [1-9]' "$out/verus-bad.log"
grep -Eq 'test result: ok\. [0-9]+ passed; 0 failed' "$out/host.log"
grep -q 'depends_scan_is_linear_in_entries ... ok' "$out/host.log"
grep -q 'depends_scan_matches_reference ... ok' "$out/proptest.log"
grep -q 'test result: ok. 2 passed; 0 failed' "$out/miri.log"
grep -q 'Done 1000000 runs' "$out/fuzz.log"
printf 'jaso core.depends linear scan Verus/Proptest/Miri/fuzz completed; Kani and Loom N/A (see registry)\n' | tee "$out/PASS"
