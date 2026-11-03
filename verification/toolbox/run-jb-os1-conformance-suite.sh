#!/usr/bin/env bash
# JB-OS1 切片 3 一致性判定与向量（SPEC §14）六步链（仅在构建虚拟机经 vm-run.sh 运行）：
# Verus/Z3 → Proptest → Miri → cargo-fuzz → Kani（N/A，见登记表）→ Loom（N/A，见登记表）。
set -euo pipefail
cd "$(dirname "$0")/../.."
out=evidence/jb-os1/conformance-suite
mkdir -p "$out"
sha256sum jaso/src/conformance.rs jaso/src/vectors.rs jaso/src/vector_tests.rs tools/jasopack/src/main.rs \
  verification/toolbox/tests/jaso.rs verification/toolbox/fuzz/fuzz_targets/jaso_conformance.rs \
  verification/toolbox/verus/jaso_conformance.rs verification/toolbox/verus/jaso_conformance_bad.rs > "$out/source.sha256"
(cd jaso/vectors && sha256sum *.jaso *.expect jasper.dev.pub) > "$out/vectors.sha256"
verus=/home/jasper/verus/verus
export PATH=/home/jasper/verus:$PATH
"$verus" verification/toolbox/verus/jaso_conformance.rs > "$out/verus.log" 2>&1
if "$verus" verification/toolbox/verus/jaso_conformance_bad.rs > "$out/verus-bad.log" 2>&1; then
  echo "负例意外通过" >&2; exit 1
fi
cargo test -p jaso --features pack > "$out/host.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test jaso > "$out/proptest.log" 2>&1
MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test -p jaso --features pack -- \
  vector_tests::a_bad_trust_key_never_admits vector_tests::every_vector_yields_its_expected_line > "$out/miri.log" 2>&1
(cd verification/toolbox/fuzz && mkdir -p corpus/jaso_conformance && \
  cargo fuzz run jaso_conformance corpus/jaso_conformance seeds/jaso_conformance -- -runs=1000000 -seed=1) > "$out/fuzz.log" 2>&1
grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
grep -Eq 'error|verified, [1-9]' "$out/verus-bad.log"
grep -q 'test result: ok. 56 passed' "$out/host.log"
grep -q 'test result: ok. 8 passed; 0 failed' "$out/proptest.log"
grep -q 'test result: ok. 2 passed; 0 failed' "$out/miri.log"
grep -q 'Done 1000000 runs' "$out/fuzz.log"
printf 'JB-OS1 conformance Verus/Proptest/Miri/fuzz completed; Kani N/A, Loom N/A (see PROPERTIES.md)\n' | tee "$out/PASS"
