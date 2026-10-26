#!/usr/bin/env bash
# Author: chatgpt. Controlled FV-3 Handle/Rights slice; run via vm-run only.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=evidence/fv3/handle-suite
mkdir -p "$out"
rustc --version > "$out/rustc-version.log"
cargo kani --version > "$out/kani-version.log"
cargo fuzz --version > "$out/fuzz-version.log"
sha256sum kernel-core/src/object.rs kernel-core/src/fv1.rs \
  verification/toolbox/tests/handle_sequence.rs \
  verification/toolbox/fuzz/fuzz_targets/handle_sequence.rs \
  verification/toolbox/negative/transfer.rs > "$out/source.sha256"

cargo test --manifest-path verification/toolbox/Cargo.toml \
  --test handle_sequence > "$out/proptest-loom.log" 2>&1

cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml \
  --test handle_sequence transfer_restrict_remove_matches_single_owner_reference \
  > "$out/miri.log" 2>&1

(cd verification/toolbox/fuzz && \
  cargo fuzz run handle_sequence -- -runs=10000) > "$out/fuzz.log" 2>&1

cargo kani -p kernel-core \
  --harness rights_access_and_reduction_do_not_escalate \
  > "$out/kani-rights.log" 2>&1
cargo kani -p kernel-core \
  --harness cross_table_transfer_is_atomic_and_preserves_rights \
  > "$out/kani-transfer.log" 2>&1

bash verification/toolbox/run-negative-transfer.sh \
  > "$out/strict-negative.log" 2>&1

grep -q '2 passed; 0 failed' "$out/proptest-loom.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#10000.*DONE' "$out/fuzz.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-rights.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-transfer.log"
grep -q 'missing-authority mutation produced assertion counterexample' "$out/strict-negative.log"
printf 'FV-3 Handle/Rights Proptest, Miri, fuzz, Kani, Loom and strict negative completed\n' | tee "$out/PASS"
