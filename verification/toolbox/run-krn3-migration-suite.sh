#!/usr/bin/env bash
# Author: chatgpt. Controlled KRN-3 protocol slice; vm-run only.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=evidence/krn3/migration-suite
mkdir -p "$out"
sha256sum kernel-core/src/percpu_migration.rs verification/krn3_percpu_migration.tla \
 verification/toolbox/tests/percpu_migration.rs verification/toolbox/fuzz/fuzz_targets/percpu_migration.rs \
 verification/toolbox/verus/percpu_migration.rs > "$out/source.sha256"
bash verification/run-krn3-percpu-migration-tlc.sh > "$out/tlc.log" 2>&1
cargo test -p kernel-core percpu_migration > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test percpu_migration > "$out/proptest-loom.log" 2>&1
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test percpu_migration \
 ordered_migration_finishes_at_exactly_one_cpu > "$out/miri.log" 2>&1
(cd verification/toolbox/fuzz && cargo fuzz run percpu_migration -- -runs=10000) > "$out/fuzz.log" 2>&1
cargo kani -p kernel-core --harness ordered_pair_is_strict_and_migration_has_one_owner > "$out/kani-migration.log" 2>&1
cargo kani -p kernel-core --harness pi_message_applies_at_most_once_to_matching_generation > "$out/kani-pi.log" 2>&1
cargo kani -p kernel-core --harness pi_mailbox_preserves_latest_round_without_duplicate_entry > "$out/kani-mailbox.log" 2>&1
verus=$(find evidence/shm1/toolbox/verus -type f -name verus -perm /111 | head -1)
"$verus" verification/toolbox/verus/percpu_migration.rs > "$out/verus.log" 2>&1
grep -q 'Model checking completed. No error has been found.' "$out/tlc.log"
grep -q 'strict negative violated Safety as expected' "$out/tlc.log"
grep -q '4 passed; 0 failed' "$out/core.log"
grep -q '4 passed; 0 failed' "$out/proptest-loom.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#10000.*DONE' "$out/fuzz.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-migration.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-pi.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-mailbox.log"
grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
printf 'KRN-3 migration protocol TLA/Verus/Proptest/Miri/fuzz/Kani/Loom completed\n' | tee "$out/PASS"
