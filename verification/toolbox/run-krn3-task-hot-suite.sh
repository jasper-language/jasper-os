#!/usr/bin/env bash
# Author: chatgpt. Controlled generation-bound task hot-state suite; vm-run only.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=evidence/krn3/task-hot-suite
mkdir -p "$out"
sha256sum kernel-core/src/task_hot.rs verification/toolbox/tests/task_hot.rs \
  verification/toolbox/fuzz/fuzz_targets/task_hot.rs verification/toolbox/verus/task_hot.rs \
  > "$out/source.sha256"
cargo test -p kernel-core task_hot > "$out/core.log" 2>&1
cargo test --manifest-path verification/toolbox/Cargo.toml --test task_hot > "$out/proptest-loom.log" 2>&1
cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test task_hot \
  stale_generation_cannot_touch_reused_slot > "$out/miri.log" 2>&1
(cd verification/toolbox/fuzz && cargo fuzz run task_hot -- -runs=10000) > "$out/fuzz.log" 2>&1
cargo kani -p kernel-core --harness stale_generation_cannot_mutate_reused_slot > "$out/kani-stale.log" 2>&1
cargo kani -p kernel-core --harness wrong_slot_never_changes_owner > "$out/kani-slot.log" 2>&1
verus=$(find evidence/shm1/toolbox/verus -type f -name verus -perm /111 | head -1)
"$verus" verification/toolbox/verus/task_hot.rs > "$out/verus.log" 2>&1
grep -q '1 passed; 0 failed' "$out/core.log"
grep -q '3 passed; 0 failed' "$out/proptest-loom.log"
grep -q '1 passed; 0 failed' "$out/miri.log"
grep -q '#10000.*DONE' "$out/fuzz.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-stale.log"
grep -q 'VERIFICATION:- SUCCESSFUL' "$out/kani-slot.log"
grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/verus.log"
printf 'KRN-3 task hot-state Verus/Proptest/Miri/fuzz/Kani/Loom completed\n' | tee "$out/PASS"
