#!/usr/bin/env bash
# Author: chatgpt. Same runner for CI and the Jasper build VM.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p evidence/fv1
cargo kani --version | tee evidence/fv1/version.log
grep -q '0.68.0' evidence/fv1/version.log
# Every symbolic input-domain restriction is reviewed and pinned by file/count.
# New, changed-count, or unreviewed assumptions and stubs fail closed.
python3 verification/check-kani-assumptions.py --self-test
sha256sum kernel-core/src/fv1.rs kernel-core/src/object.rs kernel-core/src/objtable.rs \
  kernel-core/src/memory_object.rs kernel-core/src/cpu_time.rs kernel-core/src/subscription.rs kernel-core/src/async_ring.rs kernel/src/proc/mod.rs kernel-core/src/quota.rs kernel/src/ring.rs kernel/src/ipc.rs kernel-core/Cargo.toml Cargo.lock > evidence/fv1/source.sha256
sha256sum kernel-core/src/percpu_migration.rs verification/FV1.toml \
  verification/check-kani-assumptions.py >> evidence/fv1/source.sha256
cargo kani -p kernel-core > evidence/fv1/kani.log 2>&1
# Do not use a grep result to mask cargo kani failure; set -e above is decisive.
tail -18 evidence/fv1/kani.log
python3 verification/check-fv1.py
