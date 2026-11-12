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
mapfile -t harnesses < <(python3 - <<'PYCODE'
import tomllib

with open("verification/FV1.toml", "rb") as source:
    registry = tomllib.load(source)
for prop in registry["properties"]:
    print(prop["reproduce"].split()[-1])
PYCODE
)
kani_args=()
for harness in "${harnesses[@]}"; do
  kani_args+=(--harness "$harness")
done
if ! cargo kani -p kernel-core "${kani_args[@]}" > evidence/fv1/kani.log 2>&1; then
  tail -120 evidence/fv1/kani.log
  exit 1
fi
tail -18 evidence/fv1/kani.log
python3 verification/check-fv1.py
