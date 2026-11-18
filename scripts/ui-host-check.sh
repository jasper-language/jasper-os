#!/usr/bin/env bash
# Verify the Jasper-OS UI host adapter without claiming that the pinned engine is ready.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"

OUT="${UI_HOST_OUT:-$ROOT/evidence/ui-host-adapter-$(date '+%Y%m%d-%H%M%S')}"
mkdir -p "$OUT"

env -u CARGO_TARGET_DIR JASPER_BUILD_ALLOW_VBOX="${JASPER_BUILD_ALLOW_VBOX:-1}" \
  JASPER_BUILD_CPUS="${JASPER_BUILD_CPUS:-4-5}" \
  scripts/guarded-cargo.sh test --locked -p user-ui-service --lib \
  >"$OUT/service-test.log" 2>&1
env -u CARGO_TARGET_DIR JASPER_BUILD_ALLOW_VBOX="${JASPER_BUILD_ALLOW_VBOX:-1}" \
  JASPER_BUILD_CPUS="${JASPER_BUILD_CPUS:-4-5}" \
  scripts/guarded-cargo.sh build --locked -p user-ui-service --bin ui-service \
  --target x86_64-unknown-none --features native-transport,native-engine-core --release \
  >"$OUT/service-build.log" 2>&1
env -u CARGO_TARGET_DIR JASPER_BUILD_ALLOW_VBOX="${JASPER_BUILD_ALLOW_VBOX:-1}" \
  JASPER_BUILD_CPUS="${JASPER_BUILD_CPUS:-4-5}" \
  scripts/guarded-cargo.sh check --locked -p jasper-kernel \
  --target x86_64-unknown-none --no-default-features \
  >"$OUT/kernel-check.log" 2>&1

ELF="$ROOT/target/x86_64-unknown-none/release/ui-service"
readelf -h "$ELF" >"$OUT/elf-header.txt"
grep -Eq 'Type:[[:space:]]+EXEC' "$OUT/elf-header.txt"
readelf -S "$ELF" >"$OUT/elf-sections.txt"
grep -q '\.note\.jasper\.abi' "$OUT/elf-sections.txt"
grep -q '\.note\.jasper\.caps' "$OUT/elf-sections.txt"

python3 scripts/check-ui-engine-pin.py --self-test >"$OUT/ui-pin.log"
python3 scripts/check-ui-engine-pin.py >>"$OUT/ui-pin.log"
python3 scripts/check-gpu-abi-boundary.py --self-test >"$OUT/gpu-boundary.log"
python3 scripts/check-gpu-abi-boundary.py >>"$OUT/gpu-boundary.log"

printf '%s\n' \
  "ui-host: PASS engine=cpu transport=channel frame=rgba8 kernel_linked=false" \
  "engine_commit=b21dec1ae504a06923defcc715722c7b9e9c1dc8" \
  "evidence=$OUT"
