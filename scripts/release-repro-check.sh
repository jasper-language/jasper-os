#!/bin/bash
# Verify deterministic x86_64 kernel release builds without starting a VM.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET=x86_64-unknown-none
PACKAGE=jasper-kernel
A="${ROOT}/target/release-repro-a"
B="${ROOT}/target/release-repro-b"
jobs="${JASPER_REPRO_JOBS:-2}"
cpus="${JASPER_REPRO_CPUS:-4-11}"

affinity=()
affinity_status="scheduler-selected"
if taskset -c "$cpus" true 2>/dev/null; then
  affinity=(taskset -c "$cpus")
  affinity_status="$cpus"
else
  echo "release-repro: affinity=$cpus unavailable; using scheduler-selected CPUs" >&2
fi

build() {
  local target_dir=$1
  find "$target_dir" -depth -delete 2>/dev/null || true
  env \
    SOURCE_DATE_EPOCH=0 \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS="$jobs" \
    CARGO_TARGET_DIR="$target_dir" \
    RUSTFLAGS='--cfg sha2_backend="soft" --cfg curve25519_dalek_backend="serial" -C metadata=jasper-release-repro' \
    "${affinity[@]}" cargo build \
      --locked \
      --release \
      --target "$TARGET" \
      --no-default-features \
      -p "$PACKAGE"
}

echo "release-repro: build A"
build "$A"
echo "release-repro: build B"
build "$B"

ELF_A="$A/$TARGET/release/jasper-kernel"
ELF_B="$B/$TARGET/release/jasper-kernel"
HASH_A="$(sha256sum "$ELF_A" | cut -d' ' -f1)"
HASH_B="$(sha256sum "$ELF_B" | cut -d' ' -f1)"

if [ "$HASH_A" != "$HASH_B" ]; then
  echo "release-repro: FAIL a=$HASH_A b=$HASH_B" >&2
  exit 1
fi

printf 'release-repro: PASS target=%s affinity=%s sha256=%s\n' \
  "$TARGET" "$affinity_status" "$HASH_A"
