#!/usr/bin/env bash
# Build the PEX-4 local selection probe image inside the build VM.
# 在构建虚拟机内生成 PEX-4 本地选择探测镜像。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${PEX4_IMAGE_OUT:-$ROOT/evidence/pex4-image-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target/pex4}"
mkdir -p "$OUT"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none \
  -p jasper-kernel \
  --features pex4-verify | tee "$OUT/build.log"

cargo build --locked --release -p xtask | tee -a "$OUT/build.log"
./target/release/xtask \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" \
  "$OUT/kernel.img" | tee "$OUT/image.log"

test -s "$OUT/kernel.img"
printf 'PEX-4 image: %s\n' "$OUT/kernel.img"
