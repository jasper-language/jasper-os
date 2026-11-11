#!/usr/bin/env bash
# Build the PEX-3 x86_64 acceptance image inside the dedicated build VM.
# 在专用构建虚拟机内生成 PEX-3 的 x86_64 验收镜像。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${PEX3_IMAGE_OUT:-$ROOT/evidence/pex3-image-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target/pex3}"
mkdir -p "$OUT"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none \
  -p jasper-kernel \
  --features pex3-verify | tee "$OUT/build.log"

cargo build --locked --release -p xtask | tee -a "$OUT/build.log"
./target/release/xtask \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" \
  "$OUT/kernel.img" | tee "$OUT/image.log"

test -s "$OUT/kernel.img"
printf 'PEX-3 image: %s\n' "$OUT/kernel.img"
