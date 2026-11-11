#!/usr/bin/env bash
# Build the PEX-5 real-kernel growth image inside the dedicated build VM.
# 在专用构建虚拟机内生成 PEX-5 真实内核增长镜像。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${PEX5_IMAGE_OUT:-$ROOT/evidence/pex5-image-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target/pex5}"
mkdir -p "$OUT"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none \
  -p jasper-kernel \
  --features pex5-verify | tee "$OUT/build.log"

cargo build --locked --release -p xtask | tee -a "$OUT/build.log"
./target/release/xtask \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" \
  "$OUT/kernel.img" | tee "$OUT/image.log"

test -s "$OUT/kernel.img"
printf 'PEX-5 image: %s\n' "$OUT/kernel.img"
