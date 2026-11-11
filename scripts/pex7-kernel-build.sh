#!/usr/bin/env bash
# Build the PEX-7 real-kernel frame matrix image inside the build VM.
# 在构建虚拟机内生成 PEX-7 真实内核页帧矩阵镜像。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${PEX7_IMAGE_OUT:-$ROOT/evidence/pex7-image-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target/pex7}"
mkdir -p "$OUT"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none \
  -p jasper-kernel \
  --features pex7-verify | tee "$OUT/build.log"

cargo build --locked --release -p xtask | tee -a "$OUT/build.log"
./target/release/xtask \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" \
  "$OUT/kernel.img" | tee "$OUT/image.log"

test -s "$OUT/kernel.img"
printf 'PEX-7 image: %s\n' "$OUT/kernel.img"
