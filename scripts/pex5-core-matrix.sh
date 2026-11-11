#!/usr/bin/env bash
# Run the PEX-5 host heap size-class and growth-tail matrix.
# 运行 PEX-5 宿主堆尺寸类与增长尾部矩阵。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${PEX5_CORE_OUT:-$ROOT/evidence/pex5-core-$(date '+%Y%m%d-%H%M%S')}"
mkdir -p "$OUT"

cargo test --locked --release -p kernel-core --test heap_size_classes -- --nocapture \
  | tee "$OUT/heap-size-classes.log"

python3 scripts/pex5-core-matrix.py \
  --input "$OUT/heap-size-classes.log" \
  --out "$OUT"
