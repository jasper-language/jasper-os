#!/usr/bin/env bash
# Run the PEX-7 host bitmap and cache-model baseline.
# 运行 PEX-7 宿主位图与缓存模型基线。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${PEX7_CORE_OUT:-$ROOT/evidence/pex7-core-$(date '+%Y%m%d-%H%M%S')}"
mkdir -p "$OUT"

cargo test --locked --release -p kernel-core --test frame_cache_baseline -- --nocapture \
  | tee "$OUT/frame-cache-baseline.log"

python3 scripts/pex7-core-matrix.py --input "$OUT/frame-cache-baseline.log" --out "$OUT"
