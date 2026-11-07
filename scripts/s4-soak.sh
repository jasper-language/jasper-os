#!/usr/bin/env bash
# Build one exact S-4 KVM image, then run the host-monotonic short campaign.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

seconds=${1:-${S4_SECONDS:-300}}
cores=${S4_CORES:-4-11}
out="evidence/s4/soak-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p evidence/s4

cargo build --locked --release -p xtask > evidence/s4/xtask.log 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel \
  --no-default-features --features s4-soak > evidence/s4/build.log 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel evidence/s4/s4.img \
  > evidence/s4/image.log 2>&1
sha256sum target/x86_64-unknown-none/release/jasper-kernel evidence/s4/s4.img \
  > evidence/s4/s4-sha256.txt
printf '%s\n' "$out" > evidence/s4/soak-active.txt
python3 tools/s4/soak.py --seconds "$seconds" --out "$out" \
  --image evidence/s4/s4.img --cores "$cores"
touch "$out/PASS"
