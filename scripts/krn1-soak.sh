#!/usr/bin/env bash
# Author: chatgpt. Run through vm-run.sh; a single 8-vCPU guest for 8 host hours.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
mkdir -p evidence/krn1
bash verification/run-soak-tlc.sh > evidence/krn1/soak-tlc.log 2>&1
cargo build --locked --release -p xtask > evidence/krn1/soak-xtask.log 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features krn1-soak > evidence/krn1/soak-build.log 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel evidence/krn1/soak.img > evidence/krn1/soak-image.log 2>&1
sha256sum target/x86_64-unknown-none/release/jasper-kernel evidence/krn1/soak.img > evidence/krn1/soak-sha256.txt
out="evidence/krn1/soak-$(date -u +%Y%m%dT%H%M%SZ)"
printf '%s\n' "$out" > evidence/krn1/soak-active.txt
python3 tools/krn1/soak.py --seconds 28800 --out "$out" --image evidence/krn1/soak.img
