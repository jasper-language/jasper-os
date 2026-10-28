#!/usr/bin/env bash
# Regenerates the conformance vectors (SPEC §14) in this directory from the reference generator.
# 由参考实现的生成器重建本目录的一致性向量；`cargo test -p jaso --features pack` 会逐字节比对。
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/../.."
cargo run --quiet -p jasopack -- vectors "$here"
