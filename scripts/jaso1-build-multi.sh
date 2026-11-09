#!/usr/bin/env bash
# Build one signed four-ISA .jaso container used by all JASO-1 QEMU runs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/evidence/jaso1-multi-$(date '+%Y%m%d-%H%M%S')}"
CORES="${JASO1_CORES:-4-11}"
mkdir -p "$OUT"
export PATH="$HOME/.cargo/bin:$PATH"

case "$CORES" in
  *0*|*1*|*2*|*3*)
    case ",$CORES," in
      *,0,*|*,1,*|*,2,*|*,3,*)
        echo "JASO-1: CPU 0-3 are forbidden (got $CORES)" >&2
        exit 2
        ;;
    esac
    ;;
esac

TOOL_TARGET="$OUT/tool-target"
MODULES_OUT="$OUT/jaso-demo-multi.jaso"
taskset -c "$CORES" env CARGO_TARGET_DIR="$TOOL_TARGET" \
  cargo build --locked --release -p jasopack >"$OUT/tool-build.log" 2>&1
taskset -c "$CORES" "$TOOL_TARGET/release/jasopack" \
  build-multi-dev jaso-demo modules/demo "$MODULES_OUT" \
  x86_64 aarch64 riscv64 riscv32 >"$OUT/build.log" 2>&1
"$TOOL_TARGET/release/jasopack" inspect "$MODULES_OUT" >"$OUT/inspect.log" 2>&1
sha256sum "$MODULES_OUT" >"$OUT/sha256.txt"
printf 'multi=%s\ncores=%s\n' "$MODULES_OUT" "$CORES"
