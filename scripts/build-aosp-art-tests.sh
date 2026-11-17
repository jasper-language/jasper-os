#!/usr/bin/env bash
# Build the upstream AOSP ART smoke-test DEX files with the official src/src2
# replacement order. The replacement pass matters for 003-omnibus-opcodes: its
# unresolved-member tests intentionally replace the compiled "happy" class.
set -euo pipefail

COMMIT="${AOSP_ART_COMMIT:-3c05e56adf5b268ec5b20bf8aec460815e45161c}"
OUT="${AOSP_ART_TESTS_OUT:-}"
if [ -z "$OUT" ]; then
  echo "build-aosp-art-tests: set AOSP_ART_TESTS_OUT to an output directory" >&2
  exit 64
fi

D8="${D8_BIN:-$(command -v d8 || true)}"
if [ -z "$D8" ] || [ ! -x "$D8" ]; then
  echo "build-aosp-art-tests: set D8_BIN to Android d8" >&2
  exit 69
fi
for tool in curl tar javac; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "build-aosp-art-tests: missing $tool" >&2
    exit 69
  }
done

mkdir -p "$OUT"
work=$(mktemp -d "${TMPDIR:-/tmp}/jasper-aosp-art.XXXXXX")
cleanup() {
  find "$work" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

build_test() {
  local name=$1
  local destination=$2
  local dir="$work/$name"
  curl -fsSL \
    "https://android.googlesource.com/platform/art/+archive/$COMMIT/test/$name.tar.gz" \
    -o "$work/$name.tar.gz"
  mkdir -p "$dir"
  tar -xzf "$work/$name.tar.gz" -C "$dir"
  mkdir -p "$dir/classes" "$dir/dex"
  (
    cd "$dir"
    javac -g -Xlint:-options -source 1.8 -target 1.8 \
      -d classes src/*.java
    if [ -f javac_post.sh ]; then
      bash javac_post.sh classes
    fi
    if [ -d src2 ]; then
      javac -g -Xlint:-options -source 1.8 -target 1.8 \
        -cp classes -d classes src2/*.java
    fi
    find classes -name '*.class' -print | sort >classes.list
    "$D8" --min-api 34 --output dex @"$dir/classes.list"
    cp dex/classes.dex "$OUT/$destination"
  )
}

build_test 001-HelloWorld art-official-001.dex
build_test 002-sleep art-official-002.dex
build_test 003-omnibus-opcodes art-official-003.dex
printf 'AOSP ART commit %s\n' "$COMMIT" >"$OUT/art-official.build-manifest"
printf 'build-aosp-art-tests: PASS output=%s\n' "$OUT"
