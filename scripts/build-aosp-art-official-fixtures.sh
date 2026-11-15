#!/usr/bin/env bash
# Build unmodified AOSP ART Java tests into isolated DEX fixtures.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_TREE="${1:?usage: build-aosp-art-official-fixtures.sh ANDROID_TREE}"
ART_COMMIT="${ART_COMMIT:-3c05e56adf5b268ec5b20bf8aec460815e45161c}"
D8="${D8:-/home/auth/.cache/jasper-abi-runtime-test/android-buildtools/sdk34/android-14/d8}"
WORK="${ART_FIXTURE_WORK:-$(mktemp -d /tmp/jasper-art-official.XXXXXX)}"
ARCHIVE_BASE="https://android.googlesource.com/platform/art/+archive/${ART_COMMIT}/test"

command -v curl >/dev/null
command -v javac >/dev/null
[ -x "$D8" ]

fetch_test() {
  local test="$1"
  mkdir -p "$WORK/$test"
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
    "$ARCHIVE_BASE/$test.tar.gz" | tar -xz -C "$WORK/$test"
}

build_dex() {
  local test="$1"
  shift
  local classes="$WORK/$test/classes"
  local dex="$WORK/$test/dex"
  mkdir -p "$classes" "$dex"
  find "$WORK/$test/src" -name '*.java' -print0 |
    xargs -0 javac -source 8 -target 8 -d "$classes"
  local inputs=()
  while IFS= read -r -d '' class; do
    inputs+=("$class")
  done < <(find "$classes" -name '*.class' -print0)
  "$D8" --min-api 34 --output "$dex" "${inputs[@]}"
}

fetch_test 001-HelloWorld
fetch_test 002-sleep
fetch_test 003-omnibus-opcodes
(cd "$WORK" && sha256sum -c \
  "$ROOT/verification/fixtures/android/art/source-manifest.sha256")

build_dex 001-HelloWorld
build_dex 002-sleep
build_dex 003-omnibus-opcodes

mkdir -p "$WORK/harness/classes" "$WORK/harness/dex"
javac -source 8 -target 8 -d "$WORK/harness/classes" \
  "$ROOT/verification/fixtures/android/art/HelloJvm.java"
"$D8" --min-api 34 --output "$WORK/harness/dex" \
  "$WORK/harness/classes/HelloJvm.class"

destination="$OUT_TREE/data/local/tmp"
mkdir -p "$destination"
cp "$WORK/harness/dex/classes.dex" "$destination/classes.dex"
cp "$WORK/001-HelloWorld/dex/classes.dex" \
  "$destination/art-official-001.dex"
cp "$WORK/002-sleep/dex/classes.dex" \
  "$destination/art-official-002.dex"
cp "$WORK/003-omnibus-opcodes/dex/classes.dex" \
  "$destination/art-official-003.dex"

{
  printf 'aosp_art_commit=%s\n' "$ART_COMMIT"
  for test in 001-HelloWorld 002-sleep 003-omnibus-opcodes; do
    find "$WORK/$test/src" -type f -name '*.java' -print0 |
      sort -z |
      xargs -0 sha256sum
    sha256sum "$WORK/$test/dex/classes.dex"
  done
  sha256sum "$WORK/harness/dex/classes.dex"
} >"$destination/art-official.manifest"

printf 'AOSP ART fixtures: PASS commit=%s work=%s out=%s\n' \
  "$ART_COMMIT" "$WORK" "$destination"
