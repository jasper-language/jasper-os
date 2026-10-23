#!/usr/bin/env bash
# Author: chatgpt. Run through vm-run.sh; isolate TLC counterexample artifacts.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}"
if [ ! -f "$jar" ]; then
    curl -fsSL --retry 3 https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o "$jar"
fi
meta="$(mktemp -d)"
trap 'rm -rf -- "$meta"' EXIT
cp "$here/deadline_owner.tla" "$meta/"
cp "$here/${1:-deadline_owner.cfg}" "$meta/selected.cfg"
cd "$meta"
java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 2 -cleanup -metadir "$meta/states" \
    -config selected.cfg deadline_owner.tla
