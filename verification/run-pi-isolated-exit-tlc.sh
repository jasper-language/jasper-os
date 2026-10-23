#!/usr/bin/env bash
# Author: chatgpt. Candidate runner; invoke only through the build VM.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}"
if [[ ! -f "$jar" ]]; then
    curl -fsSL --retry 3 https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o "$jar"
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here/pi_isolated_exit.tla" "$work/"
cp "$here/${1:-pi_isolated_exit.cfg}" "$work/selected.cfg"
cd "$work"
java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 2 -cleanup -metadir "$work/states" -config selected.cfg pi_isolated_exit.tla
