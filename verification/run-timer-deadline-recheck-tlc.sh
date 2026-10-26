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
cp "$here/timer_deadline_recheck.tla" "$work/"
cp "$here/${1:-timer_deadline_recheck.cfg}" "$work/selected.cfg"
cd "$work"
java -Xmx128m -XX:+UseSerialGC -cp "$jar" tlc2.TLC -workers 1 -cleanup -metadir "$work/states" -config selected.cfg timer_deadline_recheck.tla
