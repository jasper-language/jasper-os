#!/usr/bin/env bash
# Run inside the build VM, like the existing TLB model checker.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}"
if [ ! -f "$jar" ]; then
    curl -fsSL --retry 3 https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o "$jar"
fi
meta="$(mktemp -d)"
trap 'find "$meta" -type f -delete; find "$meta" -depth -type d -empty -delete' EXIT
# Author: chatgpt. Negative TLC traces must not mutate the source tree.
cp "$here/mmio_rollback.tla" "$meta/mmio_rollback.tla"
cp "$here/${1:-mmio_rollback.cfg}" "$meta/model.cfg"
java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 2 -cleanup -metadir "$meta/states" \
    -config "$meta/model.cfg" "$meta/mmio_rollback.tla"
