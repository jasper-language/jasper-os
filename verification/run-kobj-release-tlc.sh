#!/usr/bin/env bash
# Run through vm-run.sh. Positive and negative ObjectTable release-protocol models.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}"
if [ ! -f "$jar" ]; then
    curl -fsSL --retry 3 \
        https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
        -o "$jar"
fi
meta="$(mktemp -d)"
trap 'rm -rf -- "$meta"' EXIT
cp "$here/kobj_release.tla" "$meta/"
java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 2 -cleanup \
    -metadir "$meta/states-positive" \
    -config "$here/kobj_release.cfg" "$meta/kobj_release.tla"
for negative in kobj_release_missing_hook kobj_release_duplicate_hook; do
    if java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 2 -cleanup \
        -metadir "$meta/states-$negative" \
        -config "$here/$negative.cfg" "$meta/kobj_release.tla"; then
        echo "negative model unexpectedly passed: $negative" >&2
        exit 1
    fi
done
