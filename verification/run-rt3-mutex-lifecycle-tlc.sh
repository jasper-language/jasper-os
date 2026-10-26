#!/usr/bin/env bash
# Runs the positive lifecycle model, then requires the missing-retain variant
# to violate Safety. Invoke through the authorised build VM only.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}"
if [[ ! -f "$jar" ]]; then
    curl -fsSL --retry 3 https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o "$jar"
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here/rt3_mutex_lifecycle.tla" "$here/rt3_mutex_lifecycle.cfg" "$here/rt3_mutex_lifecycle_missing_ref.cfg" "$work/"
cd "$work"
java -Xmx128m -XX:+UseSerialGC -cp "$jar" tlc2.TLC -workers 1 -cleanup -metadir "$work/positive" -config rt3_mutex_lifecycle.cfg rt3_mutex_lifecycle.tla | tee positive.log
set +e
java -Xmx128m -XX:+UseSerialGC -cp "$jar" tlc2.TLC -workers 1 -cleanup -metadir "$work/negative" -config rt3_mutex_lifecycle_missing_ref.cfg rt3_mutex_lifecycle.tla >negative.log 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]] || ! grep -q 'Invariant Safety is violated' negative.log; then
    cat negative.log
    echo 'missing-retain negative did not produce the required Safety violation' >&2
    exit 1
fi
grep -E 'states generated|distinct states found|depth of the complete state graph|Invariant Safety is violated' positive.log negative.log || true
