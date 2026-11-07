#!/usr/bin/env bash
# Check the Ring object-table interval, then require both unsafe negatives to fail.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}"
if [ ! -f "$jar" ]; then
    curl -fsSL --retry 3 \
        https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
        -o "$jar"
fi
work="$(mktemp -d)"
cleanup() {
    local rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ]; then
        for log in "$work"/*.log; do
            [ -f "$log" ] || continue
            printf '===== %s =====\n' "$(basename "$log")"
            cat "$log"
        done
    fi
    find "$work" -type f -delete
    find "$work" -depth -type d -empty -delete
    exit "$rc"
}
trap cleanup EXIT

run_model() {
    local name="$1" cfg="$2"
    java -Xmx128m -XX:+UseSerialGC -cp "$jar" tlc2.TLC \
        -workers 1 -cleanup -metadir "$work/$name" \
        -config "$here/$cfg" "$here/ring_lock_scope.tla" > "$work/$name.log" 2>&1
}

run_model positive ring_lock_scope.cfg
grep -q 'Model checking completed. No error has been found.' "$work/positive.log"

if run_model nested ring_lock_scope_nested.cfg; then
    echo "nested-acquisition negative unexpectedly passed" >&2
    exit 1
fi
grep -q 'Invariant NoNestedObjectAcquire is violated' "$work/nested.log"

if run_model blocking ring_lock_scope_blocking.cfg; then
    echo "blocking negative unexpectedly passed" >&2
    exit 1
fi
grep -q 'Invariant NoTaskBlockWhileLocked is violated' "$work/blocking.log"

tail -8 "$work/positive.log"
printf '%s\n' 'Ring lock-scope TLA: positive PASS; nested-acquisition and blocking negatives rejected'
