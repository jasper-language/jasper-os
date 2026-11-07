#!/usr/bin/env bash
# Positive path requires canonical serialization; both unsafe bypasses must fail.
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
        -config "$here/$cfg" "$here/owner_leaf_fast_path.tla" > "$work/$name.log" 2>&1
}

run_model positive owner_leaf_fast_path.cfg
grep -q 'Model checking completed. No error has been found.' "$work/positive.log"

if run_model race owner_leaf_fast_path_race.cfg; then
    echo "migration-during-local-lease negative unexpectedly passed" >&2
    exit 1
fi
grep -q 'Invariant NoStaleWake is violated' "$work/race.log"

if run_model nonowner owner_leaf_fast_path_nonowner.cfg; then
    echo "non-owner publication negative unexpectedly passed" >&2
    exit 1
fi
grep -q 'Invariant NoStaleWake is violated' "$work/nonowner.log"

tail -8 "$work/positive.log"
printf '%s\n' 'owner-leaf fast path TLA: serialized restricted path PASS; migration and non-owner negatives rejected'
