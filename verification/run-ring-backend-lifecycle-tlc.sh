#!/usr/bin/env bash
# Exercise the Ring backend release model, then prove both negative controls fail.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}"
if [ ! -f "$jar" ]; then
    curl -fsSL --retry 3 https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o "$jar"
fi
work="$(mktemp -d)"
cleanup() {
    local rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ]; then
        for log in "$work"/*.log; do
            [ -f "$log" ] || continue
            echo "===== $(basename "$log") ====="
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
        -config "$here/$cfg" "$here/ring_backend_lifecycle.tla" > "$work/$name.log" 2>&1
}

run_model positive ring_backend_lifecycle.cfg
grep -q 'Model checking completed. No error has been found.' "$work/positive.log"

if run_model double_release ring_backend_lifecycle_double_release.cfg; then
    echo "double-release negative unexpectedly passed" >&2
    exit 1
fi
grep -q 'Invariant ReleaseAtMostOnce is violated' "$work/double_release.log"

if run_model early_publish ring_backend_lifecycle_early_publish.cfg; then
    echo "early-publication negative unexpectedly passed" >&2
    exit 1
fi
grep -q 'Invariant BufferPublishedOnlyAfterRelease is violated' "$work/early_publish.log"

cat "$work/positive.log" | tail -8
printf '%s\n' 'Ring backend lifecycle TLA: positive PASS; double-release and early-publication negatives rejected'
