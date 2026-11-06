#!/usr/bin/env bash
# Positive and negative TLC model for the unified timer identity integration.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}"
if [ ! -f "$jar" ]; then
  curl -fsSL --retry 3 https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o "$jar"
fi
work="$(mktemp -d)"
trap 'find "$work" -type f -delete; find "$work" -depth -type d -empty -delete' EXIT
if ! java -Xmx128m -XX:+UseSerialGC -cp "$jar" tlc2.TLC -workers 1 -cleanup \
  -metadir "$work/positive" -config "$here/timer_identity_integration.cfg" \
  "$here/timer_identity_integration.tla" >"$work/positive.log" 2>&1; then
  cat "$work/positive.log"
  exit 1
fi
grep -q 'Model checking completed. No error has been found.' "$work/positive.log"
if java -Xmx128m -XX:+UseSerialGC -cp "$jar" tlc2.TLC -workers 1 -cleanup \
  -metadir "$work/stale" -config "$here/timer_identity_integration_stale.cfg" \
  "$here/timer_identity_integration.tla" >"$work/stale.log" 2>&1; then
  echo "stale mutation negative model unexpectedly passed" >&2
  exit 1
fi
grep -Eq 'Invariant (BudgetExact|StaleNeverMutatesLive) is violated' "$work/stale.log"
tail -8 "$work/positive.log"
printf '%s\n' 'Timer identity integration TLA: positive PASS; stale mutation rejected'
