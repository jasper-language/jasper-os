#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tlc=${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}
if [[ ! -f "$tlc" ]]; then
  curl -fsSL --retry 3 https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o "$tlc"
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here"/rt3_ring_donation{.tla,.cfg,_missing_clear.cfg} "$work"/
cd "$work"
java -Xmx128m -XX:+UseSerialGC -cp "$tlc" tlc2.TLC -deadlock -cleanup -workers 1 -config rt3_ring_donation.cfg rt3_ring_donation.tla
set +e
out=$(java -Xmx128m -XX:+UseSerialGC -cp "$tlc" tlc2.TLC -deadlock -cleanup -workers 1 -config rt3_ring_donation_missing_clear.cfg rt3_ring_donation.tla 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
test "$rc" -ne 0
grep -q 'Invariant Safety is violated' <<<"$out"
