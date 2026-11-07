#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
jar=${TLA2TOOLS_JAR:?set TLA2TOOLS_JAR to the TLA+ tools jar}
if [[ ! -f "$jar" ]]; then
  echo "missing TLA2TOOLS_JAR=$jar" >&2
  exit 2
fi
mkdir -p evidence
java -cp "$jar" tlc2.TLC -workers 1 -config verification/fv4_address_lifecycle.cfg \
  verification/fv4_address_lifecycle.tla > evidence/fv4-address-lifecycle.log 2>&1
if java -cp "$jar" tlc2.TLC -workers 1 -config verification/fv4_address_lifecycle_broken.cfg \
  verification/fv4_address_lifecycle.tla > evidence/fv4-address-lifecycle-broken.log 2>&1; then
  echo "unsafe-release negative unexpectedly passed" >&2
  exit 1
fi
grep -q "No error has been found" evidence/fv4-address-lifecycle.log
grep -q "Invariant Safety is violated" evidence/fv4-address-lifecycle-broken.log
echo "FV-4 address lifecycle TLA: positive PASS; unsafe-release negative rejected"
