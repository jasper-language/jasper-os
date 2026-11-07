#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
jar=${TLA2TOOLS_JAR:-/home/auth/Documents/jasper/jasper/build/tools/tla2tools.jar}
if [[ ! -f "$jar" ]]; then
  echo "missing TLA2TOOLS_JAR=$jar" >&2
  exit 2
fi
mkdir -p evidence
java -cp "$jar" tlc2.TLC -workers 1 -config verification/s4_leaf_interleaving.cfg \
  verification/s4_leaf_interleaving.tla > evidence/s4-leaf-interleaving.log 2>&1
if java -cp "$jar" tlc2.TLC -workers 1 -config verification/s4_leaf_interleaving_broken.cfg \
  verification/s4_leaf_interleaving.tla > evidence/s4-leaf-interleaving-broken.log 2>&1; then
  echo "stale-generation negative unexpectedly passed" >&2
  exit 1
fi
grep -q "No error has been found" evidence/s4-leaf-interleaving.log
grep -q "Invariant Safety is violated" evidence/s4-leaf-interleaving-broken.log
echo "S-4 leaf interleaving TLA: positive PASS; stale-generation negative rejected"
