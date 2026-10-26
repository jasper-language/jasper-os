#!/usr/bin/env bash
# Author: chatgpt. Run through the absolute VM wrapper only.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA_JAR:-${TMPDIR:-/tmp}/tla2tools-1.8.0.jar}"
[[ -f "$jar" ]] || curl -fsSL --retry 3 https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o "$jar"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cp "$here/krn3_percpu_migration.tla" "$work/"
cd "$work"
java -cp "$jar" tlc2.TLC -workers 1 -cleanup -metadir "$work/good" -config "$here/krn3_percpu_migration.cfg" krn3_percpu_migration.tla > positive.log 2>&1 || { cat positive.log; exit 1; }
grep -q 'Model checking completed. No error has been found.' positive.log
set +e
java -cp "$jar" tlc2.TLC -workers 1 -cleanup -metadir "$work/bad" -config "$here/krn3_percpu_migration_broken.cfg" krn3_percpu_migration.tla > negative.log 2>&1
status=$?
set -e
[[ $status -ne 0 ]]
grep -q 'Invariant Safety is violated' negative.log
cat positive.log
printf 'strict negative violated Safety as expected\n'
