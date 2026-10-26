#!/usr/bin/env bash
# Author: chatgpt. Run only through the absolute vm-run wrapper.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=evidence/fv3/verus
mkdir -p "$out"
binary=$(find evidence/shm1/toolbox/verus -type f -name verus -perm /111 | head -1)
[[ -n "$binary" ]]
sha256sum verification/toolbox/verus/handle_rights.rs \
  verification/toolbox/verus/handle_rights_bad.rs > "$out/source.sha256"
"$binary" --version > "$out/version.log" 2>&1
"$binary" verification/toolbox/verus/handle_rights.rs > "$out/positive.log" 2>&1
grep -Eq '[1-9][0-9]* verified, 0 errors' "$out/positive.log"
set +e
"$binary" verification/toolbox/verus/handle_rights_bad.rs > "$out/negative.log" 2>&1
status=$?
set -e
[[ "$status" -ne 0 ]]
grep -Eq 'postcondition|verification error|failed' "$out/negative.log"
printf 'FV-3 Verus positive and strict negative completed\n' | tee "$out/PASS"
