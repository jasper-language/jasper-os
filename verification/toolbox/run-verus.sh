#!/usr/bin/env bash
# Author: chatgpt. Run through the absolute vm-run wrapper only.
set -euo pipefail
cd "$(dirname "$0")/../.."
setup=evidence/shm1/toolbox/verus
python3 - <<'PY'
import pathlib,zipfile,os
p=pathlib.Path('evidence/shm1/toolbox/verus')
with zipfile.ZipFile(p/'verus.zip') as z:
    z.extractall(p)
    for entry in z.infolist():
        dest=p/entry.filename
        if not entry.is_dir(): dest.chmod((entry.external_attr >> 16) & 0o777 or 0o644)
PY
binary=$(find "$setup" -type f -name verus -perm /111 | head -1)
[[ -n "$binary" ]]
sha256sum "$setup/verus.zip" verification/toolbox/verus/usage.rs > "$setup/source.sha256"
"$binary" --version > "$setup/version.log" 2>&1
"$binary" verification/toolbox/verus/usage.rs > "$setup/usage.log" 2>&1
cat "$setup/usage.log"
