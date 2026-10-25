#!/usr/bin/env bash
# Author: chatgpt. Mutate only an isolated copy; require actual test counterexample.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
out="$root/evidence/shm1/toolbox"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -a kernel-core "$tmp/core"
printf '\n[workspace]\n' >> "$tmp/core/Cargo.toml"
cp verification/toolbox/negative/transfer.rs "$tmp/core/tests/s3_negative_transfer.rs"
# Positive must run first, with the real source unchanged.
cargo test --manifest-path "$tmp/core/Cargo.toml" --test s3_negative_transfer > "$out/s3-transfer-positive.log" 2>&1
python3 - "$tmp/core/src/object.rs" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]);s=p.read_text()
old='if !rights.contains(Rights::TRANSFER) { return Err(HandleError::RightsDenied); }'
assert s.count(old)==1
p.write_text(s.replace(old,'// Deliberate negative mutation: omitted TRANSFER authorization.'))
PY
if cargo test --manifest-path "$tmp/core/Cargo.toml" --test s3_negative_transfer > "$out/s3-transfer-negative.log" 2>&1; then
    echo 'Negative mutation unexpectedly passed';exit 1
fi
grep -q 'transfer_without_authority_preserves_source.*FAILED' "$out/s3-transfer-negative.log"
grep -q 'assertion.*failed' "$out/s3-transfer-negative.log"
grep -q 'RightsDenied' "$out/s3-transfer-negative.log"
printf 'Real transfer positive passed; missing-authority mutation produced assertion counterexample\n'
