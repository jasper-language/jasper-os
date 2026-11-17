#!/bin/bash
# Exercise LC-5 signed release verification, trust rotation/revocation, and
# two-HTTPS-source plus offline distribution parity without production keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

KERNEL="${JASPER_RELEASE_KERNEL:-target/release-repro-a/x86_64-unknown-none/release/jasper-kernel}"
SBOM="${JASPER_RELEASE_SBOM:-target/jasper-os-sbom.cdx.json}"
[[ -f "$KERNEL" ]] || { echo "release-supply-check: missing kernel: $KERNEL" >&2; exit 1; }
if [[ ! -f "$SBOM" ]]; then
  python3 scripts/release-sbom.py --output "$SBOM"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/jasper-release-supply.XXXXXX")"
trap 'rm -rf "$work"' EXIT

keys="$work/keys"
trusted="$work/trusted"
bundle="$work/bundle"
download="$work/download"
mkdir -p "$keys" "$trusted" "$bundle"

openssl genpkey -algorithm ED25519 -out "$keys/a.private.pem"
openssl pkey -in "$keys/a.private.pem" -pubout -out "$keys/a.public.pem"
openssl genpkey -algorithm ED25519 -out "$keys/b.private.pem"
openssl pkey -in "$keys/b.private.pem" -pubout -out "$keys/b.public.pem"

fp_a="$(python3 scripts/release-artifact.py fingerprint --public-key "$keys/a.public.pem" | cut -d= -f2)"
fp_b="$(python3 scripts/release-artifact.py fingerprint --public-key "$keys/b.public.pem" | cut -d= -f2)"
cp "$keys/a.public.pem" "$trusted/$fp_a.pem"
cp "$keys/b.public.pem" "$trusted/$fp_b.pem"

abi="$(
  sed -n 's/^major = //p' abi/abi-version.txt
).$(
  sed -n 's/^minor = //p' abi/abi-version.txt
).$(
  sed -n 's/^patch = //p' abi/abi-version.txt
)"
commit="$(git rev-parse HEAD)"
cp "$KERNEL" "$bundle/jasper-kernel"
cp "$SBOM" "$bundle/sbom.json"

python3 scripts/release-artifact.py create \
  --payload "$bundle/jasper-kernel" \
  --sbom "$bundle/sbom.json" \
  --private-key "$keys/a.private.pem" \
  --output-dir "$bundle" \
  --name release \
  --channel stable \
  --source-commit "$commit" \
  --target x86_64-unknown-none \
  --abi "$abi"

verify() {
  local manifest=$1 signature=$2 payload=$3 sbom=$4
  python3 scripts/release-artifact.py verify \
    --manifest "$manifest" \
    --signature "$signature" \
    --payload "$payload" \
    --sbom "$sbom" \
    --trusted-dir "$trusted" \
    --revoked "$work/revoked.txt"
}

: > "$work/revoked.txt"
verify \
  "$bundle/release.manifest.json" \
  "$bundle/release.manifest.sig" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json"

printf '%s\n' "$fp_a" > "$work/revoked.txt"
if verify \
  "$bundle/release.manifest.json" \
  "$bundle/release.manifest.sig" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json" 2>"$work/revoked.err"; then
  echo "release-supply-check: revoked key was accepted" >&2
  exit 1
fi
grep -q 'signer is revoked' "$work/revoked.err"

python3 scripts/release-artifact.py create \
  --payload "$bundle/jasper-kernel" \
  --sbom "$bundle/sbom.json" \
  --private-key "$keys/b.private.pem" \
  --output-dir "$bundle" \
  --name rotated \
  --channel lts \
  --source-commit "$commit" \
  --target x86_64-unknown-none \
  --abi "$abi"
verify \
  "$bundle/rotated.manifest.json" \
  "$bundle/rotated.manifest.sig" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json"

# Rotate the trusted root set: A is retired, B remains sufficient.
mv "$trusted/$fp_a.pem" "$work/retired-a.pem"
verify \
  "$bundle/rotated.manifest.json" \
  "$bundle/rotated.manifest.sig" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json"

mkdir -p "$work/tampered"
cp "$bundle/rotated.manifest.json" "$work/tampered/release.manifest.json"
cp "$bundle/rotated.manifest.sig" "$work/tampered/release.manifest.sig"
cp "$bundle/sbom.json" "$work/tampered/sbom.json"
cp "$bundle/jasper-kernel" "$work/tampered/jasper-kernel"
python3 - "$work/tampered/jasper-kernel" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
data[len(data) // 2] ^= 1
path.write_bytes(data)
PY
: > "$work/revoked.txt"
if verify \
  "$work/tampered/release.manifest.json" \
  "$work/tampered/release.manifest.sig" \
  "$work/tampered/jasper-kernel" \
  "$work/tampered/sbom.json" 2>"$work/tampered.err"; then
  echo "release-supply-check: tampered payload was accepted" >&2
  exit 1
fi
grep -q 'payload identity does not match' "$work/tampered.err"

cp "$bundle/rotated.manifest.json" "$bundle/release.manifest.json"
cp "$bundle/rotated.manifest.sig" "$bundle/release.manifest.sig"
python3 scripts/release-source-drill.py --bundle "$bundle" --output "$download"
verify \
  "$download/release.manifest.json" \
  "$download/release.manifest.sig" \
  "$download/jasper-kernel" \
  "$download/sbom.json"

echo "release-supply-check: PASS signed=true revocation=true rotation=true https_sources=2 offline_sources=1 tamper_rejected=true"
