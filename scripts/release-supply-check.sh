#!/bin/bash
# Exercise LC-5 signed release verification, trust rotation/revocation, and
# two-HTTPS-source plus offline distribution parity without production keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

KERNEL="${JASPER_RELEASE_KERNEL:-target/release-repro-a/x86_64-unknown-none/release/jasper-kernel}"
SBOM="${JASPER_RELEASE_SBOM:-target/jasper-os-sbom.cdx.json}"
[[ -f "$KERNEL" ]] || { echo "release-supply-check: missing kernel: $KERNEL" >&2; exit 1; }
if [[ "${JASPER_RELEASE_SBOM_EXISTING:-0}" != 1 ]]; then
  python3 scripts/release-sbom.py --output "$SBOM"
fi
[[ -f "$SBOM" ]] || { echo "release-supply-check: missing SBOM: $SBOM" >&2; exit 1; }

work="$(mktemp -d "${TMPDIR:-/tmp}/jasper-release-supply.XXXXXX")"
trap 'rm -rf "$work"' EXIT
software_anchor=(--development-software-anchor)

keys="$work/keys"
trusted="$work/trusted"
bundle="$work/bundle"
download="$work/download"
mkdir -p "$keys" "$trusted" "$bundle"

openssl genpkey -algorithm ED25519 -out "$keys/a.private.pem"
openssl pkey -in "$keys/a.private.pem" -pubout -out "$keys/a.public.pem"
openssl genpkey -algorithm ED25519 -out "$keys/b.private.pem"
openssl pkey -in "$keys/b.private.pem" -pubout -out "$keys/b.public.pem"
openssl genpkey -algorithm ED25519 -out "$keys/c.private.pem"
openssl pkey -in "$keys/c.private.pem" -pubout -out "$keys/c.public.pem"
openssl genpkey -algorithm ED25519 -out "$keys/d.private.pem"
openssl pkey -in "$keys/d.private.pem" -pubout -out "$keys/d.public.pem"
openssl genpkey -algorithm ED25519 -out "$keys/governance.private.pem"
openssl pkey -in "$keys/governance.private.pem" -pubout -out "$keys/governance.public.pem"

fp_a="$(python3 scripts/release-artifact.py fingerprint --public-key "$keys/a.public.pem" | cut -d= -f2)"
fp_b="$(python3 scripts/release-artifact.py fingerprint --public-key "$keys/b.public.pem" | cut -d= -f2)"
fp_c="$(python3 scripts/release-artifact.py fingerprint --public-key "$keys/c.public.pem" | cut -d= -f2)"
fp_d="$(python3 scripts/release-artifact.py fingerprint --public-key "$keys/d.public.pem" | cut -d= -f2)"
cp "$keys/a.public.pem" "$trusted/$fp_a.pem"
cp "$keys/b.public.pem" "$trusted/$fp_b.pem"
cp "$keys/c.public.pem" "$trusted/$fp_c.pem"

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

printf -v zero '%064d' 0
: > "$work/revoked-empty.txt"
python3 scripts/release-revocations.py create \
  --private-key "$keys/governance.private.pem" \
  --output-dir "$bundle" \
  --name revocations-1 \
  --epoch 1 \
  --previous-sha256 "$zero" \
  --revoked "$work/revoked-empty.txt"
python3 scripts/release-revocations.py accept \
  --snapshot "$bundle/revocations-1.revocations.json" \
  --signature "$bundle/revocations-1.revocations.sig" \
  --governance-public-key "$keys/governance.public.pem" \
  --state-dir "$work/revocation-state" \
  "${software_anchor[@]}"

python3 scripts/release-artifact.py create \
  --payload "$bundle/jasper-kernel" \
  --sbom "$bundle/sbom.json" \
  --private-key "$keys/a.private.pem" \
  --private-key "$keys/b.private.pem" \
  --private-key "$keys/c.private.pem" \
  --threshold 2 \
  --output-dir "$bundle" \
  --name release \
  --channel stable \
  --source-commit "$commit" \
  --target x86_64-unknown-none \
  --abi "$abi"

verify() {
  local manifest=$1 payload=$2 sbom=$3
  shift 3
  local signature_args=()
  local signature
  for signature in "$@"; do
    signature_args+=(--signature "$signature")
  done
  python3 scripts/release-artifact.py verify \
    --manifest "$manifest" \
    --payload "$payload" \
    --sbom "$sbom" \
    --trusted-dir "$trusted" \
    --revoked "$work/revoked.txt" \
    "${signature_args[@]}"
}

python3 scripts/release-revocations.py export \
  --state-dir "$work/revocation-state" \
  --governance-public-key "$keys/governance.public.pem" \
  --output "$work/revoked.txt" \
  "${software_anchor[@]}"
release_sigs=(
  "$bundle/release.$fp_a.manifest.sig"
  "$bundle/release.$fp_b.manifest.sig"
  "$bundle/release.$fp_c.manifest.sig"
)
verify \
  "$bundle/release.manifest.json" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json" \
  "${release_sigs[@]}"

# Two of the three declared signers are sufficient.
verify \
  "$bundle/release.manifest.json" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json" \
  "${release_sigs[0]}" \
  "${release_sigs[1]}"

# One signer and a duplicated signer are both rejected.
if verify \
  "$bundle/release.manifest.json" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json" \
  "${release_sigs[0]}" 2>"$work/threshold.err"; then
  echo "release-supply-check: one-of-three threshold was accepted" >&2
  exit 1
fi
grep -q 'threshold not met' "$work/threshold.err"
if verify \
  "$bundle/release.manifest.json" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json" \
  "${release_sigs[0]}" \
  "${release_sigs[0]}" 2>"$work/duplicate.err"; then
  echo "release-supply-check: duplicate signer was accepted" >&2
  exit 1
fi
grep -q 'duplicate signature' "$work/duplicate.err"

cp "$bundle/release.manifest.json" "$work/tampered-manifest.json"
python3 - "$work/tampered-manifest.json" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
data = path.read_bytes()
old = b'"target":"x86_64-unknown-none"'
if data.count(old) != 1:
    raise SystemExit("release-supply-check: target marker is not unique")
path.write_bytes(data.replace(old, b'"target":"x86_64-unknown-nonf"'))
PY
if verify \
  "$work/tampered-manifest.json" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json" \
  "${release_sigs[@]}" 2>"$work/manifest-tampered.err"; then
  echo "release-supply-check: tampered manifest was accepted" >&2
  exit 1
fi
grep -q 'openssl pkeyutl' "$work/manifest-tampered.err"

revocations1="$(sha256sum "$bundle/revocations-1.revocations.json" | cut -d' ' -f1)"
printf '%s\n' "$fp_a" > "$work/revoked-a.txt"
python3 scripts/release-revocations.py create \
  --private-key "$keys/governance.private.pem" \
  --output-dir "$bundle" \
  --name revocations-2 \
  --epoch 2 \
  --previous-sha256 "$revocations1" \
  --revoked "$work/revoked-a.txt"
python3 scripts/release-revocations.py accept \
  --snapshot "$bundle/revocations-2.revocations.json" \
  --signature "$bundle/revocations-2.revocations.sig" \
  --governance-public-key "$keys/governance.public.pem" \
  --state-dir "$work/revocation-state" \
  "${software_anchor[@]}"
python3 scripts/release-revocations.py export \
  --state-dir "$work/revocation-state" \
  --governance-public-key "$keys/governance.public.pem" \
  --output "$work/revoked.txt" \
  "${software_anchor[@]}"
if verify \
  "$bundle/release.manifest.json" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json" \
  "${release_sigs[@]}" 2>"$work/revoked.err"; then
  echo "release-supply-check: revoked key was accepted" >&2
  exit 1
fi
grep -q 'signer is revoked' "$work/revoked.err"

python3 scripts/release-artifact.py create \
  --payload "$bundle/jasper-kernel" \
  --sbom "$bundle/sbom.json" \
  --private-key "$keys/b.private.pem" \
  --private-key "$keys/c.private.pem" \
  --private-key "$keys/d.private.pem" \
  --threshold 2 \
  --output-dir "$bundle" \
  --name rotated \
  --channel lts \
  --source-commit "$commit" \
  --target x86_64-unknown-none \
  --abi "$abi"
# Rotate the trusted root set: A is retired and D enters while the release
# still requires two signatures from a distinct three-key set.
mv "$trusted/$fp_a.pem" "$work/retired-a.pem"
cp "$keys/d.public.pem" "$trusted/$fp_d.pem"
rotated_sigs=(
  "$bundle/rotated.$fp_b.manifest.sig"
  "$bundle/rotated.$fp_c.manifest.sig"
  "$bundle/rotated.$fp_d.manifest.sig"
)
verify \
  "$bundle/rotated.manifest.json" \
  "$bundle/jasper-kernel" \
  "$bundle/sbom.json" \
  "${rotated_sigs[0]}" \
  "${rotated_sigs[1]}"

mkdir -p "$work/tampered"
cp "$bundle/rotated.manifest.json" "$work/tampered/release.manifest.json"
cp "${rotated_sigs[@]}" "$work/tampered/"
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
if verify \
  "$work/tampered/release.manifest.json" \
  "$work/tampered/jasper-kernel" \
  "$work/tampered/sbom.json" \
  "${rotated_sigs[@]}" 2>"$work/tampered.err"; then
  echo "release-supply-check: tampered payload was accepted" >&2
  exit 1
fi
grep -q 'payload identity does not match' "$work/tampered.err"

cp "$bundle/rotated.manifest.json" "$bundle/release.manifest.json"
rm -f "$bundle"/release.*.manifest.sig
python3 scripts/release-source-drill.py --bundle "$bundle" --output "$download"
verify \
  "$download/release.manifest.json" \
  "$download/jasper-kernel" \
  "$download/sbom.json" \
  "${rotated_sigs[@]}"

echo "release-supply-check: PASS threshold=2 signers=3 revocation=true revocation_snapshot_epoch=2 rotation=true https_sources=2 offline_sources=1 tamper_rejected=true"
