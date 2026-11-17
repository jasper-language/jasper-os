#!/bin/bash
# Exercise signed monotonic revocation snapshots without production keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

work="$(mktemp -d "${TMPDIR:-/tmp}/jasper-revocations.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/snapshots" "$work/state"

openssl genpkey -algorithm ED25519 -out "$work/governance.private.pem"
openssl pkey -in "$work/governance.private.pem" -pubout -out "$work/governance.public.pem"

release_a="$work/a.public.pem"
release_b="$work/b.public.pem"
openssl genpkey -algorithm ED25519 -out "$work/a.private.pem"
openssl pkey -in "$work/a.private.pem" -pubout -out "$release_a"
openssl genpkey -algorithm ED25519 -out "$work/b.private.pem"
openssl pkey -in "$work/b.private.pem" -pubout -out "$release_b"
fp_a="$(python3 scripts/release-artifact.py fingerprint --public-key "$release_a" | cut -d= -f2)"
fp_b="$(python3 scripts/release-artifact.py fingerprint --public-key "$release_b" | cut -d= -f2)"

printf -v zero '%064d' 0
: > "$work/empty.txt"
python3 scripts/release-revocations.py create \
  --private-key "$work/governance.private.pem" \
  --output-dir "$work/snapshots" \
  --name epoch1 \
  --epoch 1 \
  --previous-sha256 "$zero" \
  --revoked "$work/empty.txt"

accept() {
  local name=$1
  python3 scripts/release-revocations.py accept \
    --snapshot "$work/snapshots/$name.revocations.json" \
    --signature "$work/snapshots/$name.revocations.sig" \
    --governance-public-key "$work/governance.public.pem" \
    --state-dir "$work/state"
}

accept epoch1
snapshot1="$(sha256sum "$work/snapshots/epoch1.revocations.json" | cut -d' ' -f1)"
accept epoch1 >"$work/idempotent.txt"
grep -q 'IDEMPOTENT' "$work/idempotent.txt"
[[ "$(wc -l < "$work/state/audit.jsonl")" -eq 1 ]]

python3 scripts/release-revocations.py export \
  --state-dir "$work/state" \
  --governance-public-key "$work/governance.public.pem" \
  --output "$work/exported.txt"
[[ ! -s "$work/exported.txt" ]]

printf '%s\n' "$fp_a" > "$work/revoked-a.txt"
python3 scripts/release-revocations.py create \
  --private-key "$work/governance.private.pem" \
  --output-dir "$work/snapshots" \
  --name epoch2 \
  --epoch 2 \
  --previous-sha256 "$snapshot1" \
  --revoked "$work/revoked-a.txt"
python3 scripts/release-revocations.py create \
  --private-key "$work/governance.private.pem" \
  --output-dir "$work/snapshots" \
  --name gap3 \
  --epoch 3 \
  --previous-sha256 "$snapshot1" \
  --revoked "$work/revoked-a.txt"
python3 scripts/release-revocations.py create \
  --private-key "$work/governance.private.pem" \
  --output-dir "$work/snapshots" \
  --name badprev2 \
  --epoch 2 \
  --previous-sha256 "$zero" \
  --revoked "$work/revoked-a.txt"

if accept gap3 2>"$work/gap.err"; then
  echo "release-revocations-check: epoch gap was accepted" >&2
  exit 1
fi
grep -q 'exact successor' "$work/gap.err"
if accept badprev2 2>"$work/prev.err"; then
  echo "release-revocations-check: previous digest mismatch was accepted" >&2
  exit 1
fi
grep -q 'previous digest mismatch' "$work/prev.err"
accept epoch2
snapshot2="$(sha256sum "$work/snapshots/epoch2.revocations.json" | cut -d' ' -f1)"
if accept epoch1 2>"$work/stale.err"; then
  echo "release-revocations-check: stale snapshot replay was accepted" >&2
  exit 1
fi
grep -q 'stale revocation snapshot' "$work/stale.err"
python3 scripts/release-revocations.py export \
  --state-dir "$work/state" \
  --governance-public-key "$work/governance.public.pem" \
  --output "$work/exported.txt"
grep -qx "$fp_a" "$work/exported.txt"

python3 scripts/release-revocations.py create \
  --private-key "$work/governance.private.pem" \
  --output-dir "$work/snapshots" \
  --name remove3 \
  --epoch 3 \
  --previous-sha256 "$snapshot2" \
  --revoked "$work/empty.txt"
if accept remove3 2>"$work/remove.err"; then
  echo "release-revocations-check: revoked fingerprint removal was accepted" >&2
  exit 1
fi
grep -q 'attempts to remove' "$work/remove.err"
if [[ "$(sha256sum "$work/state/state.0.json" | cut -d' ' -f1)" == \
      "$(sha256sum "$work/state/state.1.json" | cut -d' ' -f1)" ]]; then
  :
else
  echo "release-revocations-check: state copies diverged" >&2
  exit 1
fi

printf '%s\n%s\n' "$fp_a" "$fp_b" > "$work/revoked-ab.txt"
python3 scripts/release-revocations.py create \
  --private-key "$work/governance.private.pem" \
  --output-dir "$work/snapshots" \
  --name epoch3 \
  --epoch 3 \
  --previous-sha256 "$snapshot2" \
  --revoked "$work/revoked-ab.txt"
snapshot3="$(sha256sum "$work/snapshots/epoch3.revocations.json" | cut -d' ' -f1)"
python3 - "$work/state/audit.jsonl" "$snapshot2" "$snapshot3" <<'PY'
import json
import sys

path, previous_sha256, snapshot_sha256 = sys.argv[1:]
record = {
    "epoch": 3,
    "previous_sha256": previous_sha256,
    "snapshot_sha256": snapshot_sha256,
}
with open(path, "a", encoding="ascii") as stream:
    stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY
accept epoch3 >"$work/recovered.txt"
grep -q 'RECOVERED epoch=3' "$work/recovered.txt"

cp "$work/snapshots/epoch2.revocations.json" "$work/tampered.json"
printf ' ' >> "$work/tampered.json"
if python3 scripts/release-revocations.py accept \
  --snapshot "$work/tampered.json" \
  --signature "$work/snapshots/epoch2.revocations.sig" \
  --governance-public-key "$work/governance.public.pem" \
  --state-dir "$work/state" 2>"$work/tamper.err"; then
  echo "release-revocations-check: tampered snapshot was accepted" >&2
  exit 1
fi
grep -q 'not canonical JSON' "$work/tamper.err"

cp "$work/snapshots/epoch3.revocations.sig" "$work/tampered.sig"
python3 - "$work/tampered.sig" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
data[-1] ^= 1
path.write_bytes(data)
PY
if python3 scripts/release-revocations.py accept \
  --snapshot "$work/snapshots/epoch3.revocations.json" \
  --signature "$work/tampered.sig" \
  --governance-public-key "$work/governance.public.pem" \
  --state-dir "$work/state" 2>"$work/signature.err"; then
  echo "release-revocations-check: tampered signature was accepted" >&2
  exit 1
fi
grep -q 'openssl pkeyutl' "$work/signature.err"

cp "$work/state/state.0.json" "$work/state0.backup"
cp "$work/state/state.0.json" "$work/state/state.1.backup"
python3 - "$work/state/state.0.json" "$work/state/state.1.json" <<'PY'
import hashlib
import json
import sys

for name in sys.argv[1:]:
    with open(name, encoding="ascii") as stream:
        state = json.load(stream)
    state["revoked"] = []
    state["snapshot"]["revoked"] = []
    raw = (json.dumps(state["snapshot"], sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    state["snapshot_sha256"] = hashlib.sha256(raw).hexdigest()
    with open(name, "w", encoding="ascii") as stream:
        stream.write(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
PY
if python3 scripts/release-revocations.py status \
  --state-dir "$work/state" \
  --governance-public-key "$work/governance.public.pem" 2>"$work/state-tamper.err"; then
  echo "release-revocations-check: unsigned state tampering was accepted" >&2
  exit 1
fi
grep -q 'openssl pkeyutl' "$work/state-tamper.err"
cp "$work/state0.backup" "$work/state/state.0.json"
cp "$work/state/state.1.backup" "$work/state/state.1.json"

printf '{}\n' > "$work/state/state.1.json"
if python3 scripts/release-revocations.py status \
  --state-dir "$work/state" \
  --governance-public-key "$work/governance.public.pem" 2>"$work/copies.err"; then
  echo "release-revocations-check: divergent state copies were accepted" >&2
  exit 1
fi
grep -q 'state copies diverge' "$work/copies.err"
cp "$work/state/state.1.backup" "$work/state/state.1.json"

python3 scripts/release-revocations.py status \
  --state-dir "$work/state" \
  --governance-public-key "$work/governance.public.pem" >"$work/status.txt"
grep -q 'epoch=3 .*revoked=2 audit=3' "$work/status.txt"

echo "release-revocations-check: PASS signed=true monotonic=true replay_rejected=true rollback_rejected=true dual_copy=true audit=true"
