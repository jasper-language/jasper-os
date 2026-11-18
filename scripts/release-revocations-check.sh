#!/bin/bash
# Exercise signed monotonic revocation snapshots without production keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

work="$(mktemp -d "${TMPDIR:-/tmp}/jasper-revocations.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/snapshots" "$work/state"
software_anchor=(--development-software-anchor)

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
    --state-dir "$work/state" \
    "${software_anchor[@]}"
}

accept epoch1
snapshot1="$(sha256sum "$work/snapshots/epoch1.revocations.json" | cut -d' ' -f1)"
accept epoch1 >"$work/idempotent.txt"
grep -q 'IDEMPOTENT' "$work/idempotent.txt"
[[ "$(wc -l < "$work/state/audit.jsonl")" -eq 1 ]]

python3 scripts/release-revocations.py export \
  --state-dir "$work/state" \
  --governance-public-key "$work/governance.public.pem" \
  --output "$work/exported.txt" \
  "${software_anchor[@]}"
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
  --output "$work/exported.txt" \
  "${software_anchor[@]}"
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
  --state-dir "$work/state" \
  "${software_anchor[@]}" 2>"$work/tamper.err"; then
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
  --state-dir "$work/state" \
  "${software_anchor[@]}" 2>"$work/signature.err"; then
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
  --governance-public-key "$work/governance.public.pem" \
  "${software_anchor[@]}" 2>"$work/state-tamper.err"; then
  echo "release-revocations-check: unsigned state tampering was accepted" >&2
  exit 1
fi
grep -q 'openssl pkeyutl' "$work/state-tamper.err"
cp "$work/state0.backup" "$work/state/state.0.json"
cp "$work/state/state.1.backup" "$work/state/state.1.json"

printf '{}\n' > "$work/state/state.1.json"
if python3 scripts/release-revocations.py status \
  --state-dir "$work/state" \
  --governance-public-key "$work/governance.public.pem" \
  "${software_anchor[@]}" 2>"$work/copies.err"; then
  echo "release-revocations-check: divergent state copies were accepted" >&2
  exit 1
fi
grep -q 'state copies diverge' "$work/copies.err"
cp "$work/state/state.1.backup" "$work/state/state.1.json"

python3 scripts/release-revocations.py status \
  --state-dir "$work/state" \
  --governance-public-key "$work/governance.public.pem" \
  "${software_anchor[@]}" >"$work/status.txt"
grep -q 'epoch=3 .*revoked=2 audit=3' "$work/status.txt"
if python3 scripts/release-revocations.py status \
  --state-dir "$work/state" \
  --governance-public-key "$work/governance.public.pem" \
  2>"$work/no-anchor.err"; then
  echo "release-revocations-check: production state without a TPM anchor was accepted" >&2
  exit 1
fi
grep -q 'TPM2 monotonic anchor is required' "$work/no-anchor.err"

# TPM2 NV counter adapter. The fake executable below is only a deterministic
# protocol harness; production must pass the real tpm2-tools executables.
cat >"$work/fake-tpm.py" <<'PY'
from pathlib import Path
import os
import sys

mode, counter_path = sys.argv[1], Path(sys.argv[2])
try:
    counter = int(counter_path.read_text(encoding="ascii").strip())
except (OSError, ValueError):
    raise SystemExit(31)
if mode == "increment":
    counter += 1
    if counter > (1 << 64) - 1:
        raise SystemExit(32)
    temporary = counter_path.with_name(counter_path.name + ".tmp")
    temporary.write_text(f"{counter}\n", encoding="ascii")
    os.replace(temporary, counter_path)
elif mode == "read":
    sys.stdout.buffer.write(counter.to_bytes(8, "big"))
else:
    raise SystemExit(33)
PY
cat >"$work/tpm-increment" <<EOF
#!/bin/sh
exec python3 "$work/fake-tpm.py" increment "$work/tpm-counter"
EOF
cat >"$work/tpm-read" <<EOF
#!/bin/sh
exec python3 "$work/fake-tpm.py" read "$work/tpm-counter"
EOF
cat >"$work/tpm-increment-fail" <<'EOF'
#!/bin/sh
exit 47
EOF
chmod +x "$work/tpm-increment" "$work/tpm-read" "$work/tpm-increment-fail"
printf '0\n' >"$work/tpm-counter"
tpm_args=(
  --tpm-nv-index 0x01800001
  --tpm-increment-command "$work/tpm-increment"
  --tpm-read-command "$work/tpm-read"
)
accept_tpm() {
  local name=$1
  python3 scripts/release-revocations.py accept \
    --snapshot "$work/snapshots/$name.revocations.json" \
    --signature "$work/snapshots/$name.revocations.sig" \
    --governance-public-key "$work/governance.public.pem" \
    --state-dir "$work/state-tpm" \
    "${tpm_args[@]}"
}

accept_tpm epoch1
[[ "$(cat "$work/tpm-counter")" -eq 1 ]]
accept_tpm epoch1 >"$work/tpm-idempotent.txt"
grep -q 'IDEMPOTENT' "$work/tpm-idempotent.txt"
[[ "$(cat "$work/tpm-counter")" -eq 1 ]]
accept_tpm epoch2
[[ "$(cat "$work/tpm-counter")" -eq 2 ]]
cp "$work/state-tpm/state.0.json" "$work/tpm-state2.0.json"
cp "$work/state-tpm/state.1.json" "$work/tpm-state2.1.json"
cp "$work/state-tpm/monotonic-anchor.json" "$work/tpm-anchor2.json"

if python3 scripts/release-revocations.py accept \
  --snapshot "$work/snapshots/epoch3.revocations.json" \
  --signature "$work/snapshots/epoch3.revocations.sig" \
  --governance-public-key "$work/governance.public.pem" \
  --state-dir "$work/state-tpm" \
  --tpm-nv-index 0x01800001 \
  --tpm-increment-command "$work/tpm-increment-fail" \
  --tpm-read-command "$work/tpm-read" \
  2>"$work/tpm-failed-increment.err"; then
  echo "release-revocations-check: failed TPM increment was accepted" >&2
  exit 1
fi
grep -q 'status 47' "$work/tpm-failed-increment.err"
[[ "$(cat "$work/tpm-counter")" -eq 2 ]]

# The failed increment left a durable intent. Retrying with the working tool
# must reconcile that intent and increment exactly once.
accept_tpm epoch3
[[ "$(cat "$work/tpm-counter")" -eq 3 ]]
accept_tpm epoch3 >"$work/tpm-idempotent3.txt"
grep -q 'IDEMPOTENT' "$work/tpm-idempotent3.txt"
[[ "$(cat "$work/tpm-counter")" -eq 3 ]]
cp "$work/state-tpm/state.0.json" "$work/tpm-state3.0.json"
cp "$work/state-tpm/state.1.json" "$work/tpm-state3.1.json"
cp "$work/state-tpm/monotonic-anchor.json" "$work/tpm-anchor3.json"

python3 scripts/release-revocations.py status \
  --state-dir "$work/state-tpm" \
  --governance-public-key "$work/governance.public.pem" \
  "${tpm_args[@]}" >"$work/tpm-status.txt"
grep -q 'STATUS epoch=3 .*audit=3' "$work/tpm-status.txt"
python3 scripts/release-revocations.py export \
  --state-dir "$work/state-tpm" \
  --governance-public-key "$work/governance.public.pem" \
  --output "$work/tpm-revoked.txt" \
  "${tpm_args[@]}"
grep -qx "$fp_a" "$work/tpm-revoked.txt"
grep -qx "$fp_b" "$work/tpm-revoked.txt"

cp "$work/tpm-state2.0.json" "$work/state-tpm/state.0.json"
cp "$work/tpm-state2.1.json" "$work/state-tpm/state.1.json"
cp "$work/tpm-anchor2.json" "$work/state-tpm/monotonic-anchor.json"
if python3 scripts/release-revocations.py status \
  --state-dir "$work/state-tpm" \
  --governance-public-key "$work/governance.public.pem" \
  "${tpm_args[@]}" 2>"$work/tpm-state-rollback.err"; then
  echo "release-revocations-check: rolled-back local state was accepted" >&2
  exit 1
fi
grep -q 'unregistered increment' "$work/tpm-state-rollback.err"
cp "$work/tpm-state3.0.json" "$work/state-tpm/state.0.json"
cp "$work/tpm-state3.1.json" "$work/state-tpm/state.1.json"
cp "$work/tpm-anchor3.json" "$work/state-tpm/monotonic-anchor.json"

printf '2\n' >"$work/tpm-counter"
if python3 scripts/release-revocations.py status \
  --state-dir "$work/state-tpm" \
  --governance-public-key "$work/governance.public.pem" \
  "${tpm_args[@]}" 2>"$work/tpm-rollback.err"; then
  echo "release-revocations-check: TPM counter rollback was accepted" >&2
  exit 1
fi
grep -q 'counter rolled back' "$work/tpm-rollback.err"

printf '4\n' >"$work/tpm-counter"
if python3 scripts/release-revocations.py export \
  --state-dir "$work/state-tpm" \
  --governance-public-key "$work/governance.public.pem" \
  --output "$work/tpm-unregistered.txt" \
  "${tpm_args[@]}" 2>"$work/tpm-unregistered.err"; then
  echo "release-revocations-check: unregistered TPM increment was accepted" >&2
  exit 1
fi
grep -q 'unregistered increment' "$work/tpm-unregistered.err"

printf '3\n' >"$work/tpm-counter"
if python3 scripts/release-revocations.py status \
  --state-dir "$work/state-tpm" \
  --governance-public-key "$work/governance.public.pem" \
  --tpm-nv-index 0x01800001 \
  --tpm-increment-command "$work/tpm-increment" \
  --tpm-read-command "$work/does-not-exist" 2>"$work/tpm-missing.err"; then
  echo "release-revocations-check: missing TPM reader was accepted" >&2
  exit 1
fi

cat >"$work/tpm-read-hang" <<'EOF'
#!/bin/sh
sleep 5
EOF
chmod +x "$work/tpm-read-hang"
if python3 scripts/release-revocations.py status \
  --state-dir "$work/state-tpm" \
  --governance-public-key "$work/governance.public.pem" \
  --tpm-nv-index 0x01800001 \
  --tpm-increment-command "$work/tpm-increment" \
  --tpm-read-command "$work/tpm-read-hang" \
  --tpm-command-timeout 1 2>"$work/tpm-timeout.err"; then
  echo "release-revocations-check: hanging TPM reader was accepted" >&2
  exit 1
fi
grep -q 'exceeded its 1s command deadline' "$work/tpm-timeout.err"

echo "release-revocations-check: PASS signed=true monotonic=true replay_rejected=true rollback_rejected=true dual_copy=true audit=true tpm_anchor=true unregistered_increment_rejected=true"
