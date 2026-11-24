#!/usr/bin/env bash
# Extract the pinned Darling research payload without claiming guest support.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE="${DARLING_DEBS_ARCHIVE:-${1:-}}"
OUTPUT="${2:-$ROOT/target/darling-research-tree}"
EXPECTED_SHA256=27469ef3932da2e91dd7fb34b70e3628a3e54b7af9fb5480051f44af35eca1fd

[[ -n "$ARCHIVE" ]] || {
    echo "usage: DARLING_DEBS_ARCHIVE=debs_20260608.zip $0 [ARCHIVE] [OUTPUT]" >&2
    exit 64
}
[[ -f "$ARCHIVE" ]] || {
    echo "darling-research: archive not found: $ARCHIVE" >&2
    exit 66
}
actual=$(sha256sum "$ARCHIVE" | awk '{print $1}')
[[ "$actual" == "$EXPECTED_SHA256" ]] || {
    echo "darling-research: archive digest mismatch" >&2
    exit 65
}
[[ ! -e "$OUTPUT" ]] || {
    echo "darling-research: output already exists: $OUTPUT" >&2
    exit 73
}

mkdir -p "$(dirname "$OUTPUT")"
temporary="$(mktemp -d "$(dirname "$OUTPUT")/.darling-research.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
unzip -q "$ARCHIVE" -d "$temporary/archive"

packages=(
    darling-core_0.1.20260609~noble_amd64.deb
    darling-cli_0.1.20260609~noble_amd64.deb
)
mkdir -p "$temporary/root"
for package in "${packages[@]}"; do
    source=$(find "$temporary/archive" -type f -name "$package" -print -quit)
    [[ -n "$source" ]] || {
        echo "darling-research: missing package $package" >&2
        exit 66
    }
    dpkg-deb -x "$source" "$temporary/root"
done

python3 "$ROOT/scripts/check-darling-payload.py" --self-test
python3 "$ROOT/scripts/check-darling-payload.py" --tree "$temporary/root"
mv "$temporary" "$OUTPUT"
trap - EXIT
echo "darling-research: prepared payload=$OUTPUT guest_pass=false"
