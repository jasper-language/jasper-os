#!/usr/bin/env bash
# Prepare the minimal launcher-only tree for the Darling namespace gate probe.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${DARLING_RESEARCH_TREE:-/tmp/darling-research-tree-ea9e}"
OUTPUT="${1:-$ROOT/target/darling-probe-tree}"

[[ -f "$SOURCE/usr/bin/darling" ]] || {
    echo "darling-probe: missing research tree: $SOURCE" >&2
    exit 66
}
[[ ! -e "$OUTPUT" ]] || {
    echo "darling-probe: output already exists: $OUTPUT" >&2
    exit 73
}

mkdir -p "$(dirname "$OUTPUT")"
temporary="$(mktemp -d "$(dirname "$OUTPUT")/.darling-probe.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
runtime="$temporary/data/runtimes/darling"
mkdir -p "$runtime/usr/bin" "$temporary/usr/lib/x86_64-linux-gnu" "$temporary/lib64"

install -m 0755 "$SOURCE/usr/bin/darling" "$runtime/usr/bin/darling"
for library in libc.so.6 libm.so.6 libgcc_s.so.1; do
    install -m 0644 "/usr/lib/x86_64-linux-gnu/$library" \
        "$temporary/usr/lib/x86_64-linux-gnu/$library"
done
install -m 0755 /lib64/ld-linux-x86-64.so.2 \
    "$temporary/lib64/ld-linux-x86-64.so.2"

python3 - "$runtime" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
rows = ["path\tsize\tsha256"]
for path in sorted(item for item in root.rglob("*") if item.is_file()):
    rel = path.relative_to(root).as_posix()
    if rel == "runtime.manifest.tsv":
        continue
    rows.append(
        f"{rel}\t{path.stat().st_size}\t"
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}"
    )
(root / "runtime.manifest.tsv").write_text(
    "\n".join(rows) + "\n", encoding="utf-8"
)
print(f"darling-probe: staged files={len(rows) - 1}")
PY

mv "$temporary" "$OUTPUT"
trap - EXIT
echo "darling-probe: prepared tree=$OUTPUT guest_pass=false gate=uts-ipc-namespace"
