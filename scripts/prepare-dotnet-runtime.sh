#!/usr/bin/env bash
# Prepare a minimal self-contained Linux x64 .NET runtime for Jasper ABI tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOTNET_ROOT="${DOTNET_ROOT:-/usr/share/dotnet}"
DOTNET="$DOTNET_ROOT/dotnet"
PROJECT="$ROOT/verification/fixtures/linux/dotnet/DotnetProbe.csproj"

if [[ "${1:-}" == "--verify-only" ]]; then
    TREE="${2:?usage: $0 --verify-only TREE}"
    python3 - "$TREE" <<'PY'
import hashlib
import pathlib
import sys

tree = pathlib.Path(sys.argv[1])
runtime = tree / "data/runtimes/dotnet"
manifest = runtime / "runtime.manifest.tsv"
if not manifest.is_file():
    raise SystemExit("dotnet-runtime: manifest is missing")
for required in ("DotnetProbe", "DotnetProbe.dll", "libcoreclr.so"):
    if not (runtime / required).is_file():
        raise SystemExit(f"dotnet-runtime: missing {required}")
for line in manifest.read_text(encoding="utf-8").splitlines()[1:]:
    rel, size, expected = line.split("\t")
    path = runtime / rel
    if not path.is_file() or path.stat().st_size != int(size):
        raise SystemExit(f"dotnet-runtime: missing or resized {rel}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"dotnet-runtime: digest mismatch {rel}")
print("dotnet-runtime: VERIFY PASS")
PY
    exit 0
fi

OUTPUT="${1:-$ROOT/target/dotnet-runtime-tree}"
[[ -x "$DOTNET" ]] || {
    echo "dotnet-runtime: DOTNET_ROOT must contain an SDK capable of net10.0" >&2
    exit 69
}
[[ ! -e "$OUTPUT" ]] || {
    echo "dotnet-runtime: output already exists: $OUTPUT" >&2
    exit 73
}

mkdir -p "$(dirname "$OUTPUT")"
temporary="$(mktemp -d "$(dirname "$OUTPUT")/.dotnet-runtime.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
target="$temporary/data/runtimes/dotnet"
mkdir -p "$target" "$temporary/usr/lib/x86_64-linux-gnu" "$temporary/lib64"

DOTNET_ROOT="$DOTNET_ROOT" \
DOTNET_CLI_HOME="$temporary/home" \
DOTNET_CLI_TELEMETRY_OPTOUT=1 \
DOTNET_NOLOGO=1 \
"$DOTNET" publish "$PROJECT" \
    --configuration Release \
    --runtime linux-x64 \
    --self-contained true \
    -p:PublishSingleFile=false \
    --output "$target"

for library in \
    libc.so.6 \
    libm.so.6 \
    libgcc_s.so.1 \
    libstdc++.so.6 \
    libz.so.1 \
    librt.so.1 \
    libdl.so.2 \
    libpthread.so.0
do
    install -m 0644 "/usr/lib/x86_64-linux-gnu/$library" \
        "$temporary/usr/lib/x86_64-linux-gnu/$library"
    install -m 0644 "/usr/lib/x86_64-linux-gnu/$library" \
        "$target/$library"
done
install -m 0755 /lib64/ld-linux-x86-64.so.2 \
    "$temporary/lib64/ld-linux-x86-64.so.2"

python3 - "$target" <<'PY'
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
print(f"dotnet-runtime: staged files={len(rows) - 1}")
PY

mv "$temporary" "$OUTPUT"
trap - EXIT
"$0" --verify-only "$OUTPUT"
