#!/usr/bin/env bash
# Prepare a minimal unmodified OpenJDK runtime tree for Jasper Linux ABI tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
OUTPUT="${1:-$ROOT/target/openjdk-jvm-tree}"
SOURCE="$ROOT/verification/fixtures/linux/java/JvmProbe.java"
JLINK="$JAVA_HOME/bin/jlink"
JAVAC="$JAVA_HOME/bin/javac"

if [[ "${1:-}" == "--verify-only" ]]; then
    OUTPUT="${2:?usage: $0 --verify-only TREE}"
    python3 - "$OUTPUT" <<'PY'
import hashlib
import pathlib
import sys

tree = pathlib.Path(sys.argv[1])
manifest = tree / "data/runtimes/openjdk/runtime.manifest.tsv"
if not manifest.is_file():
    raise SystemExit("openjdk-runtime: manifest is missing")
for line in manifest.read_text(encoding="utf-8").splitlines()[1:]:
    rel, size, expected = line.split("\t")
    path = tree / "data/runtimes/openjdk" / rel
    if not path.is_file() or path.stat().st_size != int(size):
        raise SystemExit(f"openjdk-runtime: missing or resized {rel}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"openjdk-runtime: digest mismatch {rel}")
print("openjdk-runtime: VERIFY PASS")
PY
    exit 0
fi

[[ -x "$JLINK" && -x "$JAVAC" ]] || {
    echo "openjdk-runtime: JAVA_HOME must point to an OpenJDK 21 JDK" >&2
    exit 69
}
[[ ! -e "$OUTPUT" ]] || {
    echo "openjdk-runtime: output already exists: $OUTPUT" >&2
    exit 73
}

mkdir -p "$(dirname "$OUTPUT")"
temporary="$(mktemp -d "$(dirname "$OUTPUT")/.openjdk-jvm.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
target="$temporary/data/runtimes/openjdk"
mkdir -p "$(dirname "$target")"

"$JLINK" \
    --add-modules java.base \
    --strip-debug \
    --no-header-files \
    --no-man-pages \
    --compress=zip-6 \
    --output "$target"
"$JAVAC" --release 21 -d "$target/probe" "$SOURCE"

mkdir -p "$temporary/usr/lib/x86_64-linux-gnu" "$temporary/lib64"
for library in \
    libc.so.6 \
    libm.so.6 \
    libgcc_s.so.1 \
    libstdc++.so.6 \
    libz.so.1 \
    libdl.so.2 \
    libpthread.so.0
do
    install -m 0644 "/usr/lib/x86_64-linux-gnu/$library" \
        "$temporary/usr/lib/x86_64-linux-gnu/$library"
    install -m 0644 "/usr/lib/x86_64-linux-gnu/$library" \
        "$target/lib/$library"
done
install -m 0755 /lib64/ld-linux-x86-64.so.2 \
    "$temporary/lib64/ld-linux-x86-64.so.2"

python3 - "$target" <<'PY'
import pathlib
import sys
import hashlib

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
(root / "runtime.manifest.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
print(f"openjdk-runtime: staged files={len(rows) - 1}")
PY

mv "$temporary" "$OUTPUT"
trap - EXIT
"$0" --verify-only "$OUTPUT"
