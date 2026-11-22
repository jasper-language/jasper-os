#!/usr/bin/env bash
# Verify the component manager against a pinned, unmodified upstream DXVK
# release. Installation is the claim under test; executing DXVK is separate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

DXVK_VERSION=3.1.1
DXVK_SHA256=40565b4a724aadc4433fa4e010b4b23916d9b1f1baeee64e17186db94f54e608
DXVK_URL="https://github.com/doitsujin/dxvk/releases/download/v${DXVK_VERSION}/dxvk-${DXVK_VERSION}.tar.gz"
ARCHIVE="${DXVK_ARCHIVE:-}"
OUT="${COMPAT_PACKAGE_REAL_OUT:-$ROOT/evidence/compat-package-real-dxvk-${DXVK_VERSION}}"
TARGET="${COMPAT_PACKAGE_REAL_TARGET:-$ROOT/target/compat-package-real}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/jasper-dxvk-package.XXXXXX")"
cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$OUT"
if [ -z "$ARCHIVE" ]; then
    ARCHIVE="$WORK/dxvk-${DXVK_VERSION}.tar.gz"
    curl --fail --location --retry 3 \
        --output "$ARCHIVE" "$DXVK_URL" 2>&1 | tee "$OUT/download.log"
fi
actual_sha256=$(sha256sum "$ARCHIVE" | awk '{ print $1 }')
[ "$actual_sha256" = "$DXVK_SHA256" ] || {
    echo "compat-package-real: DXVK digest mismatch: $actual_sha256" >&2
    exit 1
}

if [ "${COMPAT_PACKAGE_REAL_DIRECT_CARGO:-0}" = 1 ]; then
    CARGO_BUILD_JOBS=2 cargo build --locked --release --target-dir "$TARGET" \
        -p jasper-compat-packages --bin jasper-compat-pkg \
        2>&1 | tee "$OUT/build.log"
else
    env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" \
        build --locked --release --target-dir "$TARGET" \
        -p jasper-compat-packages --bin jasper-compat-pkg \
        2>&1 | tee "$OUT/build.log"
fi
CLI="$TARGET/release/jasper-compat-pkg"

install_root="$WORK/root"
manifest_version() {
    local package_version="$1"
    local path="$WORK/dxvk-${package_version}.component.manifest"
    printf '%s\n' \
        "name=dxvk" \
        "version=${package_version}" \
        "arch=x86_64" \
        "runtime=linux" \
        "sha256=${DXVK_SHA256}" \
        "license=Zlib" \
        "entrypoint=dxvk-${DXVK_VERSION}/x64/d3d11.dll" \
        >"$path"
    printf '%s\n' "$path"
}

manifest1=$(manifest_version "${DXVK_VERSION}-r1")
manifest2=$(manifest_version "${DXVK_VERSION}-r2")

"$CLI" install "$install_root" "$manifest1" "$ARCHIVE" |
    tee "$OUT/install-r1.txt"
[ -x "$install_root/components/dxvk/${DXVK_VERSION}-r1/dxvk-${DXVK_VERSION}/x64/d3d11.dll" ]
"$CLI" current "$install_root" dxvk | tee "$OUT/current-r1.txt" |
    grep -q "dxvk ${DXVK_VERSION}-r1 "

"$CLI" stop "$install_root" dxvk | tee "$OUT/stop-r1.txt" |
    grep -q "enabled=false"
"$CLI" current "$install_root" dxvk | tee "$OUT/current-stopped.txt" |
    grep -q "enabled=false"
"$CLI" start "$install_root" dxvk | tee "$OUT/start-r1.txt" |
    grep -q "enabled=true"

"$CLI" install "$install_root" "$manifest2" "$ARCHIVE" |
    tee "$OUT/install-r2.txt"
"$CLI" current "$install_root" dxvk | tee "$OUT/current-r2.txt" |
    grep -q "dxvk ${DXVK_VERSION}-r2 "

"$CLI" rollback "$install_root" dxvk | tee "$OUT/rollback-r1.txt"
"$CLI" current "$install_root" dxvk | tee "$OUT/current-rollback.txt" |
    grep -q "dxvk ${DXVK_VERSION}-r1 "

"$CLI" uninstall "$install_root" dxvk | tee "$OUT/uninstall.txt"
if "$CLI" current "$install_root" dxvk >"$OUT/current-after-uninstall.txt" 2>&1; then
    echo "compat-package-real: component still active after uninstall" >&2
    exit 1
fi
if find "$install_root" -maxdepth 1 \
    \( -name '.staging-*' -o -name '.uninstall-*' \) | grep -q .; then
    echo "compat-package-real: transient install state leaked" >&2
    exit 1
fi

offline_archive="$WORK/dxvk-offline.tar.gz"
cp "$ARCHIVE" "$offline_archive"
offline_sha256=$(sha256sum "$offline_archive" | awk '{ print $1 }')
[ "$offline_sha256" = "$DXVK_SHA256" ]
offline_root="$WORK/offline-root"
"$CLI" install "$offline_root" "$manifest1" "$offline_archive" |
    tee "$OUT/offline-install.txt"
"$CLI" current "$offline_root" dxvk | tee "$OUT/offline-current.txt" |
    grep -q "dxvk ${DXVK_VERSION}-r1 "
"$CLI" uninstall "$offline_root" dxvk | tee "$OUT/offline-uninstall.txt"

printf 'dxvk_version=%s\ndxvk_sha256=%s\nonline_install=pass\nstop_start=pass\nupgrade=pass\nrollback=pass\nuninstall=pass\noffline_install=pass\nsource_parity=true\n' \
    "$DXVK_VERSION" "$DXVK_SHA256" >"$OUT/summary.txt"
echo "compat-package-real: PASS evidence=$OUT"
