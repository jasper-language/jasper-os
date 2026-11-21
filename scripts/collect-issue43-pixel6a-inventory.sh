#!/usr/bin/env bash
# Capture names and readable metadata for the Pixel 6a vendor module/HAL inventory.
# The output never contains vendor binaries. Production builds intentionally make
# most files unreadable to the adb shell; those rows remain explicitly unreviewed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ISSUE43_INVENTORY_OUT:-$ROOT/verification/issue43-pixel6a-binary-inventory.tsv}"
EXPECTED_FINGERPRINT="google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys"
ADB_BIN="${ADB:-adb}"
ADB_ARGS=()
if [ -n "${ANDROID_SERIAL:-}" ]; then
  ADB_ARGS=(-s "$ANDROID_SERIAL")
fi

adb_cmd() {
  "$ADB_BIN" "${ADB_ARGS[@]}" "$@"
}

device_state="$(adb_cmd get-state | tr -d '\r')"
[ "$device_state" = device ] || {
  echo "issue43-inventory: no connected adb device" >&2
  exit 69
}

fingerprint="$(adb_cmd shell getprop ro.build.fingerprint | tr -d '\r')"
[ "$fingerprint" = "$EXPECTED_FINGERPRINT" ] || {
  echo "issue43-inventory: build fingerprint mismatch: $fingerprint" >&2
  exit 65
}
kernel_release="$(adb_cmd shell uname -r | tr -d '\r')"
[ "$kernel_release" = "6.1.145-android14-11-gc1de4747ac59-ab14219743" ] || {
  echo "issue43-inventory: kernel release mismatch: $kernel_release" >&2
  exit 65
}

tmp="$(mktemp -d /tmp/jasper-issue43-inventory.XXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT
loaded="$tmp/loaded"
rows="$tmp/rows"
adb_cmd shell cat /proc/modules \
  | awk '{ print $1 }' \
  | sed 's/-/_/g' \
  | LC_ALL=C sort -u >"$loaded"

adb_cmd shell sh -s <<'REMOTE' >"$rows"
emit() {
  kind=$1
  path=$2
  name=${path##*/}
  if [ -r "$path" ]; then
    size=$(stat -c %s "$path")
    sum=$(sha256sum "$path" | awk '{ print $1 }')
    access=readable
  else
    size=-
    sum=-
    access=unreadable-by-adb-shell
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$name" "$path" "$size" "$sum" "$access"
}

ls -1 /vendor_dlkm/lib/modules | grep '\.ko$' |
  while IFS= read -r name; do
    emit linux-module "/vendor_dlkm/lib/modules/$name"
  done
for name in modules.alias modules.blocklist modules.dep modules.load modules.softdep; do
  path=/vendor_dlkm/lib/modules/$name
  emit linux-module-metadata "$path"
done
ls -1 /vendor/lib64/hw | grep '\.so$' |
  while IFS= read -r name; do
    emit android-hal "/vendor/lib64/hw/$name"
  done
REMOTE

mkdir -p "$(dirname "$OUT")"
tmp_out="$tmp/output.tsv"
printf 'kind\tobserved_name\tdevice_path\tsize_bytes\tsha256\taccess\tloaded\tbuild_fingerprint\tkernel_release\n' >"$tmp_out"
while IFS=$'\t' read -r kind name path size sum access; do
  is_loaded=no
  if [ "$kind" = linux-module ]; then
    stem="${name%.ko}"
    stem="${stem//-/_}"
    if LC_ALL=C grep -Fxq -- "$stem" "$loaded"; then
      is_loaded=yes
    fi
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$kind" "$name" "$path" "$size" "$sum" "$access" "$is_loaded" \
    "$fingerprint" "$kernel_release"
done <"$rows" | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 >>"$tmp_out"

mv -- "$tmp_out" "$OUT"
printf 'issue43-inventory: wrote %s\n' "$OUT"
