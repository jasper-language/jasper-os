#!/usr/bin/env bash
# Build a no-install Ubuntu Wine 10.0 root tree and close its Linux library
# dependencies from the matching Ubuntu host. The tree is staged into the
# Jasper System ext4 fixture by issue21-uefi-boot-check.sh.
set -euo pipefail

VERSION="10.0~repack-12ubuntu1"
OUT="${JASPER_WINE_TREE:-/home/auth/.cache/jasper-compat-wine-10.0/root}"
DEBS="${JASPER_WINE_DEBS:-/home/auth/.cache/jasper-compat-wine-10.0/debs}"
ROOT="${OUT%/}"

declare -A SHA256=(
  ["libwine_${VERSION}_amd64.deb"]="5fa58f821aac76ecb538051c98e67adbdf05e570d8a0985e79803592b8c720de"
  ["wine-common_${VERSION}_all.deb"]="7033c15ca540427e9ea3936c1e6e34e4fcda904e7b5066ba66983ab7d36120c2"
  ["wine64_${VERSION}_amd64.deb"]="c3e8b68877ff154964687f41c91c1c69ad511408058b8b430a7c0e250c84c773"
  ["wine_${VERSION}_all.deb"]="1ac5c23ce6614c551dd4d5d32555a307676b3531f3072ef2273cffbdfaff11e1"
  ["wine64-preloader_${VERSION}_amd64.deb"]="fbf1a00743887544c37f4515ce4cb6391ef554cd76e77bb222d37c3576135f9e"
  ["libz-mingw-w64_1.3.1+dfsg-2_all.deb"]="7a22b145bbe7b89aeff075f96989d781bdc498884f1d603acdf001d7b69117b7"
)
declare -A DEB=(
  [wine]="wine_${VERSION}_all.deb"
  [wine64]="wine64_${VERSION}_amd64.deb"
  [libwine]="libwine_${VERSION}_amd64.deb"
  [wine-common]="wine-common_${VERSION}_all.deb"
  [wine64-preloader]="wine64-preloader_${VERSION}_amd64.deb"
  [libz-mingw-w64]="libz-mingw-w64_1.3.1+dfsg-2_all.deb"
)

mkdir -p "$DEBS" "$ROOT"
for package in wine wine64 libwine wine-common wine64-preloader libz-mingw-w64; do
  name="${DEB[$package]}"
  deb="$DEBS/$name"
  if [ ! -f "$deb" ]; then
    (
      cd "$DEBS"
      apt-get download "${package}=${VERSION}"
    )
  fi
  test -f "$deb"
  printf '%s  %s\n' "${SHA256[$name]}" "$deb" | sha256sum -c -
done

if [ ! -f "$ROOT/.complete" ]; then
  for deb in "$DEBS"/libwine_"$VERSION"*.deb \
    "$DEBS"/wine-common_"$VERSION"*.deb \
    "$DEBS"/wine64_"$VERSION"*.deb \
    "$DEBS"/wine_"$VERSION"*.deb \
    "$DEBS"/wine64-preloader_"$VERSION"*.deb \
    "$DEBS"/libz-mingw-w64_1.3.1+dfsg-2_all.deb; do
    dpkg-deb -x "$deb" "$ROOT"
  done
fi

wine="$ROOT/usr/lib/x86_64-linux-gnu/wine/wine"
wineserver="$ROOT/usr/lib/x86_64-linux-gnu/wine/wineserver"
test -x "$wine"
test -x "$wineserver"
test -f "$ROOT/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/cmd.exe"
test -f "$ROOT/usr/share/wine/wine.inf"
test -f "$ROOT/usr/share/wine/nls/l_intl.nls"
test -f "$ROOT/usr/x86_64-w64-mingw32/lib/zlib1.dll"
test -f "$ROOT/usr/i686-w64-mingw32/lib/zlib1.dll"

# libwine's trigger marks zlib as a Wine builtin by replacing the DOS stub
# with the builtin header. A plain copy is rejected by the Windows loader.
install_builtin_zlib() {
  local source="$1"
  local destination="$2"
  head -c 64 "$source" > "$destination"
  printf '%s' 'Wine builtin DLL' >> "$destination"
  printf '\0\0\0\0\0\0\0\0' >> "$destination"
  printf '\0\0\0\0\0\0\0\0' >> "$destination"
  tail -c +97 "$source" >> "$destination"
  chmod 0755 "$destination"
}
install_builtin_zlib \
  "$ROOT/usr/x86_64-w64-mingw32/lib/zlib1.dll" \
  "$ROOT/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/zlib1.dll"
install_builtin_zlib \
  "$ROOT/usr/i686-w64-mingw32/lib/zlib1.dll" \
  "$ROOT/usr/lib/x86_64-linux-gnu/wine/i386-windows/zlib1.dll"

copy_dependency() {
  local source="$1"
  local relative="${source#/}"
  local destination="$ROOT/$relative"
  if [ ! -e "$destination" ]; then
    mkdir -p "$(dirname "$destination")"
    cp -L --preserve=mode,timestamps "$source" "$destination"
  fi
}

# ldd resolves the transitive ELF closure for the Unix-side Wine loader and all
# host modules. Copy those exact matching Ubuntu files into their absolute root
# paths. Optional modules may be dlopen()ed later and are diagnosed by the real
# guest run instead of being silently synthesized.
mapfile -t ELF_INPUTS < <(
  find "$ROOT/usr/lib/x86_64-linux-gnu/wine" -type f \
    \( -name 'wine' -o -name 'wineserver' -o -name '*.so' \) -print
)
for input in "${ELF_INPUTS[@]}"; do
  while IFS= read -r dependency; do
    case "$dependency" in
      /lib/*|/lib64/*|/usr/lib/*) copy_dependency "$dependency" ;;
    esac
  done < <(ldd "$input" 2>/dev/null | awk '/=> \// { print $3 } /^\// { print $1 }')
done
copy_dependency /lib64/ld-linux-x86-64.so.2

mkdir -p "$ROOT/etc" "$ROOT/data/wineprefix" "$ROOT/tmp"
printf 'root:x:0:0:root:/data:/bin/dash\nuser:x:1000:1000:user:/data:/bin/dash\n' \
  > "$ROOT/etc/passwd"
printf 'root:x:0:\nuser:x:1000:\n' > "$ROOT/etc/group"
printf 'compat-wine version=%s source=ubuntu-resolute\n' "$VERSION" \
  > "$ROOT/etc/jasper-compat-wine"
chmod 1777 "$ROOT/tmp"

sha256sum \
  "$ROOT/usr/lib/x86_64-linux-gnu/wine/wine" \
  "$ROOT/usr/lib/x86_64-linux-gnu/wine/wineserver" \
  "$ROOT/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/cmd.exe" \
  > "$ROOT/SHA256SUMS"
touch "$ROOT/.complete"

du -sh "$ROOT"
printf 'wine-tree: PASS version=%s root=%s\n' "$VERSION" "$ROOT"
