#!/bin/bash
set -euo pipefail

src=${1:?usage: prepare-artifacts.sh <linux-build-tree> [output-directory]}
out=${2:-$(cd "$(dirname "$0")" && pwd)/../../images/linux-guest}

make -C "$src" -j"${JOBS:-8}" \
  CC="${HOST_CC:-gcc -std=gnu11}" \
  KCFLAGS="${KCFLAGS:--Wno-unterminated-string-initialization}" \
  bzImage

mkdir -p "$out"
dd if="$src/arch/x86/boot/bzImage" of="$out/setup-header.bin" \
  bs=4096 count=1 status=none
dd if="$src/arch/x86/boot/vmlinux.bin" of="$out/vmlinux.bin" status=none

printf 'header=%s\nkernel=%s\n' \
  "$(sha256sum "$out/setup-header.bin" | cut -d' ' -f1)" \
  "$(sha256sum "$out/vmlinux.bin" | cut -d' ' -f1)"
