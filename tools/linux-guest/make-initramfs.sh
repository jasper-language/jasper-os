#!/bin/bash
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/initramfs.cpio.gz}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/root/dev" "$work/root/proc" "$work/root/sys"
gcc -static -nostdlib -fno-builtin -fno-stack-protector -fno-pie -no-pie -Os -s \
    "$here/init.c" -o "$work/root/init"
(
    cd "$work/root"
    find . -print0 | sort -z |
        cpio --null -o --format=newc --owner=0:0 2>/dev/null |
        gzip -9n
) > "$out"
echo "$out"
