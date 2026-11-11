#!/usr/bin/env bash
# Install a bounded x86-64 Linux userland tree into one P0 System A/B ext4 partition.
# 向 P0 System A/B 的一个 ext4 槽写入有界 x86-64 Linux 用户态文件树，供真实健康门校验。
set -euo pipefail

IMAGE="${1:?p0 image}"
WORK="${2:?work directory}"
START_LBA="${3:?system partition LBA}"
SLOT="${4:?A or B}"
RELEASE="${5:?release}"
ROOT_EXEC_PROBE="${6:-}"
FULL_USERLAND="${7:-0}"
ROOT_SIGNAL_FIXTURE="${8:-}"
[[ "$SLOT" == A || "$SLOT" == B ]]
[[ "$RELEASE" =~ ^[1-9][0-9]*$ ]]
mkdir -p "$WORK"

PARTITION="$WORK/system-$SLOT.img"
MARKER="$WORK/system-$SLOT.jasper-root"
RELEASE_FILE="$WORK/system-$SLOT.jasper-release"
USERLAND_FILE="$WORK/system-$SLOT.jasper-userland"
BINARY=/usr/bin/true
INTERPRETER=/lib64/ld-linux-x86-64.so.2
LIBC=/usr/lib/x86_64-linux-gnu/libc.so.6
GETCONF=/usr/bin/getconf
PRINTF=/usr/bin/printf
LIBSYSTEMD=/usr/lib/x86_64-linux-gnu/libsystemd.so.0
LIBSELINUX=/usr/lib/x86_64-linux-gnu/libselinux.so.1
LIBGCC_S=/usr/lib/x86_64-linux-gnu/libgcc_s.so.1
LIBM=/usr/lib/x86_64-linux-gnu/libm.so.6
LIBPCRE2=/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0

[[ -x "$BINARY" && -f "$INTERPRETER" && -f "$LIBC" ]]
readelf -l "$BINARY" | grep -Fq "interpreter: $INTERPRETER"
ldd "$BINARY" | grep -Fq "libc.so.6 => $LIBC"
dd if="$IMAGE" of="$PARTITION" bs=512 skip="$START_LBA" count=16777216 \
  conv=sparse status=none
printf 'slot=%s\nrelease=%s\nschema=1\n' "$SLOT" "$RELEASE" >"$MARKER"
printf 'name=Jasper-OS\nvariant=p0-x86_64-uefi-ab-v1\nrelease=%s\nschema=1\n' \
  "$RELEASE" >"$RELEASE_FILE"
printf 'arch=x86_64\nabi=linux\nentry=/bin/true\ninterpreter=%s\nlibrary=%s\n' \
  "$INTERPRETER" "$LIBC" >"$USERLAND_FILE"

ensure_dir() {
  local path="$1"
  if ! debugfs -R "stat $path" "$PARTITION" 2>/dev/null | grep -q '^Inode:'; then
    debugfs -w -R "mkdir $path" "$PARTITION" >/dev/null
  fi
  debugfs -R "stat $path" "$PARTITION" 2>/dev/null | grep -q '^Inode:'
}

write_file() {
  local source="$1"
  local destination="$2"
  debugfs -w -R "rm $destination" "$PARTITION" >/dev/null 2>&1 || true
  debugfs -w -R "write $source $destination" "$PARTITION" >/dev/null
  debugfs -R "stat $destination" "$PARTITION" 2>/dev/null | grep -q '^Inode:'
}

for directory in /etc /bin /lib64 /usr /usr/bin /usr/lib /usr/lib/x86_64-linux-gnu /usr/libexec /usr/libexec/jasper; do
  ensure_dir "$directory"
done
write_file "$MARKER" /etc/jasper-root
write_file "$RELEASE_FILE" /etc/jasper-release
write_file "$USERLAND_FILE" /etc/jasper-userland
write_file "$BINARY" /bin/true
write_file "$INTERPRETER" "$INTERPRETER"
write_file "$LIBC" "$LIBC"
debugfs -w -R 'sif /etc/jasper-root mode 0100644' "$PARTITION" >/dev/null
debugfs -w -R 'sif /etc/jasper-release mode 0100644' "$PARTITION" >/dev/null
debugfs -w -R 'sif /etc/jasper-userland mode 0100644' "$PARTITION" >/dev/null
debugfs -w -R 'sif /bin/true mode 0100755' "$PARTITION" >/dev/null
debugfs -w -R "sif $INTERPRETER mode 0100755" "$PARTITION" >/dev/null
debugfs -w -R "sif $LIBC mode 0100755" "$PARTITION" >/dev/null
if [ -n "$ROOT_EXEC_PROBE" ]; then
  [[ -x "$ROOT_EXEC_PROBE" ]]
  write_file "$ROOT_EXEC_PROBE" /usr/libexec/jasper/health-probe
  debugfs -w -R 'sif /usr/libexec/jasper/health-probe mode 0100755' "$PARTITION" >/dev/null
fi
if [ "$FULL_USERLAND" = 1 ]; then
  for source in "$GETCONF" "$PRINTF" "$LIBSYSTEMD" "$LIBSELINUX" "$LIBGCC_S" "$LIBM" "$LIBPCRE2"; do
    [[ -f "$source" ]]
    write_file "$source" "$source"
    debugfs -w -R "sif $source mode 0100755" "$PARTITION" >/dev/null
  done
fi
if [ -n "$ROOT_SIGNAL_FIXTURE" ]; then
  [[ -x "$ROOT_SIGNAL_FIXTURE" ]]
  write_file "$ROOT_SIGNAL_FIXTURE" /usr/bin/jasper-signal-basic
  debugfs -w -R 'sif /usr/bin/jasper-signal-basic mode 0100755' "$PARTITION" >/dev/null
fi
e2fsck -fy "$PARTITION"
e2fsck -fn "$PARTITION"

verify_payload() {
  local image_path="$1"
  local source_path="$2"
  local extracted="$WORK/system-$SLOT-$(basename "$source_path")"
  debugfs -R "dump $image_path $extracted" "$PARTITION" >/dev/null
  cmp "$source_path" "$extracted"
}

verify_payload /bin/true "$BINARY"
verify_payload "$INTERPRETER" "$INTERPRETER"
verify_payload "$LIBC" "$LIBC"
if [ -n "$ROOT_EXEC_PROBE" ]; then
  verify_payload /usr/libexec/jasper/health-probe "$ROOT_EXEC_PROBE"
fi
if [ "$FULL_USERLAND" = 1 ]; then
  for source in "$GETCONF" "$PRINTF" "$LIBSYSTEMD" "$LIBSELINUX" "$LIBGCC_S" "$LIBM" "$LIBPCRE2"; do
    verify_payload "$source" "$source"
  done
fi
if [ -n "$ROOT_SIGNAL_FIXTURE" ]; then
  verify_payload /usr/bin/jasper-signal-basic "$ROOT_SIGNAL_FIXTURE"
fi

dd if="$PARTITION" of="$IMAGE" bs=512 seek="$START_LBA" \
  conv=notrunc,sparse status=none
sync
echo "system-root-fixture: PASS slot=$SLOT release=$RELEASE start_lba=$START_LBA files=6 userland=x86_64-linux-elf root_exec_probe=$([ -n "$ROOT_EXEC_PROBE" ] && echo present || echo absent) full_userland=$FULL_USERLAND signal_fixture=$([ -n "$ROOT_SIGNAL_FIXTURE" ] && echo present || echo absent)"
