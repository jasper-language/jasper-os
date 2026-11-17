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
ROOT_PPID_FIXTURE="${9:-}"
ROOT_ANDROID_TOYBOX="${10:-}"
ROOT_AOSP_BINDER_TEST="${11:-}"
ROOT_ANDROID_TREE="${12:-}"
ROOT_ANDROID_LINKER_CONFIG="${13:-}"
[[ "$SLOT" == A || "$SLOT" == B ]]
[[ "$RELEASE" =~ ^[1-9][0-9]*$ ]]
mkdir -p "$WORK"

PARTITION="$WORK/system-$SLOT.img"
MARKER="$WORK/system-$SLOT.jasper-root"
RELEASE_FILE="$WORK/system-$SLOT.jasper-release"
USERLAND_FILE="$WORK/system-$SLOT.jasper-userland"
BINARY=/usr/bin/true
DASH=/bin/dash
INTERPRETER=/lib64/ld-linux-x86-64.so.2
LIBC=/usr/lib/x86_64-linux-gnu/libc.so.6
GETCONF=/usr/bin/getconf
PRINTF=/usr/bin/printf
UNAME=/usr/bin/uname
PWD_UTILITY=/usr/bin/pwd
NPROC=/usr/bin/nproc
SLEEP=/usr/bin/sleep
FIND=/usr/bin/find
LS=/usr/bin/ls
WC=/usr/bin/wc
HOSTNAME=/usr/bin/hostname
BASENAME=/usr/bin/basename
DIRNAME=/usr/bin/dirname
ID=/usr/bin/id
LIBSYSTEMD=/usr/lib/x86_64-linux-gnu/libsystemd.so.0
LIBSELINUX=/usr/lib/x86_64-linux-gnu/libselinux.so.1
LIBGCC_S=/usr/lib/x86_64-linux-gnu/libgcc_s.so.1
LIBM=/usr/lib/x86_64-linux-gnu/libm.so.6
LIBPCRE2=/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0

fail() {
  echo "system-root-fixture: FAIL $*" >&2
  exit 1
}

for tool in readelf ldd dd debugfs e2fsck; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done
[[ -x "$BINARY" ]] || fail "missing executable: $BINARY"
[[ -f "$INTERPRETER" ]] || fail "missing interpreter: $INTERPRETER"
[[ -f "$LIBC" ]] || fail "missing libc: $LIBC"
readelf -l "$BINARY" | grep -Fq "interpreter: $INTERPRETER" ||
  fail "unexpected interpreter in $BINARY"
libc_loaded="$(ldd "$BINARY" | awk '$1 == "libc.so.6" && $2 == "=>" { print $3; exit }')"
[[ -n "$libc_loaded" ]] || fail "libc is not listed by ldd for $BINARY"
[[ "$(readlink -f "$libc_loaded")" = "$(readlink -f "$LIBC")" ]] ||
  fail "ldd libc $libc_loaded differs from fixture libc $LIBC"
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

for directory in /etc /bin /lib64 /usr /usr/bin /usr/lib /usr/lib/x86_64-linux-gnu /usr/libexec /usr/libexec/jasper /data /data/.cache /data/.cache/metal2vulkan; do
  ensure_dir "$directory"
done
write_file "$MARKER" /etc/jasper-root
write_file "$RELEASE_FILE" /etc/jasper-release
write_file "$USERLAND_FILE" /etc/jasper-userland
write_file "$BINARY" /bin/true
write_file "$DASH" /bin/dash
write_file "$INTERPRETER" "$INTERPRETER"
write_file "$LIBC" "$LIBC"
debugfs -w -R 'sif /etc/jasper-root mode 0100644' "$PARTITION" >/dev/null
debugfs -w -R 'sif /etc/jasper-release mode 0100644' "$PARTITION" >/dev/null
debugfs -w -R 'sif /etc/jasper-userland mode 0100644' "$PARTITION" >/dev/null
debugfs -w -R 'sif /bin/true mode 0100755' "$PARTITION" >/dev/null
debugfs -w -R 'sif /bin/dash mode 0100755' "$PARTITION" >/dev/null
debugfs -w -R "sif $INTERPRETER mode 0100755" "$PARTITION" >/dev/null
debugfs -w -R "sif $LIBC mode 0100755" "$PARTITION" >/dev/null
if [ -n "$ROOT_EXEC_PROBE" ]; then
  [[ -x "$ROOT_EXEC_PROBE" ]]
  write_file "$ROOT_EXEC_PROBE" /usr/libexec/jasper/health-probe
  debugfs -w -R 'sif /usr/libexec/jasper/health-probe mode 0100755' "$PARTITION" >/dev/null
fi
if [ "$FULL_USERLAND" = 1 ]; then
  for source in "$GETCONF" "$PRINTF" "$UNAME" "$PWD_UTILITY" "$NPROC" "$SLEEP" "$FIND" "$LS" "$WC" "$HOSTNAME" "$BASENAME" "$DIRNAME" "$ID" "$LIBSYSTEMD" "$LIBSELINUX" "$LIBGCC_S" "$LIBM" "$LIBPCRE2"; do
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
if [ -n "$ROOT_PPID_FIXTURE" ]; then
  [[ -x "$ROOT_PPID_FIXTURE" ]]
  write_file "$ROOT_PPID_FIXTURE" /usr/bin/jasper-getppid
  debugfs -w -R 'sif /usr/bin/jasper-getppid mode 0100755' "$PARTITION" >/dev/null
fi
if [ -n "$ROOT_ANDROID_TOYBOX" ]; then
  [[ -x "$ROOT_ANDROID_TOYBOX" ]]
  write_file "$ROOT_ANDROID_TOYBOX" /usr/bin/toybox
  debugfs -w -R 'sif /usr/bin/toybox mode 0100755' "$PARTITION" >/dev/null
fi
if [ -n "$ROOT_AOSP_BINDER_TEST" ]; then
  [[ -x "$ROOT_AOSP_BINDER_TEST" ]]
  write_file "$ROOT_AOSP_BINDER_TEST" /usr/bin/aosp-binder-driver-test
  debugfs -w -R 'sif /usr/bin/aosp-binder-driver-test mode 0100755' "$PARTITION" >/dev/null
fi
if [ -n "$ROOT_ANDROID_TREE" ]; then
  [[ -d "$ROOT_ANDROID_TREE" ]]
  while IFS= read -r directory; do
    relative=${directory#"$ROOT_ANDROID_TREE"}
    [ -n "$relative" ] && ensure_dir "$relative"
  done < <(find "$ROOT_ANDROID_TREE" -type d -print | sort)
  while IFS= read -r -d '' source; do
    relative=${source#"$ROOT_ANDROID_TREE"/}
    if [ -n "$ROOT_ANDROID_LINKER_CONFIG" ] && [ "$relative" = linkerconfig/ld.config.txt ]; then
      continue
    fi
    destination="/$relative"
    write_file "$source" "$destination"
    if [[ -x "$source" ]]; then
      debugfs -w -R "sif $destination mode 0100755" "$PARTITION" >/dev/null
    else
      debugfs -w -R "sif $destination mode 0100644" "$PARTITION" >/dev/null
    fi
  done < <(find "$ROOT_ANDROID_TREE" -type f -print0)
fi
if [ -n "$ROOT_ANDROID_LINKER_CONFIG" ]; then
  [[ -f "$ROOT_ANDROID_LINKER_CONFIG" ]]
  ensure_dir /linkerconfig
  write_file "$ROOT_ANDROID_LINKER_CONFIG" /linkerconfig/ld.config.txt
  debugfs -w -R 'sif /linkerconfig/ld.config.txt mode 0100644' "$PARTITION" >/dev/null
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
verify_payload /bin/dash "$DASH"
verify_payload "$INTERPRETER" "$INTERPRETER"
verify_payload "$LIBC" "$LIBC"
if [ -n "$ROOT_EXEC_PROBE" ]; then
  verify_payload /usr/libexec/jasper/health-probe "$ROOT_EXEC_PROBE"
fi
if [ "$FULL_USERLAND" = 1 ]; then
  for source in "$GETCONF" "$PRINTF" "$UNAME" "$PWD_UTILITY" "$NPROC" "$SLEEP" "$FIND" "$LS" "$WC" "$HOSTNAME" "$BASENAME" "$DIRNAME" "$ID" "$LIBSYSTEMD" "$LIBSELINUX" "$LIBGCC_S" "$LIBM" "$LIBPCRE2"; do
    verify_payload "$source" "$source"
  done
fi
if [ -n "$ROOT_SIGNAL_FIXTURE" ]; then
  verify_payload /usr/bin/jasper-signal-basic "$ROOT_SIGNAL_FIXTURE"
fi
if [ -n "$ROOT_PPID_FIXTURE" ]; then
  verify_payload /usr/bin/jasper-getppid "$ROOT_PPID_FIXTURE"
fi
if [ -n "$ROOT_ANDROID_TOYBOX" ]; then
  verify_payload /usr/bin/toybox "$ROOT_ANDROID_TOYBOX"
fi
if [ -n "$ROOT_AOSP_BINDER_TEST" ]; then
  verify_payload /usr/bin/aosp-binder-driver-test "$ROOT_AOSP_BINDER_TEST"
fi
if [ -n "$ROOT_ANDROID_TREE" ]; then
  while IFS= read -r -d '' source; do
    relative=${source#"$ROOT_ANDROID_TREE"/}
    if [ -n "$ROOT_ANDROID_LINKER_CONFIG" ] && [ "$relative" = linkerconfig/ld.config.txt ]; then
      continue
    fi
    verify_payload "/$relative" "$source"
  done < <(find "$ROOT_ANDROID_TREE" -type f -print0)
fi
if [ -n "$ROOT_ANDROID_LINKER_CONFIG" ]; then
  verify_payload /linkerconfig/ld.config.txt "$ROOT_ANDROID_LINKER_CONFIG"
fi

dd if="$PARTITION" of="$IMAGE" bs=512 seek="$START_LBA" \
  conv=notrunc,sparse status=none
sync
echo "system-root-fixture: PASS slot=$SLOT release=$RELEASE start_lba=$START_LBA files=6 userland=x86_64-linux-elf root_exec_probe=$([ -n "$ROOT_EXEC_PROBE" ] && echo present || echo absent) full_userland=$FULL_USERLAND signal_fixture=$([ -n "$ROOT_SIGNAL_FIXTURE" ] && echo present || echo absent) ppid_fixture=$([ -n "$ROOT_PPID_FIXTURE" ] && echo present || echo absent) toybox=$([ -n "$ROOT_ANDROID_TOYBOX" ] && echo present || echo absent) aosp_binder_test=$([ -n "$ROOT_AOSP_BINDER_TEST" ] && echo present || echo absent) android_tree=$([ -n "$ROOT_ANDROID_TREE" ] && echo present || echo absent)"
