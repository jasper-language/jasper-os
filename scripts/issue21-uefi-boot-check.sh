#!/usr/bin/env bash
# Build a P0 GPT/ESP image and boot the production kernel through OVMF.
# 通过 OVMF 从 P0 GPT/ESP 启动生产内核。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${ISSUE21_UEFI_OUT:-$ROOT/evidence/issue21-uefi-boot-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${ISSUE21_UEFI_TARGET:-$ROOT/target/issue21-uefi-check}"
LIMIT="${ISSUE21_UEFI_TIMEOUT:-45}"
MODE="${ISSUE21_UEFI_MODE:-normal}"
mkdir -p "$OUT"
IMAGE="$TARGET/p0.img"
ESP_IMAGE="$TARGET/esp.img"
UEFI_ESP="$TARGET/uefi-esp.img"
OVMF_VARS="$TARGET/OVMF_VARS.fd"
KERNEL="$TARGET/x86_64-unknown-none/release/jasper-kernel"
# 仅清理本脚本固定命名的派生产物；证据目录必须独占，防止陈旧日志混入。
# Remove only this script's fixed derived files; evidence output must be fresh.
rm -f -- "$IMAGE" "$ESP_IMAGE" "$UEFI_ESP" "$OVMF_VARS"

case "$MODE" in
  root-exec) KERNEL_FEATURES=lifecycle-root-exec-verify ;;
  block-timeout) KERNEL_FEATURES=lifecycle-block-timeout-verify ;;
  *) KERNEL_FEATURES=production,lifecycle-ab-health ;;
esac
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none \
  -p jasper-kernel --features "$KERNEL_FEATURES" >"$OUT/kernel-build.log" 2>&1
cargo build --locked --release -p xtask >"$OUT/xtask-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-uefi \
  -p jasper-boot-manager >"$OUT/boot-manager-build.log" 2>&1

cargo run --locked -p jasper-lifecycle-staging --bin jasper-gpt-image -- \
  "$IMAGE" 38654705664 >"$OUT/gpt.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-esp-format -- \
  "$IMAGE" 38654705664 >"$OUT/esp-format.log" 2>&1
target/release/xtask uefi-managed-esp \
  "$KERNEL" "$KERNEL" \
  "$TARGET/x86_64-unknown-uefi/release/jasper-boot-manager.efi" \
  "$UEFI_ESP" >"$OUT/uefi-esp.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-esp-install -- \
  "$IMAGE" 38654705664 "$UEFI_ESP" >"$OUT/esp-install.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-ext4-provision -- \
  "$IMAGE" 38654705664 >"$OUT/ext4-provision.log" 2>&1
ROOT_EXEC_PROBE=""
ROOT_FULL_USERLAND=0
ROOT_SIGNAL_FIXTURE=""
ROOT_PPID_FIXTURE=""
if [ "$MODE" = root-exec ]; then
  ROOT_EXEC_PROBE=$(find "$TARGET/x86_64-unknown-none/release/build" \
    -path '*/out/user-target/x86_64-unknown-none/release/user-linuxprobe' \
    -type f -print | sort | tail -n 1)
  [ -n "$ROOT_EXEC_PROBE" ]
  ROOT_FULL_USERLAND=1
  ROOT_SIGNAL_FIXTURE="$TARGET/root-signal-basic"
  gcc -O2 -mavx -pthread -fno-stack-protector \
    verification/fixtures/linux/signal_basic.c \
    -o "$ROOT_SIGNAL_FIXTURE" >"$OUT/root-signal-build.log" 2>&1
  ROOT_PPID_FIXTURE="$TARGET/root-getppid"
  gcc -O2 verification/fixtures/linux/getppid.c \
    -o "$ROOT_PPID_FIXTURE" >"$OUT/root-ppid-build.log" 2>&1
fi
bash scripts/issue21-system-root-fixture.sh \
  "$IMAGE" "$TARGET" 1050624 A 1 "$ROOT_EXEC_PROBE" "$ROOT_FULL_USERLAND" "$ROOT_SIGNAL_FIXTURE" "$ROOT_PPID_FIXTURE" >"$OUT/system-root-a.log" 2>&1
bash scripts/issue21-system-root-fixture.sh \
  "$IMAGE" "$TARGET" 17827840 B 1 "$ROOT_EXEC_PROBE" "$ROOT_FULL_USERLAND" "$ROOT_SIGNAL_FIXTURE" "$ROOT_PPID_FIXTURE" >"$OUT/system-root-b.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-init -- \
  "$IMAGE" 38654705664 "$KERNEL" 1 1 1 1 1 >"$OUT/control-init.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" 38654705664 >"$OUT/control-inspect.log" 2>&1

if [ "$MODE" = both-controls-corrupt ]; then
  CORRUPT="$TARGET/control-unrecoverable.bin"
  printf 'JASPER-CORRUPT' >"$CORRUPT"
  dd if="$CORRUPT" of="$IMAGE" bs=1 seek=$((34605056 * 512)) conv=notrunc status=none
  dd if="$CORRUPT" of="$IMAGE" bs=1 seek=$((34736128 * 512)) conv=notrunc status=none
  sync
fi

dd if="$IMAGE" of="$ESP_IMAGE" bs=512 skip=2048 count=1048576 \
  conv=sparse status=none
fsck.fat -n -v -l "$ESP_IMAGE" >"$OUT/fsck-fat.log" 2>&1
! grep -qE 'Expected a valid|Bad short file name|Renamed to|share clusters|Start does point|Deleting ' \
  "$OUT/fsck-fat.log"
sgdisk -v "$IMAGE" >"$OUT/sgdisk.log" 2>&1
grep -q 'No problems found' "$OUT/sgdisk.log"

cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS"
QEMU_EXTRA=()
if [ "$MODE" = root-exec ]; then
  QEMU_EXTRA=(-cpu max -device isa-debug-exit,iobase=0xf4,iosize=0x04)
fi
set +e
timeout "$LIMIT" qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -m 512M \
  -smp 1 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$OVMF_VARS" \
  -drive file="$IMAGE",format=raw,if=virtio \
  -serial "file:$OUT/serial.log" \
  -display none -monitor none -no-reboot "${QEMU_EXTRA[@]}"
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/qemu.rc"
if [ "$MODE" = root-exec ]; then
  [ "$rc" -eq 33 ]
else
  [ "$rc" -eq 124 ]
fi
grep -aq 'Jasper-OS boot manager starting' "$OUT/serial.log"
if [ "$MODE" = block-timeout ]; then
  grep -aq '^\[JSR-BLK\] result=timeout injected=true' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=failed reason=block' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = root-exec ]; then
  grep -aq '^\[JSR-LIFE-ROOT-EXEC\] path=/usr/libexec/jasper/health-probe .* mapped=true cpl3=true exited=true syscalls=[1-9][0-9]* frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=bin/true path=/bin/true interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/getconf path=/usr/bin/getconf interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/uname path=/usr/bin/uname interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^Linux jasper 0.0.1 Jasper-OS Linux ABI 3.1.0 x86_64 ' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/hostname path=/usr/bin/hostname interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aqE $'^jasper\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/basename path=/usr/bin/basename interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aqE $'^libc[.]so[.]6\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/dirname path=/usr/bin/dirname interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aqE $'^/usr/lib/x86_64-linux-gnu\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/id path=/usr/bin/id interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aqE $'^0\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/pwd path=/usr/bin/pwd interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aqE $'^/\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/printf path=/usr/bin/printf interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/jasper-signal-basic path=/usr/bin/jasper-signal-basic interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^jasper-signal-ok' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/jasper-getppid path=/usr/bin/jasper-getppid interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^jasper-ppid=0' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-LIBS\] count=6 bytes=[1-9][0-9]* source=system-ab' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = both-controls-corrupt ]; then
  grep -aFq '[JSR-LIFE-RESCUE] active=none selected=false reason=control_copies_invalid recovery=required' \
    "$OUT/serial.log"
  ! grep -aq 'selecting slot=' "$OUT/serial.log"
  ! grep -aq '^\[JSR-BOOT-STAGE\]' "$OUT/serial.log"
  ! grep -aq '^\[JSR-PROD\]' "$OUT/serial.log"
  ! grep -aq '^\[JSR-LIFE-HEALTH\]' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
grep -aq 'selecting slot=A reason=ConfirmedRelease attempt=1 release=1' "$OUT/serial.log"
grep -aq '^\[JSR-BOOT-STAGE\] done stage=user_runtime' "$OUT/serial.log"
grep -aq '^\[JSR-PROD\] first_program state=Some(Exited { code: 0 }) reclaimed=true' "$OUT/serial.log"
grep -aq '^\[JSR-PLAN\] finish plan=production stages=0xffff cases=2' "$OUT/serial.log"
grep -aqE '^\[JSR-PROD\] alive ticks=[1-9][0-9]*' "$OUT/serial.log"
grep -aq '^\[JSR-LIFE-ROOT\] slot=A release=1 schema=1 userland=x86_64-linux-elf files=6' \
  "$OUT/serial.log"
grep -aq '^\[JSR-LIFE-HEALTH\] result=confirmed slot=A generation=3 release=1 attempts=0 storage=virtio-blk' \
  "$OUT/serial.log"
! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" 38654705664 >"$OUT/control-postboot.log" 2>&1
grep -q 'generation=3 ' "$OUT/control-postboot.log"
grep -q 'slot=A state=Confirmed generation=3 release=1 attempts=0' \
  "$OUT/control-postboot.log"

echo "issue21-uefi-boot: PASS qemu_rc=$rc evidence=$OUT"
