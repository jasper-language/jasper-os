#!/usr/bin/env bash
# Build a P0 GPT/ESP image and boot the production kernel through OVMF.
# 通过 OVMF 从 P0 GPT/ESP 启动生产内核。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

# Serialize the complete build/image/QEMU transaction even when callers bypass
# the host-side vm-run queue. 源码同步仍可并行，但 guest 的重型验收必须独占。
UEFI_BUILD_LOCK="${ISSUE21_UEFI_BUILD_LOCK:-/tmp/jasper-os-issue21-uefi-build.lock}"
if ! command -v flock >/dev/null 2>&1; then
  echo "issue21-uefi-boot: flock is required for guest resource exclusion" >&2
  exit 69
fi
exec 8>"$UEFI_BUILD_LOCK"
if ! flock -w "${ISSUE21_UEFI_BUILD_LOCK_WAIT:-3600}" 8; then
  echo "issue21-uefi-boot: guest build/QEMU queue wait timed out" >&2
  exit 75
fi

guest_busy() {
  # The build lock above already serializes every issue21 transaction. Treating
  # queued scripts as external work deadlocks: the lock holder waits for jobs
  # that can only make progress after the holder exits.
  # 上面的构建锁已串行化 issue21 事务；把排队脚本当成外部工作会形成死锁。
  pgrep -x qemu-system-x86_64 >/dev/null 2>&1 ||
    pgrep -x cargo >/dev/null 2>&1 ||
    pgrep -x rustc >/dev/null 2>&1
}

queue_deadline=$(($(date +%s) + ${ISSUE21_UEFI_BUILD_LOCK_WAIT:-3600}))
while :; do
  if ! guest_busy; then
    sleep 3
    ! guest_busy && break
  fi
  if [ "$(date +%s)" -ge "$queue_deadline" ]; then
    echo "issue21-uefi-boot: existing guest build/QEMU did not quiesce" >&2
    exit 75
  fi
  sleep 2
done

guarded_cargo() {
  "$ROOT/scripts/guarded-cargo.sh" "$@"
}

OUT="${ISSUE21_UEFI_OUT:-$ROOT/evidence/issue21-uefi-boot-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${ISSUE21_UEFI_TARGET:-$ROOT/target/issue21-uefi-check}"
BUILD_TARGET="${ISSUE21_UEFI_CARGO_TARGET:-$TARGET}"
CARGO_TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"
case "$CARGO_TARGET" in
  /*) ;;
  *) CARGO_TARGET="$ROOT/$CARGO_TARGET" ;;
esac
LIMIT="${ISSUE21_UEFI_TIMEOUT:-45}"
MODE="${ISSUE21_UEFI_MODE:-normal}"
REUSE_ROOT="${ISSUE21_REUSE_ROOT:-0}"
if [ -z "${ISSUE21_UEFI_TIMEOUT:-}" ] &&
  { [ "$MODE" = android-art ] || [ "$MODE" = android-apk ] ||
    [ "$MODE" = compat-wine-d3d ] || [ "$MODE" = compat-wine-d3d12 ] ||
    [ "$MODE" = compat-wine-wsi ] || [ "$MODE" = compat-jvm ] ||
    [ "$MODE" = compat-dotnet ] || [ "$MODE" = compat-darling ]; }; then
  LIMIT=900
fi
PREBUILT="${ISSUE21_UEFI_PREBUILT:-0}"
QEMU_LOCK="${ISSUE21_QEMU_LOCK:-/tmp/jasper-os-qemu.lock}"
QEMU_CPUS="${ISSUE21_QEMU_CPUS:-$($ROOT/scripts/qemu-cpu-set.sh)}"
QEMU_ACCEL="${ISSUE21_QEMU_ACCEL:-tcg}"
QEMU_SMP="${ISSUE21_QEMU_SMP:-1}"
QEMU_MEMORY="${ISSUE21_QEMU_MEMORY:-}"
if [ -z "$QEMU_MEMORY" ]; then
  if [ "$MODE" = android-art ] || [ "$MODE" = android-apk ] ||
    [ "$MODE" = compat-wine-d3d ] || [ "$MODE" = compat-wine-d3d12 ] ||
    [ "$MODE" = compat-wine-wsi ] || [ "$MODE" = compat-jvm ] ||
    [ "$MODE" = compat-dotnet ] || [ "$MODE" = compat-darling ]; then
    QEMU_MEMORY=2G
  else
    QEMU_MEMORY=512M
  fi
fi
mkdir -p "$OUT"
mkdir -p "$TARGET"
IMAGE="$TARGET/p0.img"
ESP_IMAGE="$TARGET/esp.img"
UEFI_ESP="$TARGET/uefi-esp.img"
OVMF_VARS="$TARGET/OVMF_VARS.fd"
KERNEL="$TARGET/x86_64-unknown-none/release/jasper-kernel"
BOOT_MANAGER="$TARGET/x86_64-unknown-uefi/release/jasper-boot-manager.efi"
SERIAL_READER=""
SERIAL_FEEDER=""

cleanup() {
  if [ -n "$SERIAL_FEEDER" ]; then
    kill "$SERIAL_FEEDER" 2>/dev/null || true
  fi
  if [ -n "$SERIAL_READER" ]; then
    kill "$SERIAL_READER" 2>/dev/null || true
  fi
  if [ "${ISSUE21_KEEP_DERIVED:-0}" != 1 ]; then
    rm -f -- "$IMAGE" "$ESP_IMAGE" "$UEFI_ESP" "$OVMF_VARS" \
      "$TARGET/system-A.img" "$TARGET/system-B.img"
  fi
  rm -f -- "$OUT/serial.in" "$OUT/serial.out"
}
on_exit() {
  status=$?
  trap - EXIT
  cleanup
  exit "$status"
}
trap on_exit EXIT

free_kib=$(df -Pk "$TARGET" | awk 'NR == 2 { print $4 }')
disk_floor_kib="${JASPER_QEMU_MIN_DISK_KIB:-4194304}"
if [ "${free_kib:-0}" -lt "$disk_floor_kib" ]; then
  echo "FAIL QEMU target filesystem has less than ${disk_floor_kib} KiB free: $TARGET" >&2
  exit 75
fi
available_kib=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
if [ "${available_kib:-0}" -lt 2097152 ]; then
  echo "FAIL less than 2 GiB host memory available" >&2
  exit 75
fi
load1=$(awk '{ print $1 }' /proc/loadavg)
if awk -v current_load="$load1" 'BEGIN { exit !(current_load > 8.0) }'; then
  echo "FAIL host one-minute load $load1 is too high for another VM" >&2
  exit 75
fi
runtime_active() {
  local comm name
  for comm in /proc/[0-9]*/comm; do
    [ -r "$comm" ] || continue
    IFS= read -r name <"$comm" 2>/dev/null || continue
    case "$name" in
      qemu-system*) return 0 ;;
    esac
  done
  return 1
}
exec 9>"$QEMU_LOCK"
if ! flock -w 900 9; then
  echo "FAIL Jasper-OS QEMU lock remained busy for 900s: $QEMU_LOCK" >&2
  exit 75
fi
if runtime_active; then
  echo "FAIL another qemu-system-x86_64 process is already running" >&2
  exit 75
fi

# 仅清理本脚本固定命名的派生产物；证据目录必须独占，防止陈旧日志混入。
# Remove only this script's fixed derived files; evidence output must be fresh.
if [ "$REUSE_ROOT" != 1 ] && [ "${ISSUE21_REUSE_P0:-0}" != 1 ]; then
  rm -f -- "$IMAGE" "$ESP_IMAGE" "$UEFI_ESP" "$OVMF_VARS"
fi

case "$MODE" in
  root-exec) KERNEL_FEATURES=lifecycle-root-exec-verify ;;
  sandbox-launch) KERNEL_FEATURES=lifecycle-root-exec-verify,sandbox-launch-verify ;;
  native-install-abi) KERNEL_FEATURES=native-install-abi-verify ;;
  terminal-session) KERNEL_FEATURES=lifecycle-root-exec-verify,terminal-session-verify ;;
  terminal-recovery) KERNEL_FEATURES=user-programs,production,lifecycle-ab-health,terminal-session-verify ;;
  update-list) KERNEL_FEATURES=native-install-list-cli-verify ;;
  update-agent) KERNEL_FEATURES=lifecycle-ab-health,update-agent-verify ;;
  driver-host-journal) KERNEL_FEATURES=driver-host-journal-verify ;;
  iommu-dma) KERNEL_FEATURES=iommu-dma-verify ;;
  android-ecosystem) KERNEL_FEATURES=lifecycle-root-exec-verify,android-ecosystem-verify ;;
  android-art) KERNEL_FEATURES=lifecycle-root-exec-verify,android-art-verify ;;
  android-apk) KERNEL_FEATURES=lifecycle-root-exec-verify,android-apk-verify ;;
  compat-wine) KERNEL_FEATURES=lifecycle-root-exec-verify,compat-wine-verify ;;
  compat-wine-d3d) KERNEL_FEATURES=lifecycle-root-exec-verify,compat-wine-verify,compat-wine-d3d-verify ;;
  compat-wine-d3d12) KERNEL_FEATURES=lifecycle-root-exec-verify,compat-wine-verify,compat-wine-d3d-verify,compat-wine-d3d12-verify ;;
  compat-wine-wsi) KERNEL_FEATURES=lifecycle-root-exec-verify,compat-wine-verify,compat-wine-d3d-verify,compat-wine-wsi-verify ;;
  compat-jvm) KERNEL_FEATURES=lifecycle-root-exec-verify,compat-jvm-verify ;;
  compat-dotnet) KERNEL_FEATURES=lifecycle-root-exec-verify,compat-dotnet-verify ;;
  compat-darling) KERNEL_FEATURES=lifecycle-root-exec-verify,compat-darling-verify ;;
  vulkan-metal2vulkan) KERNEL_FEATURES=lifecycle-root-exec-verify,vulkan-metal2vulkan-verify ;;
  vulkan-swiftshader) KERNEL_FEATURES=lifecycle-root-exec-verify,vulkan-metal2vulkan-verify,vulkan-compute-only ;;
  block-timeout) KERNEL_FEATURES=lifecycle-block-timeout-verify ;;
  *) KERNEL_FEATURES=production,lifecycle-ab-health ;;
esac
if [ "${JASPER_ANDROID_ONLY:-0}" = 1 ]; then
  KERNEL_FEATURES="$KERNEL_FEATURES,android-fixture-verify"
fi
KERNEL_DEFAULT_FEATURES=()
if [ "$MODE" = terminal-recovery ] || [ "$MODE" = update-agent ] || [ "$MODE" = driver-host-journal ] || [ "$MODE" = iommu-dma ]; then
  KERNEL_DEFAULT_FEATURES=(--no-default-features)
fi
if [ "$PREBUILT" = 1 ]; then
  [ -x "$KERNEL" ]
  [ -f "$BOOT_MANAGER" ]
  [ -x "$CARGO_TARGET/release/xtask" ]
  for binary in jasper-gpt-image jasper-esp-format jasper-esp-install \
    jasper-ext4-provision jasper-control-init jasper-control-inspect; do
    [ -x "$CARGO_TARGET/debug/$binary" ]
  done
  : >"$OUT/kernel-build.log"
  : >"$OUT/xtask-build.log"
  : >"$OUT/boot-manager-build.log"
else
  CARGO_TARGET_DIR="$BUILD_TARGET" guarded_cargo build --locked --release --target x86_64-unknown-none \
    -p jasper-kernel "${KERNEL_DEFAULT_FEATURES[@]}" --features "$KERNEL_FEATURES" >"$OUT/kernel-build.log" 2>&1
  guarded_cargo build --locked --release -p xtask >"$OUT/xtask-build.log" 2>&1
  CARGO_TARGET_DIR="$BUILD_TARGET" guarded_cargo build --locked --release --target x86_64-unknown-uefi \
    -p jasper-boot-manager >"$OUT/boot-manager-build.log" 2>&1
  if [ "$BUILD_TARGET" != "$TARGET" ]; then
    mkdir -p "$(dirname "$KERNEL")" "$(dirname "$BOOT_MANAGER")"
    install -m 0755 "$BUILD_TARGET/x86_64-unknown-none/release/jasper-kernel" "$KERNEL"
    install -m 0644 "$BUILD_TARGET/x86_64-unknown-uefi/release/jasper-boot-manager.efi" "$BOOT_MANAGER"
  fi
fi

run_lifecycle() {
  local binary=$1
  shift
  if [ "$PREBUILT" = 1 ]; then
    "$CARGO_TARGET/debug/$binary" "$@"
  else
    guarded_cargo run --locked -p jasper-lifecycle-staging --bin "$binary" -- "$@"
  fi
}

if [ "$REUSE_ROOT" != 1 ] && [ "${ISSUE21_REUSE_P0:-0}" != 1 ]; then
  run_lifecycle jasper-gpt-image \
    "$IMAGE" 38654705664 >"$OUT/gpt.log" 2>&1
  run_lifecycle jasper-esp-format \
    "$IMAGE" 38654705664 >"$OUT/esp-format.log" 2>&1
fi
if [ "$REUSE_ROOT" = 1 ] || [ "${ISSUE21_REUSE_P0:-0}" != 1 ]; then
  if [ "$REUSE_ROOT" = 1 ]; then
    run_lifecycle jasper-esp-format \
      "$IMAGE" 38654705664 >"$OUT/esp-format.log" 2>&1
  fi
  rm -f -- "$UEFI_ESP"
  "$CARGO_TARGET/release/xtask" uefi-managed-esp \
    "$KERNEL" "$KERNEL" \
    "$BOOT_MANAGER" \
    "$UEFI_ESP" >"$OUT/uefi-esp.log" 2>&1
  run_lifecycle jasper-esp-install \
    "$IMAGE" 38654705664 "$UEFI_ESP" >"$OUT/esp-install.log" 2>&1
  if [ "$REUSE_ROOT" = 1 ]; then
    dd if=/dev/zero of="$IMAGE" bs=512 seek=34605056 count=131072 \
      conv=notrunc status=none
    dd if=/dev/zero of="$IMAGE" bs=512 seek=34736128 count=131072 \
      conv=notrunc status=none
    run_lifecycle jasper-control-init \
      "$IMAGE" 38654705664 "$KERNEL" 1 1 1 1 1 >"$OUT/control-init.log" 2>&1
    run_lifecycle jasper-control-inspect \
      "$IMAGE" 38654705664 >"$OUT/control-inspect.log" 2>&1
  fi
fi
if [ "$REUSE_ROOT" != 1 ] && [ "${ISSUE21_REUSE_P0:-0}" != 1 ]; then
  run_lifecycle jasper-ext4-provision \
    "$IMAGE" 38654705664 >"$OUT/ext4-provision.log" 2>&1
fi
ROOT_EXEC_PROBE=""
ROOT_FULL_USERLAND=0
ROOT_SIGNAL_FIXTURE=""
ROOT_PPID_FIXTURE=""
ROOT_STDIO_FIXTURE=""
ROOT_ANDROID_TOYBOX="${JASPER_TOYBOX_BIN:-}"
ROOT_AOSP_BINDER_TEST="${JASPER_AOSP_BINDER_TEST:-}"
ROOT_ANDROID_TREE="${JASPER_ANDROID_TREE:-}"
ROOT_ANDROID_LINKER_CONFIG=""
if [ "$MODE" = root-exec ] || [ "$MODE" = sandbox-launch ] || [ "$MODE" = native-install-abi ] || [ "$MODE" = terminal-session ] || [ "$MODE" = android-ecosystem ] || [ "$MODE" = android-art ] || [ "$MODE" = android-apk ] || [ "$MODE" = compat-wine ] || [ "$MODE" = compat-wine-d3d ] || [ "$MODE" = compat-wine-d3d12 ] || [ "$MODE" = compat-wine-wsi ] || [ "$MODE" = compat-jvm ] || [ "$MODE" = compat-dotnet ] || [ "$MODE" = compat-darling ] || [ "$MODE" = vulkan-metal2vulkan ] || [ "$MODE" = vulkan-swiftshader ]; then
  ROOT_EXEC_PROBE=$(find "$BUILD_TARGET/x86_64-unknown-none/release/build" \
    -path '*/out/user-target/x86_64-unknown-none/release/user-linuxprobe' \
    -type f -print | sort | tail -n 1)
  [ -n "$ROOT_EXEC_PROBE" ]
  ROOT_FULL_USERLAND=1
  ROOT_SIGNAL_FIXTURE="$TARGET/root-signal-basic"
  gcc -O2 -mavx -pthread -fno-stack-protector \
    verification/fixtures/linux/signal_basic.c \
    -o "$ROOT_SIGNAL_FIXTURE" >"$OUT/root-signal-build.log" 2>&1
  ROOT_PPID_FIXTURE="$TARGET/root-getppid"
  ANDROID_FIXTURE_FLAGS=()
  if [ "${JASPER_ANDROID_ONLY:-0}" = 1 ]; then
    ANDROID_FIXTURE_FLAGS=(-DJASPER_ANDROID_ONLY)
  fi
  gcc -O2 -pthread verification/fixtures/linux/getppid.c \
    "${ANDROID_FIXTURE_FLAGS[@]}" \
    -o "$ROOT_PPID_FIXTURE" >"$OUT/root-ppid-build.log" 2>&1
  if [ "$MODE" = compat-wine ]; then
    ROOT_STDIO_FIXTURE="$TARGET/root-file-stdio"
    gcc -O2 -fno-stack-protector verification/fixtures/linux/file_stdio.c \
      -o "$ROOT_STDIO_FIXTURE" >"$OUT/root-file-stdio-build.log" 2>&1
  fi
  if [ "$MODE" = android-ecosystem ] && [ -z "$ROOT_ANDROID_TOYBOX" ]; then
    echo "issue21-uefi-boot: JASPER_TOYBOX_BIN is required for android-ecosystem mode" >&2
    exit 64
  fi
  if [ "$MODE" = android-ecosystem ] && [ -z "$ROOT_AOSP_BINDER_TEST" ]; then
    echo "issue21-uefi-boot: JASPER_AOSP_BINDER_TEST is required for android-ecosystem mode" >&2
    exit 64
  fi
  if { [ "$MODE" = android-art ] || [ "$MODE" = android-apk ]; } && [ -z "$ROOT_ANDROID_TREE" ]; then
    echo "issue21-uefi-boot: JASPER_ANDROID_TREE is required for $MODE mode" >&2
    exit 64
  fi
  if { [ "$MODE" = compat-wine ] || [ "$MODE" = compat-wine-d3d ] || [ "$MODE" = compat-wine-d3d12 ] || [ "$MODE" = compat-wine-wsi ] || [ "$MODE" = compat-jvm ] || [ "$MODE" = compat-dotnet ] || [ "$MODE" = compat-darling ] || [ "$MODE" = vulkan-metal2vulkan ] || [ "$MODE" = vulkan-swiftshader ]; } && [ -z "$ROOT_ANDROID_TREE" ]; then
    echo "issue21-uefi-boot: JASPER_ANDROID_TREE is required for $MODE mode" >&2
    exit 64
  fi
  if [ "$MODE" = android-art ] || [ "$MODE" = android-apk ]; then
    ROOT_ANDROID_LINKER_CONFIG="$PWD/verification/fixtures/android/ld.config.txt"
  fi
  if [ "$MODE" = android-apk ]; then
    APK="$ROOT_ANDROID_TREE/data/local/tmp/app.apk"
    AAPT2="${ANDROID_AAPT2:-$(command -v aapt2 || true)}"
    [ -f "$APK" ] || {
      echo "issue21-uefi-boot: upstream APK is missing: $APK" >&2
      exit 64
    }
    [ -n "$AAPT2" ] && [ -x "$AAPT2" ] || {
      echo "issue21-uefi-boot: set ANDROID_AAPT2 to an executable AOSP aapt2" >&2
      exit 64
    }
    python3 scripts/android-apk-preflight.py \
      --apk "$APK" \
      --aapt2 "$AAPT2" \
      --expected-package "${ANDROID_APK_PACKAGE:-com.example.androidautobuildapk}" \
      --expected-activity "${ANDROID_APK_ACTIVITY:-com.example.androidautobuildapk.MainActivity}" \
      --expected-sha256 "${ANDROID_APK_SHA256:-22c31a97b1e551d2814df0e9d2f59c5da93f37c9b43e2e03ac0f84c4359c0d05}" \
      | tee "$OUT/apk-preflight.log"
  fi
fi
if [ "$REUSE_ROOT" != 1 ] && [ "${ISSUE21_REUSE_P0:-0}" != 1 ]; then
  bash scripts/issue21-system-root-fixture.sh \
    "$IMAGE" "$TARGET" 1050624 A 1 "$ROOT_EXEC_PROBE" "$ROOT_FULL_USERLAND" "$ROOT_SIGNAL_FIXTURE" "$ROOT_PPID_FIXTURE" "$ROOT_ANDROID_TOYBOX" "$ROOT_AOSP_BINDER_TEST" "$ROOT_ANDROID_TREE" "$ROOT_ANDROID_LINKER_CONFIG" "$ROOT_STDIO_FIXTURE" >"$OUT/system-root-a.log" 2>&1
  bash scripts/issue21-system-root-fixture.sh \
    "$IMAGE" "$TARGET" 17827840 B 1 "$ROOT_EXEC_PROBE" "$ROOT_FULL_USERLAND" "$ROOT_SIGNAL_FIXTURE" "$ROOT_PPID_FIXTURE" "$ROOT_ANDROID_TOYBOX" "$ROOT_AOSP_BINDER_TEST" "$ROOT_ANDROID_TREE" "$ROOT_ANDROID_LINKER_CONFIG" "$ROOT_STDIO_FIXTURE" >"$OUT/system-root-b.log" 2>&1
  run_lifecycle jasper-control-init \
    "$IMAGE" 38654705664 "$KERNEL" 1 1 1 1 1 >"$OUT/control-init.log" 2>&1
  run_lifecycle jasper-control-inspect \
    "$IMAGE" 38654705664 >"$OUT/control-inspect.log" 2>&1
fi

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

if [ "$REUSE_ROOT" != 1 ] && [ "${ISSUE21_REUSE_P0:-0}" != 1 ]; then
  cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS"
fi
QEMU_EXTRA=(-monitor none)
if [ -n "${ISSUE21_MONITOR_SOCKET:-}" ]; then
  QEMU_EXTRA=(-monitor "unix:$ISSUE21_MONITOR_SOCKET,server=on,wait=off")
fi
if [ "$MODE" = root-exec ] || [ "$MODE" = sandbox-launch ] || [ "$MODE" = native-install-abi ] || [ "$MODE" = terminal-session ] || [ "$MODE" = terminal-recovery ] || [ "$MODE" = update-list ] || [ "$MODE" = update-agent ] || [ "$MODE" = driver-host-journal ] || [ "$MODE" = iommu-dma ] || [ "$MODE" = android-ecosystem ] || [ "$MODE" = android-art ] || [ "$MODE" = android-apk ] || [ "$MODE" = compat-wine ] || [ "$MODE" = compat-jvm ] || [ "$MODE" = compat-dotnet ] || [ "$MODE" = compat-darling ] || [ "$MODE" = vulkan-metal2vulkan ] || [ "$MODE" = vulkan-swiftshader ]; then
  if [ "$MODE" = compat-jvm ] || [ "$MODE" = compat-dotnet ]; then
    CPU="${ISSUE21_QEMU_CPU:-max,-avx,-avx2}"
  else
    CPU="${ISSUE21_QEMU_CPU:-max}"
  fi
  if [ "${ISSUE21_DISABLE_RDRAND:-0}" = 1 ]; then
    CPU="$CPU,-rdrand,-rdseed"
  fi
  QEMU_EXTRA+=(-cpu "$CPU")
  if [ "$MODE" = iommu-dma ]; then
    QEMU_EXTRA+=(
      -device "intel-iommu,intremap=off,caching-mode=on,device-iotlb=on"
      -device "virtio-rng-pci,disable-legacy=on,iommu_platform=on"
    )
  else
    QEMU_EXTRA+=(-device virtio-rng-pci)
  fi
  QEMU_EXTRA+=(-device isa-debug-exit,iobase=0xf4,iosize=0x04)
fi
SERIAL_ARGS=(-serial "file:$OUT/serial.log")
if { [ "$MODE" = terminal-session ] || [ "$MODE" = terminal-recovery ] || [ "$MODE" = update-list ]; } && [ "${ISSUE21_MANUAL_INPUT:-0}" != 1 ]; then
  rm -f -- "$OUT/serial.in" "$OUT/serial.out"
  mkfifo "$OUT/serial.in" "$OUT/serial.out"
  cat "$OUT/serial.out" >"$OUT/serial.log" &
  SERIAL_READER=$!
  (
    exec 8>"$OUT/serial.in"
    # UEFI/TCG can drop individual prompt bytes under serial load. Prefer a
    # semantic readiness marker, but never let damaged logging stall the guest.
    ready_deadline=$(($(date +%s) + ${ISSUE21_SERIAL_READY_TIMEOUT:-90}))
    while ! grep -aqE 'jasper> |Jasper-OS native CLI|terminal[.]read|JSR-PROD' "$OUT/serial.log" &&
      [ "$(date +%s)" -lt "$ready_deadline" ]; do
      sleep 1
    done
    feed() {
      printf '%s\n' "$1" >&8
      sleep "${ISSUE21_SERIAL_FEED_DELAY:-0.2}"
    }
    if [ "$MODE" = update-list ]; then
      feed 'help'
      feed 'system update list'
      feed 'system update list --json'
      feed 'system update list --schema'
      feed 'system update list --help'
      feed 'exit'
    else
      feed 'help'
      feed 'system update status'
      feed 'system update status --json'
      feed 'system update status --schema'
      feed 'system update status --help'
      feed 'system update recover'
      feed 'system update recover --json'
      feed 'system update recover --schema'
      feed 'system update recover --help'
      feed 'system update archive'
      feed 'system update archive --json'
      feed 'system update archive --schema'
      feed 'system update archive --help'
      feed 'system update audit'
      feed 'system update audit --json'
      feed 'system update audit --schema'
      feed 'system update audit --help'
      feed 'echo history'
      printf '\016' >&8
      sleep "${ISSUE21_SERIAL_FEED_DELAY:-0.2}"
      printf '\003\004' >&8
    fi
  ) &
  SERIAL_FEEDER=$!
  SERIAL_ARGS=(-serial "pipe:$OUT/serial")
fi
if [ "${ISSUE21_QEMU_TRACE:-0}" = 1 ]; then
  QEMU_EXTRA+=(-d int -D "$OUT/qemu-int.log")
fi
if [ -n "${ISSUE21_QEMU_TRACE_EVENTS:-}" ]; then
  IFS=',' read -r -a trace_events <<<"${ISSUE21_QEMU_TRACE_EVENTS}"
  for trace_event in "${trace_events[@]}"; do
    QEMU_EXTRA+=(-trace "enable=${trace_event}")
  done
  QEMU_EXTRA+=(-D "$OUT/qemu-trace.log")
fi
if [ "${ISSUE21_QEMU_GDB:-0}" = 1 ]; then
  QEMU_EXTRA+=(-s -S)
fi
set +e
nice -n 15 taskset -c "$QEMU_CPUS" timeout "$LIMIT" qemu-system-x86_64 \
  -accel "$QEMU_ACCEL" \
  -machine q35 \
  -m "$QEMU_MEMORY" \
  -smp "$QEMU_SMP" \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$OVMF_VARS" \
  -drive file="$IMAGE",format=raw,if=virtio \
  "${SERIAL_ARGS[@]}" \
  -display none -no-reboot "${QEMU_EXTRA[@]}"
rc=$?
set -e
exec 9>&-
printf '%s\n' "$rc" >"$OUT/qemu.rc"
if [ "$MODE" = root-exec ] || [ "$MODE" = sandbox-launch ] || [ "$MODE" = native-install-abi ] || [ "$MODE" = terminal-session ] || [ "$MODE" = update-list ] || [ "$MODE" = update-agent ] || [ "$MODE" = driver-host-journal ] || [ "$MODE" = iommu-dma ] || [ "$MODE" = android-ecosystem ] || [ "$MODE" = android-art ] || [ "$MODE" = android-apk ] || [ "$MODE" = compat-wine ] || [ "$MODE" = compat-jvm ] || [ "$MODE" = compat-dotnet ] || [ "$MODE" = compat-darling ] || [ "$MODE" = vulkan-metal2vulkan ] || [ "$MODE" = vulkan-swiftshader ]; then
  [ "$rc" -eq 33 ]
else
  [ "$rc" -eq 124 ]
fi
grep -aq 'Jasper-OS boot manager starting' "$OUT/serial.log"
if [ "$MODE" = update-agent ]; then
  grep -aq '^\[JSR-PROD\] first_program state=Some(Exited { code: 0 }) reclaimed=true' "$OUT/serial.log"
  grep -aq 'text=\[JSR-UPDATE-AGENT-CONCURRENT\] workers=4 rounds=6 process_isolation=true failed=0 ok=true' "$OUT/serial.log"
  grep -aq 'text=\[JSR-UPDATE-AGENT\] transport=channel status=true recover=true archive=true list=true replay=true timeout=true after_timeout=true concurrent=true server_app=[1-9][0-9]* child_exit=0 ok=true payload_mismatch=true' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = driver-host-journal ]; then
  grep -aq '^\[JSR-DRIVER-HOST-JOURNAL\] mounted=true ' "$OUT/serial.log"
  grep -aq '^\[JSR-DRIVER-HOST-JOURNAL\] summary .* sequence=5 .* live_restored=false ok=true' "$OUT/serial.log"
  grep -aq '^\[JSR-DRIVER-HOST-JOURNAL\] mounted=true .* sequence=5 last=reset .* live_restored=false' "$OUT/serial.log"
  case "${ISSUE21_DRIVER_HOST_EXPECT:-}" in
    initialized)
      grep -aq '^\[JSR-DRIVER-HOST-JOURNAL\] mounted=true initialized=true sequence=5 last=reset ' "$OUT/serial.log"
      ;;
    reopened)
      grep -aq '^\[JSR-DRIVER-HOST-JOURNAL\] mounted=true initialized=false sequence=5 last=reset ' "$OUT/serial.log"
      ;;
    "")
      ;;
    *)
      echo "issue21-uefi-boot: invalid ISSUE21_DRIVER_HOST_EXPECT" >&2
      exit 64
      ;;
  esac
  ! grep -aqE '^\[JSR-(PANIC|DRIVER-HOST-JOURNAL-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = iommu-dma ]; then
  grep -aq '^\[JSR-IOMMU-DMA\] hardware_iommu=true .* translated=true' "$OUT/serial.log"
  grep -Eaq 'text=\[JSR-DC1\] summary .*queue_work=true.*failed=0' "$OUT/serial.log"
  grep -aq '^\[JSR-DRV3\].*iova_opaque=true .* failed=0' "$OUT/serial.log"
  grep -aq '^\[JSR-IOMMU-DMA\] finish failed=0' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|DRV3-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = update-list ]; then
  grep -aq '^\[JSR-PROD\] first_program state=Some(Exited { code: 0 }) reclaimed=true' "$OUT/serial.log"
  grep -aqE $'^Jasper-OS native CLI\r?$' "$OUT/serial.log"
  grep -aqE $'^native-help-ok\r?$' "$OUT/serial.log"
  grep -aqE $'^system-update list=ok command=system[.]update[.]list count=0 request=[1-9][0-9]*\r?$' "$OUT/serial.log"
  grep -aqE $'^\{"schema":"service[.]update[.]list/1","command":"system[.]update[.]list","status":"ok","request":[1-9][0-9]*,"records":\[\]\}\r?$' "$OUT/serial.log"
  grep -aqE $'^\{"schema":"jucs[.]command/1","id":"system[.]update[.]list","version":1,"effects":"read","arguments":\[\],"options":\["--help","--schema","--json"\],"service":"service[.]update[.]list","service_version":1\}\r?$' "$OUT/serial.log"
  grep -aqE $'^system update list \[\-\-help\|--schema\|--json\]\r?$' "$OUT/serial.log"
  grep -aqE $'^native-bye\r?$' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = terminal-recovery ]; then
  grep -aq '^\[JSR-PROD\] first_program state=Some(Exited { code: 0 }) reclaimed=true' "$OUT/serial.log"
  grep -aqE $'^Jasper-OS native CLI\r?$' "$OUT/serial.log"
  grep -aqE $'^native-help-ok\r?$' "$OUT/serial.log"
  grep -aqE $'^system-update status=ok command=system[.]update[.]status generation=[1-9][0-9]* transaction=[1-9][0-9]* terminal=(none|complete|rolled_back) active=[AB] state=confirmed release=[1-9][0-9]* .*caller=[1-9][0-9]* domain=1 tenant=[1-9][0-9]* request=[1-9][0-9]*\r?$' "$OUT/serial.log"
  grep -aqE $'^system-update result=ok command=system[.]update[.]recover action=recover generation=[1-9][0-9]* transaction=[1-9][0-9]* recovery_required=false tenant=[1-9][0-9]* request=[1-9][0-9]*\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-UPDATE-ACTION\].*action=recover result=ok' "$OUT/serial.log"
  grep -aqE $'^system-update result=ok command=system[.]update[.]archive action=archive generation=[1-9][0-9]* transaction=[1-9][0-9]* archived=true tenant=[1-9][0-9]* request=[1-9][0-9]*\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-UPDATE-ARCHIVE\].*terminal=Complete result=ok' "$OUT/serial.log"
  grep -aqE $'^system-update audit=ok command=system[.]update[.]audit request=[1-9][0-9]* available=true sequence=1 transaction=[1-9][0-9]* terminal=complete\r?$' "$OUT/serial.log"
  grep -aqE $'^\[JSR-UPDATE-AUDIT\].*available=true sequence=1 .*result=ok\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=confirmed ' "$OUT/serial.log"
  python3 - "$OUT/serial.log" <<'PY'
import json
import sys

status_records = []
recover_records = []
archive_records = []
audit_records = []
with open(sys.argv[1], "rb") as stream:
    for raw in stream:
        line = raw.rstrip(b"\r\n")
        if line.startswith(b'{"schema":"service.update.status/1"'):
            status_records.append(json.loads(line))
        if line.startswith(b'{"schema":"service.update.action/1"'):
            record = json.loads(line)
            if record["command"] == "system.update.recover":
                recover_records.append(record)
            elif record["command"] == "system.update.archive":
                archive_records.append(record)
        if line.startswith(b'{"schema":"service.update.audit/1"'):
            audit_records.append(json.loads(line))

assert status_records, "missing structured update status"
status = status_records[-1]
assert recover_records, "missing structured recovery action"
action = recover_records[-1]
assert action["schema"] == "service.update.action/1"
assert action["command"] == "system.update.recover"
assert action["status"] == "ok"
assert action["action"] == "recover"
assert action["generation"] == status["generation"]
assert action["transaction"] == status["transaction"]
assert action["digest"] == (
    status["candidate"]["digest"]
    if status["candidate"] is not None
    else status["active"]["digest"]
)
assert action["recovery_required"] is False
assert action["archived"] is False
assert action["caller"]["domain"] == 1
assert archive_records, "missing structured archive action"
archive = archive_records[-1]
assert archive["schema"] == "service.update.action/1"
assert archive["command"] == "system.update.archive"
assert archive["status"] == "ok"
assert archive["action"] == "archive"
assert archive["generation"] == status["generation"]
assert archive["transaction"] == status["transaction"]
assert archive["digest"] == status["transaction_digest"]
assert archive["archived"] is True
assert archive["caller"]["domain"] == 1
assert audit_records, "missing durable archive audit"
audit = audit_records[-1]
assert audit["schema"] == "service.update.audit/1"
assert audit["command"] == "system.update.audit"
assert audit["available"] is True
assert audit["sequence"] == 1
assert audit["transaction"] == archive["transaction"]
assert audit["digest"] == archive["digest"]
assert audit["terminal"] == "complete"
PY
  grep -aqE $'^\{"schema":"jucs.command/1","id":"system.update.recover","version":1,"effects":"write","arguments":\[\],"options":\["--help","--schema","--json"\],"service":"service.update.recover","service_version":1\}\r?$' "$OUT/serial.log"
  grep -aqE $'^system update recover \[\-\-help\|--schema\|--json\]\r?$' "$OUT/serial.log"
  grep -aqE $'^\{"schema":"jucs.command/1","id":"system.update.archive","version":1,"effects":"write","arguments":\[\],"options":\["--help","--schema","--json"\],"service":"service.update.archive","service_version":1\}\r?$' "$OUT/serial.log"
  grep -aqE $'^system update archive \[\-\-help\|--schema\|--json\]\r?$' "$OUT/serial.log"
  grep -aqE $'^\{"schema":"jucs.command/1","id":"system.update.audit","version":1,"effects":"read","arguments":\[\],"options":\["--help","--schema","--json"\],"service":"service.update.audit","service_version":1\}\r?$' "$OUT/serial.log"
  grep -aqE $'^system update audit \[\-\-help\|--schema\|--json\]\r?$' "$OUT/serial.log"
  grep -aqE $'^native-bye\r?$' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = block-timeout ]; then
  grep -aq '^\[JSR-BLK\] result=timeout injected=true' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=failed reason=block' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = native-install-abi ]; then
  grep -aq '^\[JSR-PROD\] first_program state=Some(Exited { code: 0 }) reclaimed=true' "$OUT/serial.log"
  grep -aqE $'^(\\[JSR-USERTEXT\\].*text=)?native-install-abi: ok package=true idempotent=true register=true grant=true query=true updates=true update_short=true handle=true rights=true close=true denied_short=true\r?$' "$OUT/serial.log"
  case "${ISSUE21_NATIVE_INSTALL_EXPECT:-}" in
    initialized)
      grep -aq '^\[JSR-NATIVE-INSTALL-STORE\] mounted=true initialized=true ' "$OUT/serial.log"
      ;;
    reopened)
      grep -aq '^\[JSR-NATIVE-INSTALL-STORE\] mounted=true initialized=false ' "$OUT/serial.log"
      ;;
    "")
      ;;
    *)
      echo "issue21-uefi-boot: invalid ISSUE21_NATIVE_INSTALL_EXPECT" >&2
      exit 64
      ;;
  esac
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = android-ecosystem ]; then
  grep -aq '^\[JSR-LIFE-ROOT-EXEC\] path=/usr/libexec/jasper/health-probe .* mapped=true cpl3=true exited=true syscalls=[1-9][0-9]* frames_before=[0-9]* frames_after=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-ANDROID-TOYBOX\] program=android-toybox-uname static=true mapped=true started=true syscalls=[1-9][0-9]* exit_zero=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-ANDROID-TOYBOX\] program=android-toybox-printf static=true mapped=true started=true syscalls=[1-9][0-9]* exit_zero=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-ANDROID-TOYBOX\] program=android-toybox-sha256sum static=true mapped=true started=true syscalls=[1-9][0-9]* exit_zero=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-ANDROID-TOYBOX\] program=aosp-binder-driver-test static=true mapped=true started=true syscalls=[1-9][0-9]* exit_zero=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = android-apk ]; then
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=android-apk-upstream path=/system/bin/dalvikvm64 interpreter=/system/bin/linker64 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = compat-wine ]; then
  grep -aq '^FILE_STDIO_OK stdio_stat=true pipe_stat=true socket_stat=true file_status=true positioned_io=true vectored_fd=true cwd_status=true record_lock=true monotonic_time=true unix_socket=true socket_message=true epoll_status=true vfs_path=true unlink_lifetime=true shared_mmap=true materialized_fork_inherit=true fixed_prot_none_replace=true low_window=true' "$OUT/serial.log"
  grep -aq '^WINE_CMD_OK' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=compat-wine-cmd path=/usr/lib/x86_64-linux-gnu/wine/wine interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = compat-wine-d3d ]; then
  grep -aq '^D3D11_PROBE_OK feature=0x[0-9a-f]* pixel=32,64,128,255' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=compat-wine-d3d11 path=/opt/wine-devel/lib/wine/x86_64-unix/wine interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = compat-wine-d3d12 ]; then
  grep -aq '^D3D12_PROBE_OK pixel=32,64,128,255 observed=' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=compat-wine-d3d12 path=/opt/wine-devel/lib/wine/x86_64-unix/wine interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = compat-wine-wsi ]; then
  grep -aq '^D3D11_WSI_PROBE_OK .*present=1' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=compat-wine-wsi path=/opt/wine-devel/lib/wine/x86_64-unix/wine interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = compat-jvm ]; then
  grep -aq '^JVM_PROBE_OK value=499500 thread=true gc=true file=true java=' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=openjdk21-jvm path=/data/runtimes/openjdk/bin/java interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = compat-dotnet ]; then
  grep -aq '^DOTNET_PROBE_OK runtime=10\.0\.15 checksum=150015000 thread=true task=true gc=true exception=true file=true socket=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=dotnet10-coreclr path=/data/runtimes/dotnet/DotnetProbe interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = compat-darling ]; then
  grep -aq '^Failed to create socket: Invalid argument' "$OUT/serial.log"
  grep -aq '^Cannot mmap commpage: Cannot allocate memory' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=darling-launcher path=/data/runtimes/darling/usr/bin/darling interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=false frames_before=[0-9]* resources=false failed=[1-9][0-9]*' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-COMPAT-DYNAMIC-RESOURCE\] program=darling-launcher .* retained=0 ' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aq 'DARLING_JASPER_GUEST_OK' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: RECORDED mode=$MODE qemu_rc=$rc gate=proc-mounted-runtime-blocked evidence=$OUT"
  exit 0
fi
if [ "$MODE" = android-art ]; then
  grep -aq '^JVM_OK value=499500' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=android-art-official-001 path=/system/bin/dalvikvm64 interpreter=/system/bin/linker64 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=android-art-official-002 path=/system/bin/dalvikvm64 interpreter=/system/bin/linker64 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=android-art-official-003 path=/system/bin/dalvikvm64 interpreter=/system/bin/linker64 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=android-art-upstream-apk path=/system/bin/dalvikvm64 interpreter=/system/bin/linker64 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=system/bin/dalvikvm64 path=/system/bin/dalvikvm64 interpreter=/system/bin/linker64 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = vulkan-swiftshader ]; then
  grep -aq '^output\[0\.\.4\] = \[0\.0, 3\.0, 6\.0, 9\.0\].*as expected' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=metal2vulkan-compute path=/usr/bin/metal2vulkan-compute interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = vulkan-metal2vulkan ]; then
  grep -aq '^output\[0\.\.4\] = \[0\.0, 3\.0, 6\.0, 9\.0\].*as expected' "$OUT/serial.log"
  grep -aq '^every texel as expected' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=metal2vulkan-compute path=/usr/bin/metal2vulkan-compute interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=metal2vulkan-render path=/usr/bin/metal2vulkan-render interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "${JASPER_ANDROID_ONLY:-0}" = 1 ]; then
  grep -aq '^\[JSR-LIFE-ROOT-EXEC\] path=/usr/libexec/jasper/health-probe .* mapped=true cpl3=true exited=true syscalls=[1-9][0-9]* frames_before=[0-9]* frames_after=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/jasper-getppid path=/usr/bin/jasper-getppid interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=false failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/jasper-getppid path=/usr/bin/jasper-getppid interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true failed=0' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT\] slot=A release=1 schema=1 userland=x86_64-linux-elf' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-HEALTH\] result=root_execution_complete' \
    "$OUT/serial.log"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$OUT/serial.log"
  echo "issue21-uefi-boot: PASS mode=$MODE android_only=true qemu_rc=$rc evidence=$OUT"
  exit 0
fi
if [ "$MODE" = root-exec ] || [ "$MODE" = sandbox-launch ] || [ "$MODE" = native-install-abi ] || [ "$MODE" = terminal-session ]; then
  grep -aq '^\[JSR-LIFE-ROOT-EXEC\] path=/usr/libexec/jasper/health-probe .* mapped=true cpl3=true exited=true syscalls=[1-9][0-9]* frames_before=[0-9]* frames_after=[0-9]* resources=true' \
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
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/nproc path=/usr/bin/nproc interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/sleep path=/usr/bin/sleep interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/find path=/usr/bin/find interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aqE $'^/lib\r?$' "$OUT/serial.log"
  grep -aqE $'^/usr\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/ls path=/usr/bin/ls interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aqE $'^basename\r?$' "$OUT/serial.log"
  grep -aqE $'^find\r?$' "$OUT/serial.log"
  grep -aqE $'^ls\r?$' "$OUT/serial.log"
  grep -aqE $'^wc\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/wc path=/usr/bin/wc interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aqE $'^2190608 /usr/lib/x86_64-linux-gnu/libc[.]so[.]6\r?$' "$OUT/serial.log"
  grep -aqE $'^jasper-random-ok bytes=32\r?$' "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=bin/dash path=/bin/dash interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aqE $'^jasper-shell-ok\r?$' "$OUT/serial.log"
  grep -aqE $'^/usr\r?$' "$OUT/serial.log"
  grep -aqE $'^jasper-registry-ok\r?$' "$OUT/serial.log"
  grep -aqE $'^external-ok\r?$' "$OUT/serial.log"
  grep -aqE $'^jasper-orphan-vfork-ok\r?$' "$OUT/serial.log"
  if [ "$MODE" = sandbox-launch ]; then
    grep -aq '^\[JSR-PROD\] first_program state=Some(Exited { code: 0 }) reclaimed=true' "$OUT/serial.log"
    grep -aqE '^\[JSR-SANDBOX-LAUNCH\] started plan=0x[0-9a-f]+ child_handle=0x[0-9a-f]+ workload=0x[0-9a-f]+' "$OUT/serial.log"
    grep -aqE $'^(\\[JSR-USERTEXT\\].*text=)?sandbox-launch: ok sandbox=true image=true device_authority=true data_authority=true net_authority=true plan=true query=true child=true child_exit=0 child_cleanup=true destroy=true cleanup=true\r?$' "$OUT/serial.log"
  fi
  if [ "$MODE" = terminal-session ]; then
    grep -aq '^\[JSR-PROD\] first_program state=Some(Exited { code: 0 }) reclaimed=true' "$OUT/serial.log"
    grep -aqE $'^Jasper-OS native CLI\r?$' "$OUT/serial.log"
    if [ "${ISSUE21_MANUAL_INPUT:-0}" != 1 ]; then
      grep -aqE $'^native-help-ok\r?$' "$OUT/serial.log"
      grep -aqE $'^system-update status=ok command=system[.]update[.]status generation=[1-9][0-9]* transaction=[1-9][0-9]* terminal=(none|complete|rolled_back) active=[AB] state=confirmed release=[1-9][0-9]* .*caller=[1-9][0-9]* domain=1 tenant=[1-9][0-9]* request=[1-9][0-9]*\r?$' "$OUT/serial.log"
      grep -aqE $'^system-update-ok\r?$' "$OUT/serial.log"
      grep -aqE $'^system-update result=ok command=system[.]update[.]recover action=recover generation=[1-9][0-9]* transaction=[1-9][0-9]* recovery_required=false tenant=[1-9][0-9]* request=[1-9][0-9]*\r?$' "$OUT/serial.log"
      grep -aq '^\[JSR-UPDATE-ACTION\].*action=recover result=ok' "$OUT/serial.log"
      grep -aqE $'^system-update result=ok command=system[.]update[.]archive action=archive generation=[1-9][0-9]* transaction=[1-9][0-9]* archived=true tenant=[1-9][0-9]* request=[1-9][0-9]*\r?$' "$OUT/serial.log"
      grep -aq '^\[JSR-UPDATE-ARCHIVE\].*terminal=Complete result=ok' "$OUT/serial.log"
      grep -aqE $'^system-update audit=ok command=system[.]update[.]audit request=[1-9][0-9]* available=true sequence=1 transaction=[1-9][0-9]* terminal=complete\r?$' "$OUT/serial.log"
      grep -aqE $'^\[JSR-UPDATE-AUDIT\].*available=true sequence=1 .*result=ok\r?$' "$OUT/serial.log"
      python3 - "$OUT/serial.log" <<'PY'
import json
import sys

status_records = []
recover_records = []
archive_records = []
audit_records = []
with open(sys.argv[1], "rb") as stream:
    for raw in stream:
        line = raw.rstrip(b"\r\n")
        if line.startswith(b'{"schema":"service.update.status/1"'):
            status_records.append(json.loads(line))
        if line.startswith(b'{"schema":"service.update.action/1"'):
            record = json.loads(line)
            if record["command"] == "system.update.recover":
                recover_records.append(record)
            elif record["command"] == "system.update.archive":
                archive_records.append(record)
        if line.startswith(b'{"schema":"service.update.audit/1"'):
            audit_records.append(json.loads(line))

assert status_records, "missing structured update status"
record = status_records[-1]
assert record["schema"] == "service.update.status/1"
assert record["command"] == "system.update.status"
assert record["status"] == "ok"
assert record["generation"] > 0
assert record["transaction"] > 0
assert record["active"]["slot"] in ("A", "B")
assert record["active"]["state"] == "confirmed"
assert len(record["active"]["digest"]) == 64
assert record["caller"]["subject"] > 0
assert record["caller"]["domain"] == 1
assert record["caller"]["tenant"] > 0
assert record["request"] > 0
assert recover_records, "missing structured recovery action"
action = recover_records[-1]
assert action["schema"] == "service.update.action/1"
assert action["command"] == "system.update.recover"
assert action["status"] == "ok"
assert action["action"] == "recover"
assert action["generation"] == record["generation"]
assert action["transaction"] == record["transaction"]
assert action["digest"] == (
    record["candidate"]["digest"]
    if record["candidate"] is not None
    else record["active"]["digest"]
)
assert action["recovery_required"] is False
assert action["archived"] is False
assert action["caller"]["tenant"] > 0
assert action["caller"]["domain"] == 1
assert action["request"] > 0
assert archive_records, "missing structured archive action"
archive = archive_records[-1]
assert archive["command"] == "system.update.archive"
assert archive["action"] == "archive"
assert archive["generation"] == record["generation"]
assert archive["transaction"] == record["transaction"]
assert archive["digest"] == record["transaction_digest"]
assert archive["archived"] is True
assert audit_records, "missing structured update audit"
audit = audit_records[-1]
assert audit["schema"] == "service.update.audit/1"
assert audit["command"] == "system.update.audit"
assert audit["available"] is True
assert audit["sequence"] == 1
assert audit["transaction"] == archive["transaction"]
assert audit["digest"] == archive["digest"]
assert audit["terminal"] == "complete"
PY
      grep -aqE $'^\{"schema":"jucs.command/1","id":"system.update.status","version":1,"effects":"read","arguments":\[\],"options":\["--help","--schema","--json"\],"service":"service.update.status","service_version":1\}\r?$' "$OUT/serial.log"
      grep -aqE $'^system update status \[\-\-help\|--schema\|--json\]\r?$' "$OUT/serial.log"
      grep -aqE $'^\{"schema":"jucs.command/1","id":"system.update.recover","version":1,"effects":"write","arguments":\[\],"options":\["--help","--schema","--json"\],"service":"service.update.recover","service_version":1\}\r?$' "$OUT/serial.log"
      grep -aqE $'^system update recover \[\-\-help\|--schema\|--json\]\r?$' "$OUT/serial.log"
      grep -aqE $'^\{"schema":"jucs.command/1","id":"system.update.archive","version":1,"effects":"write","arguments":\[\],"options":\["--help","--schema","--json"\],"service":"service.update.archive","service_version":1\}\r?$' "$OUT/serial.log"
      grep -aqE $'^system update archive \[\-\-help\|--schema\|--json\]\r?$' "$OUT/serial.log"
      grep -aqE $'^\{"schema":"jucs.command/1","id":"system.update.audit","version":1,"effects":"read","arguments":\[\],"options":\["--help","--schema","--json"\],"service":"service.update.audit","service_version":1\}\r?$' "$OUT/serial.log"
      grep -aqE $'^system update audit \[\-\-help\|--schema\|--json\]\r?$' "$OUT/serial.log"
      [ "$(grep -acE $'^native-echo=history\r?$' "$OUT/serial.log")" -ge 2 ]
      grep -aqE $'^\^C\r?$' "$OUT/serial.log"
    fi
    grep -aqE $'^native-echo-ok\r?$' "$OUT/serial.log"
    grep -aqE $'^native-bye\r?$' "$OUT/serial.log"
  fi
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/printf path=/usr/bin/printf interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/jasper-signal-basic path=/usr/bin/jasper-signal-basic interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
    "$OUT/serial.log"
  grep -aq '^jasper-signal-ok' "$OUT/serial.log"
  if [ "$MODE" != terminal-session ]; then
    grep -aq '^\[JSR-LIFE-ROOT-DYNAMIC\] program=usr/bin/jasper-getppid path=/usr/bin/jasper-getppid interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true interpreter_syscalls=true syscalls=[1-9][0-9]* exit_zero=true frames_before=[0-9]* resources=true' \
      "$OUT/serial.log"
    grep -aqE $'^jasper-ppid=0 lseek=[1-9][0-9]* affinity=[1-9][0-9]* cpu=[0-9][0-9]* node=0 uptime=[0-9][0-9]* totalram=[1-9][0-9]* freeram=[1-9][0-9]* procs=[1-9][0-9]* exe=/usr/bin/jasper-getppid resolution_ns=[1-9][0-9]* sleep_ns=[1-9][0-9]* wall=[1-9][0-9]* dirent=6 exec_meta=true fork=true\r?$' "$OUT/serial.log"
    exec_before_pid=$(grep -aoE '^jasper-exec-before pid=[0-9]+ ppid=0' "$OUT/serial.log" | tail -n 1 | sed -E 's/.*pid=([0-9]+).*/\1/')
    exec_child_pid=$(grep -aoE '^jasper-exec-child pid=[0-9]+ ppid=0' "$OUT/serial.log" | tail -n 1 | sed -E 's/.*pid=([0-9]+).*/\1/')
    [ -n "$exec_before_pid" ]
    [ "$exec_before_pid" = "$exec_child_pid" ]
  fi
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
run_lifecycle jasper-control-inspect \
  "$IMAGE" 38654705664 >"$OUT/control-postboot.log" 2>&1
grep -q 'generation=3 ' "$OUT/control-postboot.log"
grep -q 'slot=A state=Confirmed generation=3 release=1 attempts=0' \
  "$OUT/control-postboot.log"

echo "issue21-uefi-boot: PASS qemu_rc=$rc evidence=$OUT"
