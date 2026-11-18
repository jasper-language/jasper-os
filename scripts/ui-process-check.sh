#!/usr/bin/env bash
# Launch the real Jasper-OS UI Service in CPL3 and verify fail-closed engine
# reporting, Channel delivery, process exit 69, Console liveness and reclaim.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"

OUT="${UI_PROCESS_OUT:-$ROOT/evidence/ui-process-$(date '+%Y%m%d-%H%M%S')}"
LIMIT="${UI_PROCESS_TIMEOUT:-180}"
QEMU_CPUS="${UI_PROCESS_QEMU_CPUS:-6-7}"
mkdir -p "$OUT"

env -u CARGO_TARGET_DIR \
  JASPER_BUILD_ALLOW_VBOX="${JASPER_BUILD_ALLOW_VBOX:-1}" \
  JASPER_BUILD_CPUS="${JASPER_BUILD_CPUS:-4-5}" \
  scripts/guarded-cargo.sh build --locked --release -p xtask \
  >"$OUT/xtask-build.log" 2>&1

env -u CARGO_TARGET_DIR \
  JASPER_BUILD_ALLOW_VBOX="${JASPER_BUILD_ALLOW_VBOX:-1}" \
  JASPER_BUILD_CPUS="${JASPER_BUILD_CPUS:-4-5}" \
  scripts/guarded-cargo.sh build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel \
  --features ui-process-verify \
  >"$OUT/kernel-build.log" 2>&1

target/release/xtask \
  target/x86_64-unknown-none/release/jasper-kernel \
  "$OUT/kernel.img" >"$OUT/image.log" 2>&1
sha256sum \
  target/x86_64-unknown-none/release/jasper-kernel \
  "$OUT/kernel.img" >"$OUT/artifacts.sha256"

set +e
flock -w 900 /tmp/jasper-os-qemu.lock \
  nice -n 10 taskset -c "$QEMU_CPUS" timeout "$LIMIT" \
  qemu-system-x86_64 \
  -accel tcg -icount shift=5 \
  -drive format=raw,file="$OUT/kernel.img" \
  -smp 2 -m 512M \
  -serial stdio -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  >"$OUT/serial.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/qemu_rc.txt"

test "$rc" = 33
grep -aFq 'ui-service: ready protocol=1 engine=blocked-no-std' "$OUT/serial.log"
grep -aFq '[JSR-UI-PROCESS] started=true channel=true request_queued=true blocked=true exit=69 response=true terminal_alive=true resources=true' "$OUT/serial.log"
! grep -aEq 'panicked|JSR-PANIC|JSR-UI-PROCESS-FAIL' "$OUT/serial.log"

printf '%s\n' \
  "ui-process: PASS cpl3=true channel=true jsui=true engine=blocked-no-std exit=69 terminal=true resources=true" \
  "engine_commit=4194117011f13fdc063977683162fd5a145c85d7" \
  "qemu_rc=$rc" \
  "evidence=$OUT"
