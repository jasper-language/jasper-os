#!/usr/bin/env bash
# Launch the real Jasper-OS UI Service in CPL3 and verify fail-closed engine
# reporting, Channel delivery, real PS/2 Enter routing, Console liveness and reclaim.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.cargo/bin:$PATH"

OUT="${UI_PROCESS_OUT:-$ROOT/evidence/ui-process-$(date '+%Y%m%d-%H%M%S')}"
LIMIT="${UI_PROCESS_TIMEOUT:-180}"
QEMU_CPUS="${UI_PROCESS_QEMU_CPUS:-6-7}"
mkdir -p "$OUT"
command -v socat >/dev/null || {
  echo "ui-process: socat is required to inject the QEMU PS/2 key" >&2
  exit 69
}

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
exec 8>/tmp/jasper-os-qemu.lock
if ! flock -w 900 8; then
  rc=75
else
  monitor="/tmp/jasper-ui-monitor-$$.sock"
  nice -n 10 taskset -c "$QEMU_CPUS" timeout "$LIMIT" \
  qemu-system-x86_64 \
  -accel tcg -icount shift=5 \
  -drive format=raw,file="$OUT/kernel.img" \
  -smp 2 -m 512M \
  -serial "file:$OUT/serial.log" -display none \
  -monitor "unix:$monitor,server=on,wait=off" -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  >"$OUT/qemu.log" 2>&1 &
  qemu_pid=$!
  remaining=$((LIMIT * 10))
  sent=0
  while [ "$remaining" -gt 0 ] && kill -0 "$qemu_pid" 2>/dev/null; do
    waits=$(grep -acF 'waiting_real_key=true' "$OUT/serial.log" 2>/dev/null || true)
    while [ "$sent" -lt "${waits:-0}" ]; do
      printf 'sendkey ret\n' | timeout 5 socat - "UNIX-CONNECT:$monitor" >/dev/null 2>&1 || break
      sent=$((sent + 1))
    done
    sleep 0.1
    remaining=$((remaining - 1))
  done
  wait "$qemu_pid"
  rc=$?
fi
set -e
printf '%s\n' "$rc" >"$OUT/qemu_rc.txt"

test "$rc" = 33
grep -aFq '[JSR-UI-PROCESS] waiting_real_key=true native_enter=0x0103' "$OUT/serial.log"
grep -aFq '[JSR-UI-PROCESS] native_keyboard=true native_code=0x0103 jsui_code=28' "$OUT/serial.log"
grep -aFq 'ui-service: ready protocol=1 engine=cpu-ready' "$OUT/serial.log"
grep -aFq 'ui-service: presented 64x64 bytes=16384 sequence=1' "$OUT/serial.log"
grep -aFq 'ui-service: patch accepted revision=2 presents=2' "$OUT/serial.log"
grep -aFq 'ui-service: input accepted code=28 presents=3' "$OUT/serial.log"
grep -aFq 'ui-service: closed presents=3' "$OUT/serial.log"
grep -aFq '[JSR-UI-SESSION] round=0 started=true channel=true request_queued=true engine=cpu rendered=true present=true patch=true input=true native_keyboard=true frames=3 display=true exit=0 response=true terminal_alive=true resources=true' "$OUT/serial.log"
grep -aFq '[JSR-UI-SESSION] round=1 started=true channel=true request_queued=true engine=cpu rendered=true present=true patch=true input=true native_keyboard=true frames=3 display=true exit=0 response=true terminal_alive=true resources=true' "$OUT/serial.log"
grep -aFq 'remote_channel=true session_key=true scope=true recovered=true scene=true focus=true input_capability=true replay_rejected=true failed=0' "$OUT/serial.log"
grep -aFq '[JSR-UI-PROCESS] rounds=2 started=true channel=true request_queued=true engine=cpu rendered=true present=true patch=true input=true native_keyboard=true frames=6 display=true exit=0 response=true terminal_alive=true restart=true resources=true' "$OUT/serial.log"
grep -aFq '[JSR-DISPLAY-UI] presented=true' "$OUT/serial.log"
! grep -aEq 'panicked|JSR-PANIC|JSR-UI-PROCESS-FAIL' "$OUT/serial.log"
printf 'PASS\n' >"$OUT/PASS"

printf '%s\n' \
  "ui-process: PASS cpl3=true channel=true jsui=true engine=cpu rendered=true present=true patch=true input=true native_keyboard=true frames=6 display=true exit=0 terminal=true restart=true resources=true" \
  "engine_commit=8adb6d4432c8385250192304eef04a07b22594d2" \
  "qemu_rc=$rc" \
  "evidence=$OUT"
