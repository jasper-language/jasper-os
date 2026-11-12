#!/usr/bin/env bash
# Verify that the native CLI prompt, typed command and output are visible in
# the framebuffer after real PS/2 input reaches the terminal session.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${GRAPHICAL_TERMINAL_CPUSET:-0}" != 1 ]; then
  exec taskset -c "${GRAPHICAL_TERMINAL_CPUS:-4-5}" \
    env GRAPHICAL_TERMINAL_CPUSET=1 bash "$ROOT/scripts/graphical-terminal-check.sh" "$@"
fi

OUT="${GRAPHICAL_TERMINAL_OUT:-$ROOT/evidence/graphical-terminal-$(date '+%Y%m%d-%H%M%S')}"
SOCKET="$OUT/monitor.sock"
mkdir -p "$OUT"
rm -f -- "$SOCKET"

export ISSUE21_UEFI_MODE=terminal-session
export ISSUE21_UEFI_TIMEOUT="${GRAPHICAL_TERMINAL_TIMEOUT:-150}"
export ISSUE21_UEFI_OUT="$OUT"
export ISSUE21_UEFI_TARGET="${GRAPHICAL_TERMINAL_TARGET:-$ROOT/target/graphical-terminal}"
export ISSUE21_MANUAL_INPUT=1
export ISSUE21_MONITOR_SOCKET="$SOCKET"
export ISSUE21_QEMU_CPUS="${GRAPHICAL_TERMINAL_CPUS:-4-5}"

bash "$ROOT/scripts/issue21-uefi-boot-check.sh" >"$OUT/runner.log" 2>&1 &
runner=$!
cleanup() {
  if kill -0 "$runner" 2>/dev/null; then
    kill "$runner" 2>/dev/null || true
    wait "$runner" 2>/dev/null || true
  fi
}
trap cleanup EXIT

for _ in $(seq 1 480); do
  [ -S "$SOCKET" ] && break
  if ! kill -0 "$runner" 2>/dev/null; then
    set +e
    wait "$runner"
    runner_status=$?
    set -e
    cat "$OUT/runner.log" >&2
    echo "graphical-terminal: runner exited status=$runner_status" >&2
    exit "$runner_status"
  fi
  sleep 1
done
[ -S "$SOCKET" ]

for _ in $(seq 1 240); do
  grep -aq '^jasper> ' "$OUT/serial.log" 2>/dev/null && break
  if ! kill -0 "$runner" 2>/dev/null; then
    set +e
    wait "$runner"
    runner_status=$?
    set -e
    cat "$OUT/runner.log" >&2
    echo "graphical-terminal: runner exited status=$runner_status" >&2
    exit "$runner_status"
  fi
  sleep 1
done
grep -aq '^jasper> ' "$OUT/serial.log"

printf 'screendump %s\n' "$OUT/frame-prompt.ppm" |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-prompt.log" 2>&1

printf '%s\n' \
  'sendkey h 30' 'sendkey e 30' 'sendkey l 30' 'sendkey p 30' \
  'sendkey ret 30' |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-help.log" 2>&1

for _ in $(seq 1 120); do
  grep -aq '^native-help-ok' "$OUT/serial.log" 2>/dev/null && break
  sleep 1
done
grep -aq '^native-help-ok' "$OUT/serial.log"

printf '%s\n' \
  'sendkey e 30' 'sendkey c 30' 'sendkey h 30' 'sendkey o 30' \
  'sendkey spc 30' 'sendkey h 30' 'sendkey i 30' 'sendkey s 30' \
  'sendkey t 30' 'sendkey o 30' 'sendkey r 30' 'sendkey y 30' \
  'sendkey ret 30' |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-command.log" 2>&1

for _ in $(seq 1 120); do
  grep -aqE $'^native-echo=history\r?$' "$OUT/serial.log" 2>/dev/null && break
  if ! kill -0 "$runner" 2>/dev/null; then
    set +e
    wait "$runner"
    runner_status=$?
    set -e
    cat "$OUT/runner.log" >&2
    echo "graphical-terminal: runner exited status=$runner_status" >&2
    exit "$runner_status"
  fi
  sleep 1
done
grep -aqE $'^native-echo=history\r?$' "$OUT/serial.log"

printf '%s\n' 'sendkey up 30' 'sendkey ret 30' |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-history.log" 2>&1
for _ in $(seq 1 120); do
  [ "$(grep -acE $'^native-echo=history\r?$' "$OUT/serial.log" 2>/dev/null)" -ge 2 ] && break
  sleep 1
done
[ "$(grep -acE $'^native-echo=history\r?$' "$OUT/serial.log")" -ge 2 ]

printf '%s\n' \
  'sendkey e 30' 'sendkey c 30' 'sendkey h 30' 'sendkey o 30' \
  'sendkey spc 30' 'sendkey h 30' 'sendkey e 30' 'sendkey l 30' \
  'sendkey l 30' 'sendkey p 30' 'sendkey backspace 30' \
  'sendkey o 30' 'sendkey ret 30' |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-edit.log" 2>&1
for _ in $(seq 1 120); do
  grep -aqE $'^native-echo=hello\r?$' "$OUT/serial.log" 2>/dev/null && break
  sleep 1
done
grep -aqE $'^native-echo=hello\r?$' "$OUT/serial.log"

printf 'screendump %s\n' "$OUT/frame-command.ppm" |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-after.log" 2>&1

printf '%s\n' \
  'sendkey b 30' 'sendkey a 30' 'sendkey d 30' 'sendkey ctrl-c 30' |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-cancel.log" 2>&1
for _ in $(seq 1 120); do
  grep -aqE $'^\^C\r?$' "$OUT/serial.log" 2>/dev/null && break
  sleep 1
done
grep -aqE $'^\^C\r?$' "$OUT/serial.log"

printf '%s\n' 'sendkey ctrl-d 30' |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-eof.log" 2>&1

for _ in $(seq 1 120); do
  grep -aq '^native-bye' "$OUT/serial.log" 2>/dev/null && break
  sleep 1
done
grep -aq '^native-bye' "$OUT/serial.log"

set +e
wait "$runner"
runner_status=$?
set -e
trap - EXIT
[ "$runner_status" -eq 0 ]
test -s "$OUT/frame-prompt.ppm"
test -s "$OUT/frame-command.ppm"
[ "$(sha256sum "$OUT/frame-prompt.ppm" | awk '{print $1}')" != \
  "$(sha256sum "$OUT/frame-command.ppm" | awk '{print $1}')" ]
printf 'graphical-terminal: PASS frames=%s,%s evidence=%s\n' \
  "$OUT/frame-prompt.ppm" "$OUT/frame-command.ppm" "$OUT"
