#!/usr/bin/env bash
# Verify that the native CLI prompt, typed command and output are visible in
# the framebuffer after real PS/2 input reaches the terminal session.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${GRAPHICAL_TERMINAL_GUARDED:-0}" != 1 ]; then
  exec taskset -c "${GRAPHICAL_TERMINAL_CPUS:-4-5}" \
    flock -w 900 "/tmp/jasper-os-cargo-$(id -u).lock" \
    env GRAPHICAL_TERMINAL_GUARDED=1 bash "$ROOT/scripts/graphical-terminal-check.sh" "$@"
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

bash -x "$ROOT/scripts/issue21-uefi-boot-check.sh" >"$OUT/runner.log" 2>&1 &
runner=$!
cleanup() {
  if kill -0 "$runner" 2>/dev/null; then
    kill "$runner" 2>/dev/null || true
    wait "$runner" 2>/dev/null || true
  fi
}
trap cleanup EXIT

for _ in $(seq 1 180); do
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

for _ in $(seq 1 180); do
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
  'sendkey e 30' 'sendkey c 30' 'sendkey h 30' 'sendkey o 30' \
  'sendkey spc 30' 'sendkey h 30' 'sendkey e 30' 'sendkey l 30' \
  'sendkey l 30' 'sendkey o 30' 'sendkey ret 30' |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-command.log" 2>&1

for _ in $(seq 1 120); do
  grep -aq '^\[JSR-GTERM\] output=echo-ok visible=true' "$OUT/serial.log" 2>/dev/null && break
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
grep -aq '^\[JSR-GTERM\] output=echo-ok visible=true' "$OUT/serial.log"

printf 'screendump %s\n' "$OUT/frame-command.ppm" |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-after.log" 2>&1

printf '%s\n' \
  'sendkey e 30' 'sendkey x 30' 'sendkey i 30' 'sendkey t 30' \
  'sendkey ret 30' |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-exit.log" 2>&1

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
