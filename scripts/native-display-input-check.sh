#!/usr/bin/env bash
# Verify the native framebuffer, a committed first frame, and a real QEMU PS/2
# key transition without depending on the Linux compatibility rootfs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${NATIVE_DISPLAY_GUARDED:-0}" != 1 ]; then
  exec taskset -c "${NATIVE_DISPLAY_CPUS:-4-5}" \
    flock -w 900 "/tmp/jasper-os-cargo-$(id -u).lock" \
    env NATIVE_DISPLAY_GUARDED=1 bash "$ROOT/scripts/native-display-input-check.sh" "$@"
fi

OUT="${NATIVE_DISPLAY_OUT:-$ROOT/evidence/native-display-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${NATIVE_DISPLAY_TARGET:-$ROOT/target/native-display-qemu}"
TIMEOUT_SECONDS="${NATIVE_DISPLAY_TIMEOUT:-60}"
SOCKET="$OUT/monitor.sock"
IMAGE="$TARGET/jasper-display.img"
KERNEL="$TARGET/x86_64-unknown-none/release/jasper-kernel"
XTASK="$ROOT/target/release/xtask"
mkdir -p "$OUT" "$TARGET"
rm -f -- "$SOCKET" "$IMAGE" "$OUT/frame-before.ppm" "$OUT/frame-after.ppm"

export PATH="${HOME}/.cargo/bin:${PATH}"
CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS=2 \
  cargo build --locked --release --target x86_64-unknown-none \
  -p jasper-kernel --features production >"$OUT/kernel-build.log" 2>&1
env -u CARGO_TARGET_DIR CARGO_BUILD_JOBS=2 \
  cargo build --locked --release -p xtask >"$OUT/xtask-build.log" 2>&1
"$XTASK" "$KERNEL" "$IMAGE" >"$OUT/image.log" 2>&1

exec 9>"/tmp/jasper-os-qemu.lock"
if ! flock -n 9; then
  echo "native-display-input: another Jasper-OS QEMU owns /tmp/jasper-os-qemu.lock" >&2
  exit 75
fi
if pgrep -f '^qemu-system-x86_64 |^timeout [0-9]+ qemu-system-x86_64 ' >/dev/null; then
  echo "native-display-input: another QEMU is already running" >&2
  exit 75
fi

timeout "$TIMEOUT_SECONDS" qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -m 512M \
  -smp 1 \
  -drive "format=raw,file=$IMAGE" \
  -serial "file:$OUT/serial.log" \
  -display none \
  -monitor "unix:$SOCKET,server=on,wait=off" \
  -no-reboot \
  -cpu max &
runner=$!
cleanup() {
  if kill -0 "$runner" 2>/dev/null; then
    kill "$runner" 2>/dev/null || true
    wait "$runner" 2>/dev/null || true
  fi
}
trap cleanup EXIT

for _ in $(seq 1 "$TIMEOUT_SECONDS"); do
  [ -S "$SOCKET" ] && break
  sleep 1
done
[ -S "$SOCKET" ]

for _ in $(seq 1 "$TIMEOUT_SECONDS"); do
  grep -aq '^\[JSR-DISPLAY\] backend=framebuffer keyboard=true ' "$OUT/serial.log" 2>/dev/null && break
  sleep 1
done
grep -aq '^\[JSR-DISPLAY\] backend=framebuffer keyboard=true ' "$OUT/serial.log"

printf 'screendump %s\n' "$OUT/frame-before.ppm" |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-before.log" 2>&1
printf 'sendkey a 500\n' |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-key.log" 2>&1
sleep 1
printf 'screendump %s\n' "$OUT/frame-after.ppm" |
  timeout 10 socat - "UNIX-CONNECT:$SOCKET" >"$OUT/monitor-after.log" 2>&1

for _ in $(seq 1 30); do
  grep -aq '^\[JSR-DISPLAY\].*pressed=[1-9][0-9]* ' "$OUT/serial.log" && break
  sleep 1
done
grep -aq '^\[JSR-DISPLAY\].*pressed=[1-9][0-9]* ' "$OUT/serial.log"
test -s "$OUT/frame-before.ppm"
test -s "$OUT/frame-after.ppm"

kill "$runner" 2>/dev/null || true
wait "$runner" 2>/dev/null || true
trap - EXIT
printf 'native-display-input: PASS evidence=%s\n' "$OUT"
