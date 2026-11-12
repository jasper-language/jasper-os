#!/usr/bin/env bash
# Real CPL3 Linux file/console I/O under a Workload budget, twice.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${WORKLOAD_IO_OUT:-$ROOT/evidence/workload-io-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${WORKLOAD_IO_TARGET:-$ROOT/target/workload-io}"
IMAGE="$OUT/workload-io.img"
LIMIT="${WORKLOAD_IO_QEMU_TIMEOUT:-180}"
QEMU_CPUS="${WORKLOAD_IO_QEMU_CPUS:-0-1}"
case "$LIMIT" in
    ''|0|*[!0-9]*)
        echo "workload-io: WORKLOAD_IO_QEMU_TIMEOUT must be a positive integer" >&2
        exit 2
        ;;
esac

# Serialize the entire build-and-run sequence with other Jasper QEMU users.
exec 9>/tmp/jasper-os-qemu.lock
if ! flock -n 9; then
    echo "workload-io: another Jasper QEMU workflow holds the global lock" >&2
    exit 75
fi
runtime_active() {
    local comm
    for comm in /proc/[0-9]*/comm; do
        IFS= read -r name <"$comm" 2>/dev/null || continue
        case "$name" in
            qemu-system*|VBoxHeadless) return 0 ;;
        esac
    done
    return 1
}
if runtime_active; then
    echo "workload-io: another QEMU/VBox workload is already running" >&2
    exit 75
fi

mkdir -p "$OUT"
available_kib=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
[ "${available_kib:-0}" -ge 2097152 ] || {
    echo "workload-io: less than 2 GiB host memory is available" >&2
    exit 75
}
free_kib=$(df -Pk "$OUT" | awk 'NR == 2 { print $4 }')
[ "${free_kib:-0}" -ge 12582912 ] || {
    echo "workload-io: less than 12 GiB workspace space is available" >&2
    exit 75
}
load1=$(awk '{ print $1 }' /proc/loadavg)
awk -v load="$load1" 'BEGIN { exit !(load <= 8.0) }' || {
    echo "workload-io: host one-minute load $load1 is too high" >&2
    exit 75
}

env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" \
    build --locked --release --target-dir "$TARGET" -p xtask \
    >"$OUT/build.log" 2>&1
env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" \
    build --locked --release --target-dir "$TARGET" \
    --target x86_64-unknown-none -p jasper-kernel --no-default-features \
    --features workload-io-verify \
    >>"$OUT/build.log" 2>&1

"$TARGET/release/xtask" \
    "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$IMAGE" \
    >"$OUT/image.log" 2>&1
sha256sum "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$IMAGE" \
    >"$OUT/artifacts.sha256"

for round in 1 2; do
    serial="$OUT/round-$round.serial"
    qemu_log="$OUT/round-$round.qemu.log"
    qemu_pid_file="$OUT/round-$round.qemu.pid"
    rm -f -- "$qemu_pid_file"
    set +e
    nice -n 15 taskset -c "$QEMU_CPUS" \
        timeout --signal=TERM --kill-after=10s "$LIMIT" \
        sh -c '
            pid_file=$1
            shift
            printf "%s\n" "$$" >"$pid_file"
            exec qemu-system-x86_64 "$@"
        ' workload-io-qemu "$qemu_pid_file" \
            -accel tcg -icount shift=5 \
            -drive format=raw,file="$IMAGE" \
            -smp 1 -m 512M -serial "file:$serial" \
            -display none -monitor none -no-reboot \
            -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
            </dev/null >"$qemu_log" 2>&1
    rc=$?
    set -e
    if [ -s "$qemu_pid_file" ]; then
        qemu_pid=$(cat "$qemu_pid_file")
        if kill -0 "$qemu_pid" 2>/dev/null \
            && grep -aFq -- "$IMAGE" "/proc/$qemu_pid/cmdline" 2>/dev/null; then
            kill -TERM "$qemu_pid" 2>/dev/null || true
            for _ in $(seq 1 20); do
                kill -0 "$qemu_pid" 2>/dev/null || break
                sleep 0.5
            done
            if kill -0 "$qemu_pid" 2>/dev/null; then
                kill -KILL "$qemu_pid" 2>/dev/null || true
            fi
        fi
    fi
    printf '%s\n' "$rc" >"$OUT/round-$round.rc"
    [ "$rc" -eq 33 ] || {
        echo "workload-io: round $round QEMU rc=$rc, expected 33" >&2
        tail -n 60 "$serial" >&2
        tail -n 20 "$qemu_log" >&2
        exit 1
    }
    grep -aq '^\[JSR-WORKLOAD\] runtime=true checks_failed=0 ' "$serial" || {
        echo "workload-io: round $round lacks Workload runtime success" >&2
        exit 1
    }
    grep -aq '^\[JSR-WORKLOAD-IO\] runtime=true file_read=true console_write=true quota_rejected=true rollback=true .* failed=0' "$serial" || {
        echo "workload-io: round $round lacks Linux I/O success evidence" >&2
        exit 1
    }
    grep -aq '^JQ' "$serial" && grep -aq '^x\[JSR-LINUX-SYSCALL\]' "$serial" || {
        echo "workload-io: round $round lacks the two real console writes" >&2
        exit 1
    }
    if grep -aqE '^\[JSR-(PANIC|WORKLOAD-IO-FAIL|LINUX-ABI-FAIL)\]|KERNEL PANIC|panicked at' "$serial"; then
        echo "workload-io: round $round contains a failure marker" >&2
        exit 1
    fi
done

echo "workload-io: PASS rounds=2 evidence=$OUT"
