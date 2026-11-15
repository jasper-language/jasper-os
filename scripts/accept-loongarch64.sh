#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
: "${JASPER_CORES:=4-11}"
: "${JASPER_SMP:=4}"
: "${JASPER_QEMU_TIMEOUT:=300}"
: "${JASPER_MEMORY_MIB:=128 256}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target-loongarch}"
OUT="$ROOT/evidence/accept-loongarch64-$(date '+%Y%m%d-%H%M%S')"
KERNEL="$TARGET_DIR/loongarch64-unknown-none-softfloat/release/jasper-kernel"
QEMU="${JASPER_QEMU:-qemu-system-loongarch64}"

mkdir -p "$OUT"
cd "$ROOT"

{
    echo "time=$(date --iso-8601=seconds)"
    echo "target=loongarch64-unknown-none-softfloat"
    echo "smp=$JASPER_SMP"
    echo "memory_mib=$JASPER_MEMORY_MIB"
    echo "cpu_affinity=$JASPER_CORES"
    "$QEMU" --version | head -1
    rustc -Vv
} > "$OUT/environment.txt"

CARGO_TARGET_DIR="$TARGET_DIR" \
    cargo build -p jasper-kernel \
        --target loongarch64-unknown-none-softfloat \
        --no-default-features --release 2>&1 | tee "$OUT/build.log"

readelf -h "$KERNEL" | grep -E 'Class:|Machine:|Entry point' | tee "$OUT/elf.txt"

MEMORY_FACTS=""
for memory_mib in $JASPER_MEMORY_MIB; do
    case "$memory_mib" in
        ''|*[!0-9]*)
            echo "invalid JASPER_MEMORY_MIB entry: $memory_mib" >&2
            exit 2
            ;;
    esac
    RUN="$OUT/${memory_mib}M"
    mkdir -p "$RUN"

    exec 9>/tmp/jasper-os-qemu.lock
    flock 9
    taskset -c "$JASPER_CORES" \
        "$QEMU" -M virt -cpu la464 -smp "$JASPER_SMP" -m "${memory_mib}M" \
        -kernel "$KERNEL" -serial file:"$RUN/serial.log" \
        -display none -monitor none -no-reboot \
        >"$RUN/qemu.stdout" 2>"$RUN/qemu.stderr" &
    QPID=$!

    deadline=$((SECONDS + JASPER_QEMU_TIMEOUT))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if grep -a -q '^\[JSR-EXIT-CODE\] code=33' "$RUN/serial.log" 2>/dev/null; then
            break
        fi
        if ! kill -0 "$QPID" 2>/dev/null; then
            break
        fi
        sleep 0.25
    done

    set +e
    kill -TERM "$QPID" 2>/dev/null
    wait "$QPID"
    RC=$?
    set -e
    flock -u 9
    exec 9>&-

    grep -a -q '^\[JSR-BOOT\].*loongarch64' "$RUN/serial.log"
    grep -a -q '^\[JSR-VEC\] ok' "$RUN/serial.log"
    grep -a -q '^\[JSR-TICK\] n=25' "$RUN/serial.log"
    grep -a -q '^\[JSR-EXIT\] success' "$RUN/serial.log"
    if [ "$JASPER_SMP" -gt 1 ]; then
        grep -a -q "present=$JASPER_SMP online=$JASPER_SMP failed=0" "$RUN/serial.log"
    fi
    grep -a -q '^\[JSR-EXIT-CODE\] code=33' "$RUN/serial.log"
    grep -a -E '^\[JSR-FRAME\].*usable_mib=[0-9]+' "$RUN/serial.log" | tee "$RUN/memory.txt"
    usable_mib="$(sed -n 's/^\[JSR-FRAME\].*usable_mib=\([0-9][0-9]*\).*/\1/p' "$RUN/memory.txt")"
    test -n "$usable_mib"
    MEMORY_FACTS="${MEMORY_FACTS}${memory_mib}:${usable_mib} "
    echo "qemu_memory_mib=$memory_mib" > "$RUN/summary.txt"
    echo "usable_mib=$usable_mib" >> "$RUN/summary.txt"
    echo "qemu_terminated_rc=$RC" >> "$RUN/summary.txt"
done

requested_topologies="$(printf '%s\n' $JASPER_MEMORY_MIB | sort -nu | wc -l)"
distinct_facts="$(printf '%s\n' $MEMORY_FACTS | awk -F: '{print $2}' | sort -nu | wc -l)"
if [ "$requested_topologies" -ne "$distinct_facts" ]; then
    echo "LoongArch memory discovery produced identical facts for distinct topologies" >&2
    exit 1
fi
printf '%s\n' $MEMORY_FACTS | awk -F: '
    NR > 1 && $1 <= previous_size { exit 1 }
    { previous_size = $1 }
' || {
    echo "JASPER_MEMORY_MIB must be provided in strictly increasing order" >&2
    exit 2
}

echo "accept-loongarch64: PASS"
echo "evidence: $OUT"
