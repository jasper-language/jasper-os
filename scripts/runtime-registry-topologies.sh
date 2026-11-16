#!/usr/bin/env bash
# Verify HC-20/HC-21 registry admission on two runtime memory topologies.
# 使用同一内核镜像，在两个真实内存拓扑上验收 HC-20/HC-21 注册表准入。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${RUNTIME_REGISTRY_OUT:-$ROOT/evidence/runtime-registry-topologies-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${RUNTIME_REGISTRY_TARGET:-$ROOT/target/runtime-registry-topologies}"
IMAGE="$OUT/kernel.img"
ELF="$TARGET/x86_64-unknown-none/release/jasper-kernel"
MEMORY_MIB="${RUNTIME_REGISTRY_MEMORY_MIB:-32 128}"
TIMEOUT_SECS="${RUNTIME_REGISTRY_TIMEOUT:-180}"
CPUS="${RUNTIME_REGISTRY_CPUS:-4-7}"
SMP="${RUNTIME_REGISTRY_SMP:-1}"
ACCEL="${RUNTIME_REGISTRY_ACCEL:-kvm}"
CPU_MODEL="${RUNTIME_REGISTRY_CPU:-host}"

mkdir -p "$OUT" "$TARGET"

runtime_active() {
    local comm
    for comm in /proc/[0-9]*/comm; do
        [ -r "$comm" ] || continue
        IFS= read -r name <"$comm" 2>/dev/null || continue
        case "$name" in
            qemu-system*|VBoxHeadless) return 0 ;;
        esac
    done
    return 1
}

if runtime_active; then
    echo "runtime-registry: another QEMU/VBox workload is running" >&2
    exit 75
fi

available_kib=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
[ "${available_kib:-0}" -ge 4194304 ] || {
    echo "runtime-registry: less than 4 GiB host memory available" >&2
    exit 75
}
disk_kib=$(df -Pk "$OUT" | awk 'NR == 2 { print $4 }')
[ "${disk_kib:-0}" -ge 12582912 ] || {
    echo "runtime-registry: less than 12 GiB workspace space available" >&2
    exit 75
}
load1=$(awk '{ print $1 }' /proc/loadavg)
awk -v load="$load1" 'BEGIN { exit !(load <= 8.0) }' || {
    echo "runtime-registry: host one-minute load $load1 is too high" >&2
    exit 75
}

case "$ACCEL" in
    kvm)
        [ -r /dev/kvm ] && [ -w /dev/kvm ] || {
            echo "runtime-registry: KVM is unavailable; use RUNTIME_REGISTRY_ACCEL=tcg for deterministic-only evidence" >&2
            exit 75
        }
        ;;
    tcg) ;;
    *)
        echo "runtime-registry: unknown accelerator $ACCEL" >&2
        exit 2
        ;;
esac

env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" \
    build --locked --release --target-dir "$TARGET" -p xtask \
    >"$OUT/xtask-build.log" 2>&1
env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" \
    build --locked --release --target-dir "$TARGET" \
    --target x86_64-unknown-none -p jasper-kernel --no-default-features \
    --features runtime-registry-topology-verify \
    >"$OUT/kernel-build.log" 2>&1
"$TARGET/release/xtask" "$ELF" "$IMAGE" >"$OUT/image.log" 2>&1
test -s "$IMAGE"
sha256sum "$ELF" "$IMAGE" >"$OUT/artifacts.sha256"

exec 9>/tmp/jasper-os-qemu.lock
if ! flock -w 900 9; then
    echo "runtime-registry: Jasper QEMU lock busy for 900s" >&2
    exit 75
fi

printf 'memory_mib\timage_sha256\tworkloads\tmembers\ttasks\tsandboxes\timages\tlayers\tvolumes\tbudget\n' \
    >"$OUT/topologies.tsv"

for memory_mib in $MEMORY_MIB; do
    case "$memory_mib" in
        ''|*[!0-9]*|0)
            echo "runtime-registry: invalid memory topology: $memory_mib" >&2
            exit 2
            ;;
    esac

    run_dir="$OUT/${memory_mib}M"
    serial="$run_dir/serial.log"
    mkdir -p "$run_dir"

    set +e
    nice -n 19 taskset -c "$CPUS" \
        timeout --signal=TERM --kill-after=10s "$TIMEOUT_SECS" \
        qemu-system-x86_64 \
            -accel "$ACCEL" -cpu "$CPU_MODEL" \
            -m "${memory_mib}M" -smp "$SMP" \
            -drive format=raw,file="$IMAGE",snapshot=on \
            -serial "file:$serial" \
            -display none -monitor none -no-reboot \
            -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
            >"$run_dir/qemu.log" 2>&1
    rc=$?
    set -e
    printf '%s\n' "$rc" >"$run_dir/qemu.rc"

    case "$rc" in
        33|37) ;;
        *)
            echo "runtime-registry: ${memory_mib}M QEMU rc=$rc (expected 33 or 37)" >&2
            exit 1
            ;;
    esac
    grep -aqE '^\[JSR-EXIT\] (success|timing-only)' "$serial"
    ! grep -aqE '^\[JSR-(PANIC|.*-FAIL)\]|KERNEL PANIC|panicked at' "$serial"
    grep -aqE '^\[JSR-WORKLOAD\] capacity workloads=[1-9][0-9]* members=[1-9][0-9]* tasks=[1-9][0-9]* budget=[1-9][0-9]* dynamic=true$' "$serial"
    grep -aqE '^\[JSR-SANDBOX\] capacity sandboxes=[1-9][0-9]* workloads=[1-9][0-9]* budget=[1-9][0-9]* dynamic=true$' "$serial"
    grep -aqE '^\[JSR-SANDBOX-STORAGE\] capacity images=[1-9][0-9]* layers=[1-9][0-9]* volumes=[1-9][0-9]* sandboxes=[1-9][0-9]* budget=[1-9][0-9]* dynamic=true$' "$serial"

    workload_line=$(grep -aE '^\[JSR-WORKLOAD\] capacity ' "$serial" | head -1)
    sandbox_line=$(grep -aE '^\[JSR-SANDBOX\] capacity ' "$serial" | head -1)
    storage_line=$(grep -aE '^\[JSR-SANDBOX-STORAGE\] capacity ' "$serial" | head -1)

    field() {
        local name="$1"
        shift
        printf '%s\n' "$@" |
            awk -v key="$name" '{
                for (i = 1; i <= NF; i++) {
                    if (index($i, key "=") == 1) {
                        split($i, pair, "=")
                        print pair[2]
                        exit
                    }
                }
            }'
    }

    workloads=$(field workloads "$workload_line")
    members=$(field members "$workload_line")
    tasks=$(field tasks "$workload_line")
    workload_budget=$(field budget "$workload_line")
    sandboxes=$(field sandboxes "$sandbox_line")
    images=$(field images "$storage_line")
    layers=$(field layers "$storage_line")
    volumes=$(field volumes "$storage_line")
    storage_budget=$(field budget "$storage_line")
    [ "$workload_budget" = "$storage_budget" ]

    image_sha=$(sha256sum "$IMAGE" | awk '{ print $1 }')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$memory_mib" "$image_sha" "$workloads" "$members" "$tasks" \
        "$sandboxes" "$images" "$layers" "$volumes" "$workload_budget" \
        >>"$OUT/topologies.tsv"
done

awk -F '\t' '
    NR == 2 {
        first_budget = $10
        first_facts = $3 FS $4 FS $5 FS $6 FS $7 FS $8 FS $9
    }
    NR > 2 && $10 != first_budget {
        distinct_budget = 1
    }
    NR > 2 && ($3 FS $4 FS $5 FS $6 FS $7 FS $8 FS $9) != first_facts {
        distinct_facts = 1
    }
    END {
        if (NR < 3) {
            print "runtime-registry: at least two memory topologies are required" > "/dev/stderr"
            exit 1
        }
        if (!distinct_budget) {
            print "runtime-registry: heap budgets did not change across topologies" > "/dev/stderr"
            exit 1
        }
        if (!distinct_facts) {
            print "runtime-registry: registry capacities did not change; the policy ceiling was not exercised by any topology" > "/dev/stderr"
            exit 1
        }
    }
' "$OUT/topologies.tsv"

echo "runtime-registry: PASS evidence=$OUT"
