#!/usr/bin/env bash
# Serialize resource-heavy Jasper builds across parallel agent worktrees.
#
# 并行 Agent 可以同时编辑独立 worktree，但 Cargo 构建共享宿主资源，
# 因此必须排队，并固定在预留 CPU、低优先级和有限 job 数下运行。
set -eu

cargo_bin=${CARGO_BIN:-/home/auth/.cargo/bin/cargo}
build_cpus=${JASPER_BUILD_CPUS:-4-5}
build_jobs=${JASPER_CARGO_JOBS:-2}
minimum_available_kib=${JASPER_BUILD_MIN_AVAILABLE_GIB:-12884902}
minimum_disk_kib=${JASPER_BUILD_MIN_DISK_GIB:-12582912}
lock_path=${JASPER_BUILD_LOCK:-/tmp/jasper-os-cargo-$(id -u).lock}

if [ ! -x "$cargo_bin" ]; then
    echo "guarded-cargo: cargo not executable: $cargo_bin" >&2
    exit 69
fi
for tool in flock awk df taskset nice timeout pgrep; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "guarded-cargo: required tool missing: $tool" >&2
        exit 69
    fi
done

# Agent builds queue rather than stacking. A stale waiter gives up with the
# same host-gate status used by the QEMU verifier.
exec 9>"$lock_path"
if ! flock -w 900 9; then
    echo "guarded-cargo: build lock busy for 900s" >&2
    exit 75
fi

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
    echo "guarded-cargo: VM/QEMU is running; refusing to stack a host build" >&2
    exit 75
fi

available_kib=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
disk_kib=$(df -Pk . | awk 'NR == 2 { print $4 }')
if [ "${available_kib:-0}" -lt "$minimum_available_kib" ]; then
    echo "guarded-cargo: insufficient memory (${available_kib} KiB available)" >&2
    exit 75
fi
if [ "${disk_kib:-0}" -lt "$minimum_disk_kib" ]; then
    echo "guarded-cargo: insufficient disk (${disk_kib} KiB available)" >&2
    exit 75
fi

echo "guarded-cargo: cpus=$build_cpus jobs=$build_jobs mem=${available_kib}KiB disk=${disk_kib}KiB" >&2
exec env CARGO_BUILD_JOBS="$build_jobs" \
    taskset -c "$build_cpus" \
    nice -n 10 \
    timeout 1800 \
    "$cargo_bin" "$@"
