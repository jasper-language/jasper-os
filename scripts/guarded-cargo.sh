#!/usr/bin/env bash
# Serialize resource-heavy Jasper builds across parallel agent worktrees.
#
# 并行 Agent 可以同时编辑独立 worktree，但 Cargo 构建共享宿主资源，
# 因此必须排队，并固定在预留 CPU、低优先级和有限 job 数下运行。
set -eu

cargo_bin=${CARGO_BIN:-$(command -v cargo 2>/dev/null || true)}
if [ -z "$cargo_bin" ]; then
    cargo_bin="${HOME}/.cargo/bin/cargo"
fi
build_cpus=${JASPER_BUILD_CPUS:-4-5}
build_jobs=${JASPER_CARGO_JOBS:-2}
minimum_available_kib=${JASPER_BUILD_MIN_AVAILABLE_GIB:-12884902}
minimum_disk_kib=${JASPER_BUILD_MIN_DISK_GIB:-12582912}
lock_path=${JASPER_BUILD_LOCK:-/tmp/jasper-os-cargo-$(id -u).lock}
allow_vbox=${JASPER_BUILD_ALLOW_VBOX:-0}
build_affinity=()
affinity_status="$build_cpus"

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
            qemu-system*) return 0 ;;
            VBoxHeadless) [ "$allow_vbox" = 1 ] || return 0 ;;
        esac
    done
    return 1
}
if runtime_active; then
    echo "guarded-cargo: VM/QEMU is running; refusing to stack a host build" >&2
    exit 75
fi

available_kib=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
disk_dir=${CARGO_TARGET_DIR:-.}
case "$disk_dir" in
    /*) ;;
    *) disk_dir="$(pwd)/$disk_dir" ;;
esac
mkdir -p "$disk_dir"
disk_kib=$(df -Pk "$disk_dir" | awk 'NR == 2 { print $4 }')
if [ "${available_kib:-0}" -lt "$minimum_available_kib" ]; then
    echo "guarded-cargo: insufficient memory (${available_kib} KiB available)" >&2
    exit 75
fi
if [ "${disk_kib:-0}" -lt "$minimum_disk_kib" ]; then
    echo "guarded-cargo: insufficient disk (${disk_kib} KiB available)" >&2
    exit 75
fi

if taskset -c "$build_cpus" true 2>/dev/null; then
    build_affinity=(taskset -c "$build_cpus")
else
    affinity_status=scheduler-selected
    echo "guarded-cargo: affinity=$build_cpus unavailable; using scheduler-selected CPUs" >&2
fi

echo "guarded-cargo: cpus=$affinity_status jobs=$build_jobs mem=${available_kib}KiB disk=${disk_kib}KiB" >&2
exec env CARGO_BUILD_JOBS="$build_jobs" \
    "${build_affinity[@]}" \
    nice -n 10 \
    timeout 1800 \
    "$cargo_bin" "$@"
