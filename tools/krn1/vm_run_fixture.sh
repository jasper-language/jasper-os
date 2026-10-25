#!/bin/bash
# =============================================================================
# vm-run.sh —— 在 Jasper 专用构建虚拟机 JasperBuild01 里执行重型构建 / 验收
#
# 为什么：用户 2026-10-21 决定把暴力编译与 QEMU 验收放进独立虚拟机——虚拟机固定在宿主
# 逻辑 CPU 12-19（8 个 vCPU 全占），系统盘在第二块 SSD（nvme1n1）上，与宿主桌面、
# Codex 的 MeowuuBuild01（4-7 号核）互不争抢；虚拟机由用户级服务 jasper-build-vm 常驻。
#
# 做什么：rsync 推送源码（不含 target / evidence / images）→ 在虚拟机里执行命令
#        → 把虚拟机里的 evidence/ 拉回宿主同一位置。虚拟机里不保存任何凭据；推送与同步公开仓库仍在宿主做。
#
# 用法：vm-run.sh <仓库目录> <命令...>
#   例：vm-run.sh jasper-os-build/jasper-os bash scripts/accept.sh
#       vm-run.sh jasper ./gradlew test --no-daemon
# 退出码：命令在虚拟机里的退出码；虚拟机不可达时为 90。
# =============================================================================
set -uo pipefail
# Author: chatgpt. Execute a private immutable inode: editing the public script
# must never change where a long-lived Bash process resumes after SSH returns.
if [[ "${1:-}" == --vm-run-internal-snapshot && "${BASH_SOURCE[0]}" == /tmp/jasper-vm-run.*/vm-run.sh ]]; then
    shift
    vm_run_snapshot_path="${BASH_SOURCE[0]}"
else
    vm_run_snapshot_dir=$(mktemp -d /tmp/jasper-vm-run.XXXXXX) || exit 92
    vm_run_snapshot_path="$vm_run_snapshot_dir/vm-run.sh"
    cp -- "${BASH_SOURCE[0]}" "$vm_run_snapshot_path" || { rmdir -- "$vm_run_snapshot_dir"; exit 92; }
    trap 'rm -f -- "$vm_run_snapshot_path"; rmdir -- "${vm_run_snapshot_path%/*}"' EXIT
    exec bash "$vm_run_snapshot_path" --vm-run-internal-snapshot "$@"
fi
trap 'rm -f -- "$vm_run_snapshot_path"; rmdir -- "${vm_run_snapshot_path%/*}"' EXIT
REPO="${1:?用法：vm-run.sh <仓库目录> <命令...>}"; shift
[ $# -gt 0 ] || { echo "缺少要执行的命令"; exit 2; }
case "$REPO" in /*) ;; *) REPO="/home/auth/Documents/jasper/$REPO";; esac
# Author: chatgpt. Reject ambiguous/root destinations before any remote mutation.
REPO=$(realpath -e -- "$REPO") || { echo "✗ 源码目录不存在"; exit 92; }
case "$REPO" in /|/home/auth|/home/auth/Documents|/home/auth/Documents/jasper|/home/auth/Documents/jasper/jasper-os-build)
  echo "✗ 拒绝同步工作区根目录；请传具体项目目录"; exit 92;;
esac
[ -d "$REPO" ] || { echo "✗ 源码路径不是目录"; exit 92; }
NAME="$(basename -- "$REPO")"
[[ "$NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] || { echo "✗ 非法项目目录名"; exit 92; }
SSH=(ssh -i "$HOME/.ssh/jasper_build_vm" -o UserKnownHostsFile="$HOME/.ssh/known_hosts_jasper_vm" -o BatchMode=yes -o ConnectTimeout=10 -p 2224)
DEST=jasper@127.0.0.1

"${SSH[@]}" "$DEST" true 2>/dev/null || { echo "✗ 构建虚拟机不可达（systemctl --user status jasper-build-vm）"; exit 90; }

"${SSH[@]}" "$DEST" "mkdir -p ~/work/$NAME" || { echo "✗ 无法在虚拟机里建立工作目录"; exit 91; }

# 1) 推送源码：删除虚拟机里多余的源文件，保留其构建缓存与证据
rsync -a --delete -e "${SSH[*]}" \
  --exclude target/ --exclude evidence/ --exclude images/ --exclude build/ --exclude .gradle/ \
  "$REPO/" "$DEST:work/$NAME/" || { echo "✗ 推送源码失败"; exit 91; }

# 2) 在虚拟机里执行（VM_NICE：虚拟机内的优先级，语言车道传 10，让 jasper-os 的计时类 QEMU 测试优先；8 个 vCPU 全部可用：核约束 0-7；最低 CPU / I/O 优先级不再需要——整台虚拟机都是构建专用）
#    VM_KEEP_AWAKE（默认 1）：命令执行期间在每个 vCPU 上挂一个 SCHED_IDLE 空转进程，让 vCPU 不进入 HLT。
#    原因（2026-10-21 实测）：VirtualBox 7.2.22 的 global1 停机方式下，停机中的 vCPU 本地定时器严重迟到
#    （客户机 sleep(10ms) 中位 19 ms、p90 388 ms、max 934 ms），vCPU 不停机时准确（中位 10.1 ms、max 11 ms）；
#    改用 old / method1 停机方式虽治定时器，但跨 vCPU 唤醒变成 16 ms、客户机几乎不可用，故不采用。
#    SCHED_IDLE 只在该核无其他可运行任务时才运行，不与构建 / QEMU 争 CPU；父 shell 退出即自行结束。
#    2026-10-21 分层验收：默认（=1）不再整条命令空转，只把 JASPER_KEEP_AWAKE=1 交给命令——accept.sh 只在 QEMU 运行期间、
#    只在 QEMU 所用的核上空转（定点单核时只占 2 个核）。=all 恢复旧的整条命令全核空转；=0 完全不空转。
KEEP=""
export_keep="JASPER_KEEP_AWAKE=$([ "${VM_KEEP_AWAKE:-1}" = 0 ] && echo 0 || echo 1)"
if [ "${VM_KEEP_AWAKE:-1}" = all ]; then
  KEEP='for c in $(seq 0 $(($(nproc)-1))); do taskset -c $c chrt -i 0 sh -c "while kill -0 $$ 2>/dev/null; do :; done" & done; trap "kill \$(jobs -p) 2>/dev/null" EXIT; '
fi
CMD=$(printf '%q ' "$@")
"${SSH[@]}" "$DEST" "${KEEP}source \$HOME/.cargo/env 2>/dev/null; cd ~/work/$NAME && $export_keep JASPER_CORES=0-7 JASPER_QEMU_TIMEOUT=${JASPER_QEMU_TIMEOUT:-300} nice -n ${VM_NICE:-0} $CMD"
RC=$?

# 3) 拉回证据目录（若有）
if "${SSH[@]}" "$DEST" "[ -d ~/work/$NAME/evidence ]"; then
  mkdir -p "$REPO/evidence"
  rsync -a -e "${SSH[*]}" "$DEST:work/$NAME/evidence/" "$REPO/evidence/"
fi
exit $RC
