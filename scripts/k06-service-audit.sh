#!/usr/bin/env bash
# =============================================================================
# k06-service-audit.sh —— 完整 / 精简 Profile 的服务归属与可用性真实启动审计
#
# 判据：
#  1. 每个已登记操作在完整服务面中都有唯一所有者（unclaimed=0）；
#  2. 完整 Profile 没有未装配服务或门禁不一致；
#  3. 精简 Profile 不装配异步/通道/作业模块，因此异步环操作为 unavailable；
#  4. 精简 Profile 仍保留的 core 同步、ABI 与时间基础调用可用。
#
# 只接受真实 QEMU 串口证据；不把文档或合成 mock 当作运行结果。
# 用法：k06-service-audit.sh；LIMIT、STOP_LINES、OUT 可调。只在构建虚拟机内运行。
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

LIMIT="${LIMIT:-240}"
STOP_LINES="${STOP_LINES:-320}"
OUT="${OUT:-evidence/k06-service-audit/$(date '+%Y%m%d-%H%M%S')}"
TARGET=target/k06-service-audit
KTARGET=x86_64-unknown-none
mkdir -p "$OUT"

source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$HOME/.cargo/bin:$PATH"

cargo build --locked --release -p xtask > "$OUT/build.log" 2>&1 \
  || { echo "FAIL xtask 构建失败"; exit 1; }

build_and_boot() { # build_and_boot <name> [features...]
  local name="$1"; shift
  local features=()
  if [ "$#" -gt 0 ]; then features=(--features "$*"); fi
  CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
    --target "$KTARGET" -p jasper-kernel "${features[@]}" >> "$OUT/build.log" 2>&1 \
    || { echo "FAIL $name 内核构建失败"; return 1; }
  target/release/xtask "$TARGET/$KTARGET/release/jasper-kernel" "$OUT/$name.img" \
    > "$OUT/$name.image.log" 2>&1 \
    || { echo "FAIL $name 镜像生成失败"; return 1; }
  flock /tmp/jasper-os-qemu.lock python3 scripts/boot-trace.py \
    --img "$OUT/$name.img" --out "$OUT/$name" --timeout "$LIMIT" \
    --stop-at-lines "$STOP_LINES" --nice 10 --io-class 2 --smp 4 \
    > "$OUT/$name.result" 2>&1
  return 0
}

build_and_boot standard || exit 1
build_and_boot headless-min rt1-no-realtime || exit 1

why=""
standard_line=$(grep -a '^\[JSR-K06\]' "$OUT/standard.serial" | head -1)
minimal_line=$(grep -a '^\[JSR-K06\]' "$OUT/headless-min.serial" | head -1)

case "$standard_line" in
  *'profile=headless '*active_unavailable=0*unclaimed=0*gate_mismatch=0*ring=available*time=available*sync=available*) ;;
  *) why="$why 标准 Profile 服务审计不符：${standard_line:-missing}" ;;
esac
case "$minimal_line" in
  *'profile=headless-min '*active_unavailable=[1-9]*unclaimed=0*gate_mismatch=0*ring=unavailable*time=available*sync=available*) ;;
  *) why="$why 精简 Profile 服务审计不符：${minimal_line:-missing}" ;;
esac

for name in standard headless-min; do
  grep -aq '^\[JSR-K06-FAIL\]' "$OUT/$name.serial" \
    && why="$why $name 存在未认领操作"
  grep -aE 'panicked at|KERNEL PANIC|^\[JSR-PANIC\]' "$OUT/$name.serial" | grep -q . \
    && why="$why $name 串口出现恐慌"
done

if [ -z "$why" ]; then
  echo "PASS 标准 Profile：所有登记操作有唯一所有者，异步/时间/同步服务可用"
  echo "PASS 精简 Profile：异步环明确不可用，core 同步/ABI 与时间服务仍可用"
  printf '%s\n' "$standard_line" "$minimal_line" > "$OUT/summary.txt"
  printf 'PASS\n' > "$OUT/PASS"
  exit 0
fi

echo "FAIL$why"
printf '%s\n' "$standard_line" "$minimal_line"
tail -n 30 "$OUT/standard.serial" 2>/dev/null || true
tail -n 30 "$OUT/headless-min.serial" 2>/dev/null || true
exit 1
