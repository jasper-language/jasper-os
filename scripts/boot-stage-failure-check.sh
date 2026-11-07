#!/usr/bin/env bash
# =============================================================================
# boot-stage-failure-check.sh —— 启动阶段失败、回滚与重复初始化的真实内核检查
#
# 构建专用验收内核；在 assembly 阶段让一次真实服务激活失败。判据：
#  1. 已完成的 capacity 阶段再次 begin 必须得到 duplicate 且状态不变；
#  2. assembly 失败后显式启动期回滚释放已安装对象表，所有资源回到阶段前基线；
#  3. 后续 sched_mode 的 begin 必须得到 halted，串口不得出现后续阶段的 done；
#  4. 验收构建以失败退出码 35 结束，不伪造成功收尾。
#
# 生产模式持续等待与容量拒绝停机由 production-check.sh 单独验证。
# 用法：boot-stage-failure-check.sh；LIMIT、OUT 可调。只在构建虚拟机内运行。
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

LIMIT="${LIMIT:-180}"
OUT="${OUT:-evidence/boot-stage-failure}"
TARGET=target/boot-stage-failure
mkdir -p "$OUT"
rm -f "$OUT/build.log" "$OUT/image.log" "$OUT/kernel.img" \
  "$OUT/guest.result" "$OUT/guest.serial" "$OUT/result" "$OUT/PASS"

cargo build --locked --release -p xtask > "$OUT/build.log" 2>&1 \
  || { echo "FAIL xtask 构建失败"; exit 1; }
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel \
  --features boot-stage-rollback-verify >> "$OUT/build.log" 2>&1 \
  || { echo "FAIL 故障注入内核构建失败"; exit 1; }
target/release/xtask \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" \
  "$OUT/kernel.img" > "$OUT/image.log" 2>&1 \
  || { echo "FAIL 镜像生成失败"; exit 1; }

flock /tmp/jasper-os-qemu.lock python3 scripts/boot-trace.py \
  --img "$OUT/kernel.img" --out "$OUT/guest" --timeout "$LIMIT" \
  --nice 10 --io-class 2 --smp 1 > "$OUT/result" 2>&1

serial="$OUT/guest.serial"
why=""
want_done="console platform timer frames kernel_map heap capacity devices profile "
done=$(grep -aoE '^\[JSR-BOOT-STAGE\] done stage=[a-z_]+' "$serial" \
  | sed 's/.*stage=//' | tr '\n' ' ')
[ "$done" = "$want_done" ] || why="$why 失败前阶段序列=[$done]"
grep -aq 'rc=35 ' "$OUT/result" || why="$why 验收失败退出码不是 35"
grep -aq '^\[JSR-BOOT-DUPLICATE\] stage=capacity result=duplicate state_unchanged=true' "$serial" \
  || why="$why 重复初始化未被拒绝"
grep -aq '^\[JSR-BOOT-FAULT\] point=assembly_activation nth=1 armed=true' "$serial" \
  || why="$why 故障未按预期装填"
grep -aq 'module=memory .*state=failed reason=injected boot activation failure' "$serial" \
  || why="$why 服务激活故障未发生在真实装配路径"
grep -aq '^\[JSR-BOOT-STAGE\] failed stage=assembly blocked=.*sched_mode.*user_runtime' "$serial" \
  || why="$why assembly 未报告失败与阻断集合"
grep -aqE '^\[JSR-BOOT-ROLLBACK\] owner=assembly .*objects_before=[1-9][0-9]* objects_after=0 .*published_before=0x0 published_after=0x0 runtime_before=false runtime_after=false .*heap_used_restored=true resources_baseline=true' "$serial" \
  || why="$why 对象表未释放或资源未回到基线"
grep -aq '^\[JSR-BOOT-STAGE\] rollback stage=assembly action=assembly resources_baseline=true' "$serial" \
  || why="$why 阶段回滚动作未通过"
grep -aq '^\[JSR-BOOT-STAGE\] blocked stage=sched_mode begin=halted started=0' "$serial" \
  || why="$why 被阻断阶段仍可开始"
grep -aq '^\[JSR-EXIT\] failure boot_stage=assembly' "$serial" \
  || why="$why 未走统一阶段失败出口"
grep -aqE '^\[JSR-PLAN\] finish|observed=false|^\[JSR-SCHED\] mode=|^\[JSR-SPACE\]|^\[JSR-STAGE\] user_runtime' "$serial" \
  && why="$why 意外进入后续阶段或计划收尾"
grep -aE 'panicked at|KERNEL PANIC|^\[JSR-PANIC\]' "$serial" | grep -q . \
  && why="$why 串口出现恐慌"

if [ -z "$why" ]; then
  echo "PASS 重复初始化被拒；assembly 失败后对象表与资源回到基线；后续阶段 halted；rc=35"
  cp "$OUT/result" "$OUT/PASS"
  exit 0
fi
echo "FAIL$why；结果：$(head -1 "$OUT/result" | cut -c1-160)"
tail -n 30 "$serial" 2>/dev/null || true
exit 1
