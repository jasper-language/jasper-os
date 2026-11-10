#!/usr/bin/env bash
# =============================================================================
# production-check.sh —— 生产启动模式的真实启动检查（issue #7 第二片，只在虚拟机内运行）
#
# 构建 production 内核，x86_64 QEMU 真实启动。判据：
#   1. 十六个阶段按序完成，第一个用户程序以退出码 0 结束且页帧全部归还；
#   2. 进入等待后时钟继续走（alive 行），到时限时 QEMU 还在运行：内核没有退出模拟器；
#   3. 不运行任何演练：计划里只有 first-program，串口没有 [JSR-EXIT]、恐慌或演练标记，等待期间不刷屏；
#   4. 损坏的启动容量记录：报告拒绝原因后停机，同样不退出模拟器，也不走到后面的阶段。
# 用法：production-check.sh；环境变量 CPUS（处理器数列表）、LIMIT（秒）、OUT 可调。
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
CPUS="${CPUS-1 4}"
LIMIT="${LIMIT:-120}"
OUT="${OUT:-evidence/production}"
TARGET=target/production
ORDER="console platform timer frames kernel_map heap capacity devices profile assembly sched_mode space smp highres idle_tick user_runtime "
mkdir -p "$OUT"
python3 scripts/check-production-feature-isolation.py
python3 scripts/check-issue19-demo-paths.py
cargo build --locked --release -p xtask > "$OUT/build.log" 2>&1 || { echo "FAIL xtask 构建失败"; exit 1; }
ELF="$TARGET/x86_64-unknown-none/release/jasper-kernel"
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features production >> "$OUT/build.log" 2>&1 \
  || { echo "FAIL 生产内核构建失败"; exit 1; }
python3 scripts/check-production-symbols.py "$ELF"

# 未列入生产清单的特性必须被 build.rs 默认拒绝。
# The negative case proves the build gate rejects an unlisted verification feature.
if CARGO_TARGET_DIR="$TARGET" cargo check --locked --target x86_64-unknown-none -p jasper-kernel \
    --features production,compat-elf-backend-verify >> "$OUT/build.log" 2>&1; then
  echo "FAIL 生产构建错误接受了验收特性"
  exit 1
fi
grep -q 'production feature isolation: forbidden features enabled' "$OUT/build.log" \
  || { echo "FAIL 生产特性负例缺少机械拒绝原因"; exit 1; }
target/release/xtask "$ELF" "$OUT/kernel.img" > "$OUT/image.log" 2>&1 || { echo "FAIL 镜像生成失败"; exit 1; }
# 同一个生产内核，容量记录写成不支持的版本号（与 accept.sh 的 x86-corrupt 相同）。
target/release/xtask bootcap "$ELF" "$OUT/caprej.elf" record=corrupt >> "$OUT/build.log" 2>&1 \
  && target/release/xtask "$OUT/caprej.elf" "$OUT/caprej.img" >> "$OUT/image.log" 2>&1 || { echo "FAIL 损坏容量记录的镜像生成失败"; exit 1; }

for n in $CPUS; do
  cp "$OUT/kernel.img" "$OUT/k$n.img"
  rm -f "$OUT/p$n.result" "$OUT/p$n.serial"
  python3 scripts/boot-trace.py --img "$OUT/k$n.img" --out "$OUT/p$n" --timeout "$LIMIT" --nice 10 --io-class 2 --smp "$n" \
    > "$OUT/p$n.result" 2>&1
done
rm -f "$OUT/caprej.result" "$OUT/caprej.serial"
python3 scripts/boot-trace.py --img "$OUT/caprej.img" --out "$OUT/caprej" --timeout "$LIMIT" --nice 10 --io-class 2 \
  > "$OUT/caprej.result" 2>&1

rc=0
for n in $CPUS; do
  s="$OUT/p$n.serial"
  order=$(grep -aoE '^\[JSR-BOOT-STAGE\] done stage=[a-z_]+' "$s" | sed 's/.*stage=//' | tr '\n' ' ')
  cases=$(grep -aoE '^\[JSR-PLAN\] case name=[a-z0-9-]+' "$s" | sed 's/.*name=//' | tr '\n' ' ')
  why=""
  [ "$order" = "$ORDER" ] || why="$why 阶段序列=[$order]"
  [ "$cases" = "first-program " ] || why="$why 用例=[$cases]"
  grep -aq 'timed_out=1' "$OUT/p$n.result" || why="$why QEMU 提前退出($(head -1 "$OUT/p$n.result" | cut -c1-80))"
  grep -aqE '^\[JSR-PROD\] first_program state=Some\(Exited \{ code: 0 \}\) reclaimed=true' "$s" || why="$why 第一个用户程序未正常结束"
  grep -aq '^\[JSR-PLAN\] finish plan=production stages=0xffff cases=1' "$s" || why="$why 缺计划收尾行"
  grep -aqE '^\[JSR-PROD\] alive ticks=[1-9]' "$s" || why="$why 等待后时钟没有走"
  grep -aqE '^\[JSR-(EXIT|PANIC)\]|panicked at|KERNEL PANIC' "$s" && why="$why 串口出现退出或恐慌"
  grep -aqE '^\[JSR-(BENCH|SCALE|PROG\] elf|MM-DEMO)' "$s" && why="$why 串口出现演练输出"
  [ "$(wc -l < "$s")" -lt 1000 ] || why="$why 等待期间串口持续输出（$(wc -l < "$s") 行）"
  rm -f "$OUT/k$n.img"
  if [ -z "$why" ]; then
    echo "cpus=$n PASS $(grep -am1 -E '^\[JSR-PROD\] alive' "$s")，串口 $(wc -l < "$s") 行"
  else
    echo "cpus=$n FAIL$why；末行：$(tail -n1 "$s" | cut -c1-160)"
    rc=1
  fi
done

s="$OUT/caprej.serial"
why=""
grep -aq 'timed_out=1' "$OUT/caprej.result" || why="$why QEMU 提前退出"
grep -aqE '^\[JSR-CAP\] reject field=record .* reason=bad_version' "$s" || why="$why 缺拒绝原因"
grep -aq '^\[JSR-EXIT\] failure boot_capacity' "$s" || why="$why 缺失败标记"
grep -aq 'done stage=capacity\|done stage=devices\|done stage=profile' "$s" && why="$why 走到了容量之后的阶段"
if [ -z "$why" ]; then
  echo "caprej PASS 拒绝后停机，QEMU 未退出"
else
  echo "caprej FAIL$why；末行：$(tail -n1 "$s" | cut -c1-160)"
  rc=1
fi
exit "$rc"
