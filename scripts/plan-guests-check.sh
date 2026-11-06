#!/usr/bin/env bash
# =============================================================================
# plan-guests-check.sh —— 启动计划的构建矩阵与专项计划真实启动（issue #7 第二片，只在虚拟机内运行）
#
# 1. 构建矩阵：每个专项特性、裁剪与策略组合都要能编译（计划在编译期检查，所以这同时检查计划良构）。
#    多个专项特性同开、production 与验收特性同开必须编译失败。
# 2. 真实启动：专项计划各启动一次（S-2 与长跑除外，它们由各自的脚本跑），要求走到计划收尾、
#    退出码是该计划的成功码、没有恐慌。判据只看计划编排，不替代各专项脚本的结论。
#    预算窗口、p999 与广播演练自身要求 8 个处理器，即使 SMP 默认值更小也按 8 核启动。
# 用法：plan-guests-check.sh；环境变量 LIMIT（单次启动秒数）、SMP、ONLY（只跑这些特性）、
# MATRIX=0（复用已完成的构建矩阵，只跑 guest）、OUT 可调。
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
LIMIT="${LIMIT:-900}"
SMP="${SMP:-4}"
MATRIX="${MATRIX:-1}"
OUT="${OUT:-evidence/plan-guests}"
TARGET=target/plan-guests
KTARGET=x86_64-unknown-none
mkdir -p "$OUT"
rc=0
cargo build --locked --release -p xtask > "$OUT/build.log" 2>&1 || { echo "FAIL xtask 构建失败"; exit 1; }

build() { # build <目标> <cargo 参数…>
  local t="$1"; shift
  CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target "$t" -p jasper-kernel "$@" >> "$OUT/build.log" 2>&1
}

# 特性:计划名
GUESTS="rt1-verify:rt1 rt2-verify:rt2 rt3-verify:rt3 budget-window-verify:budget-window krn3-fast-tick-verify:krn3-fast-tick
krn3-postsplit-verify:krn3-postsplit krn3-p999-verify:krn3-p999 evt1-verify:evt1 evt2-verify:evt2
evt2-broadcast-verify:evt2-broadcast s3-nohz-verify:s3-nohz shm1-verify:shm1"

if [ "$MATRIX" = 1 ]; then
  for spec in \
    "$KTARGET --features s2-only" "$KTARGET --features s2-fuzz" "$KTARGET --features krn1-soak" "$KTARGET --features fault-inject" \
    "$KTARGET --features sched-rr" "$KTARGET --features profile-compact" "$KTARGET --no-default-features" \
    "$KTARGET --no-default-features --features production" "$KTARGET --features ns-dirty-audit,rt2-verify" \
    "aarch64-unknown-none --no-default-features" "aarch64-unknown-none --no-default-features --features production"; do
    # shellcheck disable=SC2086
    if build $spec; then echo "build PASS $spec"; else echo "build FAIL $spec"; rc=1; fi
  done
  for spec in "rt1-verify,evt1-verify" "production,rt2-verify" "production,fault-inject"; do
    if build "$KTARGET" --features "$spec"; then
      echo "reject FAIL $spec 竟然能编译"; rc=1
    else
      echo "reject PASS $spec"
    fi
  done
else
  echo "build SKIP 矩阵（MATRIX=0）"
fi

selected=""
for g in $GUESTS; do
  f="${g%%:*}"
  if [ -n "${ONLY:-}" ] && ! grep -qw "$f" <<<"$ONLY"; then continue; fi
  selected="$selected $g"
  if ! build "$KTARGET" --features "$f"; then echo "guest FAIL $f 构建失败"; rc=1; continue; fi
  target/release/xtask "$TARGET/$KTARGET/release/jasper-kernel" "$OUT/$f.img" > "$OUT/$f.image.log" 2>&1 || { echo "guest FAIL $f 镜像失败"; rc=1; continue; }
  rm -f "$OUT/$f.result" "$OUT/$f.serial"
  cpus="$SMP"
  guest_limit="$LIMIT"
  extra=()
  case "$f" in
    budget-window-verify) cpus=8; extra=(--icount 5);;
    krn3-postsplit-verify) cpus=4; extra=(--icount 5);;
    krn3-p999-verify|evt2-broadcast-verify) cpus=8; guest_limit=1200; extra=(--icount 0);;
  esac
  python3 scripts/boot-trace.py --img "$OUT/$f.img" --out "$OUT/$f" --timeout "$guest_limit" --nice 10 --io-class 2 --smp "$cpus" "${extra[@]}" > "$OUT/$f.result" 2>&1
done

for g in $selected; do
  f="${g%%:*}"; name="${g##*:}"; s="$OUT/$f.serial"
  if [ ! -f "$OUT/$f.result" ]; then
    echo "guest FAIL $f plan=UNKNOWN result=MISSING（启动结果缺失）"
    rc=1
    continue
  fi
  plan_why=""
  result_why=""
  grep -aq "^\[JSR-PLAN\] finish plan=$name " "$s" || plan_why="$plan_why 没走到计划收尾"
  grep -aqE '^\[JSR-BOOT-STAGE\] (refused|failed)' "$s" && plan_why="$plan_why 阶段被拒或失败"
  grep -aqE "rc=(33|37) " "$OUT/$f.result" || result_why="$result_why $(head -1 "$OUT/$f.result" | cut -c1-70)"
  grep -aE 'panicked at|KERNEL PANIC|^\[JSR-PANIC\]' "$s" | grep -avE '^\[JSR-USERTEXT\]' | grep -q . && result_why="$result_why 恐慌"
  rm -f "$OUT/$f.img"
  if [ -z "$plan_why" ] && [ -z "$result_why" ]; then
    echo "guest PASS $f $(head -1 "$OUT/$f.result" | grep -oE 'rc=[0-9]+')，$(wc -l < "$s") 行"
  elif [ -z "$plan_why" ]; then
    echo "guest FAIL $f plan=PASS result=FAIL$result_why；末行：$(tail -n1 "$s" | cut -c1-140)"
    rc=1
  else
    echo "guest FAIL $f plan=FAIL$plan_why result=FAIL$result_why；末行：$(tail -n1 "$s" | cut -c1-140)"
    rc=1
  fi
done
exit "$rc"
