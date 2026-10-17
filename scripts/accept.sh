#!/bin/bash
# =============================================================================
# accept.sh —— jasper-os 一键验收（M1.0–M2.x，逐里程碑累加）+ 证据归档
#
# 做什么：
#   1. 宿主单元测试（kernel-core）与裸机目标编译
#   2. 构建内核与可引导镜像，在 QEMU 中**真实启动一次**，保存原始串口日志
#   3. 按各里程碑的判据逐项检查同一份串口日志，打印 PASS/FAIL 表
#   4. 全部证据（构建日志、测试日志、串口日志、汇总表）归档到 evidence/accept-<时间戳>/
#
# 设计：
#   * 每个里程碑一个检查函数，互不依赖；任何一项失败都不提前退出，最后统一汇总
#   * 只有真实 QEMU 输出才算数：日志由 QEMU stdout 重定向得到，脚本从不生成或改写日志
#   * 仅使用仓库内相对路径，可在任何检出位置运行
#
# 用法：  bash scripts/accept.sh            （默认 4 核：taskset -c 0-3）
#         JASPER_CORES=0-7 bash scripts/accept.sh
# 退出码：0 = 全部 PASS；1 = 至少一项 FAIL；2 = 环境缺失（无 cargo / qemu）
# =============================================================================
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORES="${JASPER_CORES:-0-3}"
TS="$(date '+%Y%m%d-%H%M%S')"
OUT="$ROOT/evidence/accept-$TS"
IMG="$ROOT/images/jasper-kernel.img"
SERIAL="$OUT/serial.log"
QEMU="$(command -v qemu-system-x86_64 || true)"
export PATH="$HOME/.cargo/bin:$PATH"

mkdir -p "$OUT" "$ROOT/images"
cd "$ROOT" || { echo "✗ 无法进入仓库根目录"; exit 2; }
command -v cargo >/dev/null || { echo "✗ 找不到 cargo"; exit 2; }
[ -n "$QEMU" ] || { echo "✗ 找不到 qemu-system-x86_64"; exit 2; }

# 在限定核上运行（taskset 不存在时直接运行）。
run() { if command -v taskset >/dev/null; then taskset -c "$CORES" "$@"; else "$@"; fi; }

# ---- 结果表 ----------------------------------------------------------------
declare -a ROWS=()
FAILED=0
# record <里程碑> <PASS|FAIL> <说明>
record() {
  ROWS+=("$(printf '%-6s %-4s %s' "$1" "$2" "$3")")
  [ "$2" = "PASS" ] || FAILED=1
}
# has <正则>：串口日志里是否出现
has() { grep -qE "$1" "$SERIAL" 2>/dev/null; }
# count <正则>：串口日志里出现的行数
count() { grep -cE "$1" "$SERIAL" 2>/dev/null || true; }

# ---- 阶段 A：构建、测试、启动（产出证据）------------------------------------
echo "== 构建与测试（核：$CORES）=="
run cargo test -p kernel-core > "$OUT/cargo-test.log" 2>&1;                                   TEST_RC=$?
run cargo build --release --target x86_64-unknown-none -p kernel-core > "$OUT/build.log" 2>&1; CORE_RC=$?
run cargo build --release --target x86_64-unknown-none -p jasper-kernel >> "$OUT/build.log" 2>&1 \
  && run cargo build --release -p xtask >> "$OUT/build.log" 2>&1 \
  && run "$ROOT/target/release/xtask" "$ROOT/target/x86_64-unknown-none/release/jasper-kernel" "$IMG" >> "$OUT/build.log" 2>&1
BUILD_RC=$?

QRC=-1
if [ "$BUILD_RC" -eq 0 ]; then
  echo "== QEMU 真实启动 =="
  run timeout 90 "$QEMU" -drive format=raw,file="$IMG" \
    -serial stdio -display none -monitor none -no-reboot \
    -m 256M -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$SERIAL" 2>&1
  QRC=$?
fi

# ---- 阶段 B：逐里程碑检查 ----------------------------------------------------

check_m10() {   # 骨架：kernel-core 宿主测试 + 裸机编译
  local passed
  passed=$(grep -oE '^test result: ok\. [0-9]+ passed; 0 failed' "$OUT/cargo-test.log" | head -1 | grep -oE '[0-9]+ passed')
  if [ "$TEST_RC" -eq 0 ] && [ "$CORE_RC" -eq 0 ] && [ -n "$passed" ]; then
    record M1.0 PASS "kernel-core 宿主测试 $passed；裸机目标编译 ✓"
  else
    record M1.0 FAIL "cargo test rc=$TEST_RC，裸机编译 rc=$CORE_RC（见 cargo-test.log / build.log）"
  fi
}

check_m11() {   # 真实启动 + 横幅 + 自退出
  if [ "$QRC" -eq 33 ] && has '^\[JSR-BOOT\] jasper-os rust kernel' && has '^\[JSR-EXIT\] success'; then
    record M1.1 PASS "QEMU=33，横幅与 [JSR-EXIT] success ✓"
  else
    record M1.1 FAIL "QEMU 退出码=$QRC（期望 33）或缺少 BOOT/EXIT 标记"
  fi
}

check_m12() {   # 真中断：断点异常 + tick ≥20 且严格递增
  local n prev=0 mono=1 v
  n=$(count '^\[JSR-TICK\] n=')
  for v in $(grep -oE '^\[JSR-TICK\] n=[0-9]+' "$SERIAL" 2>/dev/null | grep -oE '[0-9]+$'); do
    [ "$v" -gt "$prev" ] || mono=0; prev=$v
  done
  if [ "${n:-0}" -ge 20 ] && [ "$mono" -eq 1 ] && has '^\[JSR-EXC\] breakpoint handler verified'; then
    record M1.2 PASS "tick=$n（严格递增），断点异常 ✓"
  else
    record M1.2 FAIL "tick=${n:-0}，递增=$mono，或缺少断点异常标记"
  fi
}

check_m13() {   # 协作式切换：A/B/C 交错，回到引导线程
  local sw names a1 a2 ok=1
  sw=$(count 'JSR-SCHED\] switch .*cause=yield')
  names=$(grep -oE 'JSR-TASK\] name=[ABC] ' "$SERIAL" 2>/dev/null | sort -u | wc -l)
  a1=$(grep -n 'name=A step=1' "$SERIAL" | head -1 | cut -d: -f1)
  a2=$(grep -n 'name=A step=2' "$SERIAL" | head -1 | cut -d: -f1)
  { [ -n "$a1" ] && [ -n "$a2" ] && sed -n "${a1},${a2}p" "$SERIAL" | grep -q 'name=B'; } || ok=0
  if [ "${sw:-0}" -ge 6 ] && [ "$names" -ge 3 ] && [ "$ok" -eq 1 ] && has 'JSR-SCHED\] all tasks exited'; then
    record M1.3 PASS "yield 切换=$sw，A/B/C 交错，回到引导线程 ✓"
  else
    record M1.3 FAIL "yield 切换=${sw:-0}，任务数=$names，交错=$ok"
  fi
}

check_m14() {   # 定时器抢占：段内 cause=tick ≥10、P/Q/R 交错 ≥3、无主动让出
  local seg tick yld chg
  seg=$(sed -n '/name=P step=1/,/preemptive demo done/p' "$SERIAL" 2>/dev/null)
  tick=$(printf '%s\n' "$seg" | grep -c 'cause=tick' || true)
  yld=$(printf '%s\n' "$seg" | grep -c 'cause=yield' || true)
  chg=$(printf '%s\n' "$seg" | grep -oE 'JSR-TASK\] name=[PQR]' | awk -F= 'NR>1 && $2!=p{c++} {p=$2} END{print c+0}')
  if [ "${tick:-0}" -ge 10 ] && [ "${yld:-0}" -eq 0 ] && [ "${chg:-0}" -ge 3 ]; then
    record M1.4 PASS "tick 抢占切换=$tick，P/Q/R 交错=$chg，段内无主动让出 ✓"
  else
    record M1.4 FAIL "tick 切换=${tick:-0}，主动让出=${yld:-0}，交错=${chg:-0}"
  fi
}

check_m14b() {  # arch 分层：Core 与 kernel-core 不含 ISA 专有代码
  local files leaks
  files=$(find "$ROOT/kernel/src" -name '*.rs' -not -path '*/arch/*' -not -name main.rs; find "$ROOT/kernel-core/src" -name '*.rs')
  leaks=$(grep -nE 'x86_64::|asm!|global_asm!|x86-interrupt|\boutb\b|\binb\b|Port::|0x3[Ff]8|_VECTOR' $files \
          | grep -vE '^[^:]+:[0-9]+:\s*//' || true)
  if [ -z "$leaks" ]; then
    record M1.4b PASS "Core $(echo "$files" | wc -l) 个文件无 ISA 专有代码 ✓"
  else
    printf '%s\n' "$leaks" > "$OUT/isa-leaks.txt"
    record M1.4b FAIL "Core 出现 ISA 专有代码（见 isa-leaks.txt）"
  fi
}

check_m15() {   # 机制演练：8 类标记 + 关键语义 + 真机断言 0 失败
  local k miss=""
  for k in OBJ WAIT IO VM MOD SYSCALL SYNC TRACE; do has "^\[JSR-$k\]" || miss="$miss $k"; done
  has 'stale handle=[0-9]+ rejected'           || miss="$miss 句柄复用拒绝"
  has '^\[JSR-IO\] ring completions=2 pending=0' || miss="$miss 恰好两条完成"
  has 'cancelled err=system\.async\.error\.cancelled' || miss="$miss 取消完成"
  has '^\[JSR-MECH\] .*failed=0'                || miss="$miss 真机断言"
  if [ -z "$miss" ]; then
    record M1.5 PASS "8 类机制标记齐全，句柄/ring/取消语义 ✓，真机断言 0 失败"
  else
    record M1.5 FAIL "缺少：$miss"
  fi
}

check_m21() {   # 物理页帧：可用帧规模合理、真实读写、复用、重复释放被拒、断言 0 失败
  local usable
  usable=$(grep -oE '^\[JSR-FRAME\] regions=[0-9]+ usable_frames=[0-9]+' "$SERIAL" 2>/dev/null | grep -oE '[0-9]+$')
  if [ "${usable:-0}" -ge 16384 ] && has '^\[JSR-FRAME\] rw ok=true' && has 'reuse=true' \
     && has 'double free rejected err=system\.memory\.error\.double_free' && has '^\[JSR-FRAME\] checks=[0-9]+ failed=0'; then
    record M2.1 PASS "可用帧=$usable，真实读写/复用/重复释放拒绝 ✓，断言 0 失败"
  else
    record M2.1 FAIL "可用帧=${usable:-0} 或缺少 rw/reuse/double-free/failed=0 标记"
  fi
}

check_m22() {   # 映射 API：映射后经虚拟地址写/物理映射读一致、只读生效、错误路径、取消映射
  if has '^\[JSR-MAP\] map va=0x[0-9a-f]+ frame=0x[0-9a-f]+ .*translate_ok=true' \
     && has '^\[JSR-MAP\] write via va, read via phys same=true' && has '^\[JSR-MAP\] protect read_only ok=true' \
     && has 'double_map=system\.memory\.error\.already_mapped invalid_addr=system\.memory\.error\.invalid_address' \
     && has 'unmap returned_frame=true translate_after=none again=system\.memory\.error\.not_mapped' \
     && has '^\[JSR-MAP\] checks=[0-9]+ failed=0'; then
    record M2.2 PASS "映射/真实读写/只读/错误路径/取消映射 ✓，断言 0 失败"
  else
    record M2.2 FAIL "缺少 JSR-MAP 关键标记或 failed≠0"
  fi
}

check_m23() {   # 内核堆：Box/Vec/String（UTF-8 中文）可用、大对象触发增长、全部释放后回到基线且合并为一块
  if has '^\[JSR-HEAP\] box ok vec_len=10000 vec_sum=149985000' && has '^\[JSR-HEAP\] grow big_bytes=[0-9]+ .*mapped_after=' \
     && has 'baseline_ok=true' && has '^\[JSR-HEAP\] checks=[0-9]+ failed=0'; then
    record M2.3 PASS "Box/Vec/String(中文) ✓，按需增长 ✓，释放后回到基线并合并 ✓"
  else
    record M2.3 FAIL "缺少 JSR-HEAP 关键标记或 failed≠0"
  fi
}

check_m24() {   # 独立地址空间：真实切换后同一虚拟地址读到不同帧、内核共享、私有不外泄、销毁后页帧全部回收
  if has '^\[JSR-AS\] switch read a=0xaaaa00000000000a b=0xbbbb00000000000b a_again=0xaaaa00000000000a isolated=true kernel_shared=true' \
     && has '^\[JSR-AS\] kernel space sees va=unmapped' && has 'outside_window=system\.memory\.error\.invalid_address' \
     && has '^\[JSR-AS\] destroyed .*reclaimed=true' && has '^\[JSR-AS\] checks=[0-9]+ failed=0'; then
    record M2.4 PASS "真实切换隔离 ✓，内核共享 ✓，私有不外泄 ✓，销毁后页帧全部回收 ✓"
  else
    record M2.4 FAIL "缺少 JSR-AS 关键标记或 failed≠0"
  fi
}

check_m31() {   # Ring 3：真实 CPL=3；读内核地址在该地址缺页且无泄漏；特权指令被拦；三次故障后内核存活、页帧回收
  if has 'probe=report_privilege cs=0x[0-9a-f]+ cpl=3 marker=0x55aa ring3=true' \
     && has 'probe=read_kernel addr=0x[0-9a-f]+ leaked=false fault_at_addr=true' \
     && has 'probe=privileged marker=0x7e57 after=0x0 stopped=true' \
     && has 'kernel alive after faults=3 .*reclaimed=true' && has '^\[JSR-USER\] checks=[0-9]+ failed=0'; then
    record M3.1 PASS "CPL=3 实证，读内核被拦无泄漏，特权指令被拦，3 次用户故障后内核存活且页帧回收"
  else
    record M3.1 FAIL "缺少 JSR-USER 关键标记或 failed≠0"
  fi
}

check_m10; check_m11; check_m12; check_m13; check_m14; check_m14b; check_m15; check_m21; check_m22; check_m23; check_m24; check_m31

# ---- 汇总与归档 --------------------------------------------------------------
{
  echo "jasper-os 一键验收  $TS"
  echo "提交：$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)$(git -C "$ROOT" diff --quiet 2>/dev/null || echo '（工作区有未提交改动）')"
  echo "QEMU 退出码：$QRC"
  echo
  printf '%-6s %-4s %s\n' "里程碑" "结果" "说明"
  printf '%s\n' "${ROWS[@]}"
} | tee "$OUT/summary.txt"

for f in cargo-test.log build.log serial.log summary.txt; do
  [ -s "$OUT/$f" ] || { echo "✗ 证据文件为空或缺失：$f"; FAILED=1; }
done
echo
echo "证据目录：$OUT"
if [ "$FAILED" -eq 0 ]; then echo "accept: ALL PASS"; exit 0; else echo "accept: FAIL"; exit 1; fi
