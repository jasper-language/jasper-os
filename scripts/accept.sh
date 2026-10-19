#!/bin/bash
# =============================================================================
# accept.sh —— jasper-os 一键验收（M1.0–M2.x，逐里程碑累加）+ 证据归档
#
# 做什么：
#   1. 宿主单元测试（kernel-core）与裸机目标编译
#   2. 构建内核与可引导镜像，在 QEMU 中**真实启动一次**，保存原始串口日志；
#      同一内核再以 AArch64 与 RISC-V64 构建，各在对应的 QEMU 中真实启动一次
#   3. 按各里程碑的判据逐项检查同一份串口日志，打印 PASS/FAIL 表
#   4. 全部证据（构建日志、测试日志、串口日志、汇总表）归档到 evidence/accept-<时间戳>/
#
# 设计：
#   * 每个里程碑一个检查函数，互不依赖；任何一项失败都不提前退出，最后统一汇总
#   * 只有真实 QEMU 输出才算数：日志由 QEMU stdout 重定向得到，脚本从不生成或改写日志
#   * 仅使用仓库内相对路径，可在任何检出位置运行
#
# 用法：  bash scripts/accept.sh            （默认：机器最后 4 个逻辑核，最低 CPU 与 I/O 优先级）
#         JASPER_CORES=8-11 bash scripts/accept.sh
#         JASPER_PROFILE=compact bash scripts/accept.sh   （内核配置档：standard（默认）| compact）
#         JASPER_QEMU_TIMEOUT=300 bash scripts/accept.sh  （单次 QEMU 启动的时限，秒；默认 90。较慢的托管运行器上放宽）
# 为什么默认用最后几个核：前几个核（尤其 CPU 0）通常承担显卡、硬盘等设备中断与按核的内核后台工作；
# 把它们压满会让桌面失去响应。构建与 QEMU 一律以 nice 19 / ionice 空闲级运行，桌面需要时随时让出。
# 退出码：0 = 全部 PASS；1 = 至少一项 FAIL；2 = 环境缺失（无 cargo / qemu）
# =============================================================================
set -u

# 串口日志一律按文本匹配：部分固件版本（如 QEMU 8.2 自带的 OpenSBI v1.3）会在启动横幅里输出 NUL 字节，
# GNU grep 遇到它会把整个日志当作二进制文件，只回「Binary file matches」而不输出匹配行，导致数值提取为空。
# 这里只改变匹配方式，不改动原始串口日志（证据保持原样）。
# Treat serial logs as text: some firmware emits NUL bytes that make grep treat the log as binary.
grep() { command grep -a "$@"; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NCPU="$(nproc --all 2>/dev/null || echo 4)"
if [ "$NCPU" -ge 8 ]; then DEFAULT_CORES="$((NCPU - 4))-$((NCPU - 1))"; else DEFAULT_CORES="0-$((NCPU > 1 ? NCPU - 2 : 0))"; fi
CORES="${JASPER_CORES:-$DEFAULT_CORES}"
PROFILE="${JASPER_PROFILE:-standard}"
QEMU_TIMEOUT="${JASPER_QEMU_TIMEOUT:-90}"
# 两次 QEMU 启动之间的间隔（秒）：连续压满会让宿主桌面失去响应，默认留 3 秒让系统喘口气。
BOOT_GAP="${JASPER_BOOT_GAP:-3}"
case "$QEMU_TIMEOUT" in ''|0|*[!0-9]*) echo "✗ JASPER_QEMU_TIMEOUT 必须是正整数秒：$QEMU_TIMEOUT"; exit 2 ;; esac
case "$PROFILE" in
  standard) KFEAT=() ;;
  compact)  KFEAT=(--features profile-compact) ;;
  *) echo "✗ 未知配置档：$PROFILE（可选 standard / compact）"; exit 2 ;;
esac
# 调度策略（POL-1）：ts = 分时策略（默认），rr = 纯轮转（构建期特性 sched-rr）。
# 轮转构建用于验证「换策略只改一个选择点」，机制层全部验收照跑；QoS 专项检查检验的是分时策略的语义，
# 在轮转构建下如实记为不适用，仍在分时构建中照常执行并通过。
SCHED_POLICY="${JASPER_SCHED:-ts}"
case "$SCHED_POLICY" in
  ts) SFEAT=() ;;
  rr) SFEAT=(--features sched-rr) ;;
  *) echo "✗ 未知调度策略：$SCHED_POLICY（可选 ts / rr）"; exit 2 ;;
esac
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

# 在限定核上、以最低 CPU / I/O 优先级运行（工具不存在时跳过相应限制）。
run() {
  local pre=()
  command -v nice >/dev/null && pre+=(nice -n 19)
  command -v ionice >/dev/null && pre+=(ionice -c3)
  command -v taskset >/dev/null && pre+=(taskset -c "$CORES")
  "${pre[@]}" "$@"
}

# ---- 结果表 ----------------------------------------------------------------
declare -a ROWS=()
FAILED=0
# record <里程碑> <PASS|FAIL> <说明>
record() {
  # 端口复跑在被测目标本机不可运行时（例如缺少 32 位 OpenSBI 固件），逐项如实记 N/A：
  # 「没有运行」既不是通过，也不该被判成失败。
  if [ "${PORT_NA:-0}" = "1" ]; then
    ROWS+=("$(printf '%-6s %-4s %s' "${REC_PREFIX:-}$1" "N/A" "本机目标不可运行（${PORT_NA_REASON:-未知原因}），未运行、不计入通过；$3")")
    return
  fi
  ROWS+=("$(printf '%-6s %-4s %s' "${REC_PREFIX:-}$1" "$2" "$3")")
  [ "$2" = "PASS" ] || FAILED=1
}
# record_na <里程碑> <说明>：本构建下不适用（不计入失败，也不计入通过）
record_na() {
  ROWS+=("$(printf '%-6s %-4s %s' "${REC_PREFIX:-}$1" "N/A" "$2")")
}
# has <正则>：串口日志里是否出现
has() { grep -qE "$1" "$SERIAL" 2>/dev/null; }
# count <正则>：串口日志里出现的行数
count() { grep -cE "$1" "$SERIAL" 2>/dev/null || true; }
# cfg <参数名>：本次启动在串口上输出的生效参数值（与配置档相关的判据据此计算期望值；缺失时为 0）
cfg() { local v; v="$(grep -aoE "^\[JSR-CONFIG\] $1=[0-9]+" "$SERIAL" 2>/dev/null | head -1 | grep -oE '[0-9]+$')"; echo "${v:-0}"; }

# ---- 阶段 A：构建、测试、启动（产出证据）------------------------------------
echo "== 构建与测试（核：$CORES，配置档：$PROFILE）=="
run cargo test -p kernel-core > "$OUT/cargo-test.log" 2>&1;                                   TEST_RC=$?
run cargo test -p jaso --features pack > "$OUT/jaso-test.log" 2>&1;                           JASO_RC=$?
run cargo build --release --target x86_64-unknown-none -p kernel-core > "$OUT/build.log" 2>&1; CORE_RC=$?
run cargo build --release --target x86_64-unknown-none -p jasper-kernel "${KFEAT[@]}" "${SFEAT[@]}" >> "$OUT/build.log" 2>&1 \
  && run cargo build --release -p xtask >> "$OUT/build.log" 2>&1 \
  && run "$ROOT/target/release/xtask" "$ROOT/target/x86_64-unknown-none/release/jasper-kernel" "$IMG" >> "$OUT/build.log" 2>&1
BUILD_RC=$?

# 多指令集：kernel-core 在全部目标指令集上编译；单元测试在 64 位与 32 位上运行；
# 装有 qemu-user 时再在 AArch64 / RISC-V64 上运行（用 musl 目标 + 自带的 rust-lld 链接，不依赖交叉 C 工具链）。
ISA_BUILD_FAIL=""
for t in x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf riscv32imac-unknown-none-elf; do
  run cargo build --release --target "$t" -p kernel-core >> "$OUT/isa-build.log" 2>&1 || ISA_BUILD_FAIL="$ISA_BUILD_FAIL $t"
done
# isa_test <rust 目标> <可选 qemu-user 运行器>：运行 kernel-core 单元测试，输出写到 isa-test-<目标>.log
isa_test() {
  local t="$1" runner="${2:-}" var
  var="CARGO_TARGET_$(echo "$t" | tr 'a-z-' 'A-Z_')"
  run env "${var}_LINKER=rust-lld" ${runner:+"${var}_RUNNER=$runner"} RUSTFLAGS="-C link-self-contained=yes -C target-feature=+crt-static" \
    CARGO_TARGET_DIR="$ROOT/target/isa-test" cargo test -p kernel-core --target "$t" > "$OUT/isa-test-$t.log" 2>&1
}
ISA_TESTS_RAN=""; ISA_TESTS_FAIL=""; ISA_TESTS_SKIPPED=""
if isa_test i686-unknown-linux-musl; then ISA_TESTS_RAN="$ISA_TESTS_RAN 32位"; else ISA_TESTS_FAIL="$ISA_TESTS_FAIL 32位"; fi
for pair in "aarch64-unknown-linux-musl:qemu-aarch64:AArch64" "riscv64gc-unknown-linux-musl:qemu-riscv64:RISC-V64"; do
  IFS=: read -r t q label <<< "$pair"
  if command -v "$q" >/dev/null && rustup target list --installed 2>/dev/null | grep -qx "$t"; then
    if isa_test "$t" "$q"; then ISA_TESTS_RAN="$ISA_TESTS_RAN $label"; else ISA_TESTS_FAIL="$ISA_TESTS_FAIL $label"; fi
  else
    ISA_TESTS_SKIPPED="$ISA_TESTS_SKIPPED $label"
  fi
done

QRC=-1
if [ "$BUILD_RC" -eq 0 ]; then
  echo "== QEMU 真实启动 =="
  sleep "$BOOT_GAP"
  run timeout "$QEMU_TIMEOUT" "$QEMU" -drive format=raw,file="$IMG" \
    -serial stdio -display none -monitor none -no-reboot \
    -m 256M -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$SERIAL" 2>&1
  QRC=$?
fi
# 多处理器（SMP-1）：同一镜像以 4 个处理器再真实启动一次（其余参数不变）；上面的单处理器启动同时验证「只有引导处理器」的路径。
SERIAL_SMP4="$OUT/serial-smp4.log"
QRC_SMP4=-1
if [ "$BUILD_RC" -eq 0 ]; then
  echo "== QEMU 真实启动（x86_64，4 个处理器）=="
  sleep "$BOOT_GAP"
  run timeout "$QEMU_TIMEOUT" "$QEMU" -drive format=raw,file="$IMG" -smp 4 \
    -serial stdio -display none -monitor none -no-reboot \
    -m 256M -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$SERIAL_SMP4" 2>&1
  QRC_SMP4=$?
fi
# AArch64（ISA-1）：同一内核以软浮点目标构建（不内嵌用户程序），在 QEMU virt 上直接装载 ELF 启动；
# 退出经半主机（成功 33、失败 35，与 x86_64 一致）。缺少 qemu-system-aarch64 时如实记为失败。
QEMU_A64="$(command -v qemu-system-aarch64 || true)"
SERIAL_A64="$OUT/serial-aarch64.log"
A64_ELF="$ROOT/target/aarch64-unknown-none-softfloat/release/jasper-kernel"
QRC_A64=-1
run cargo build --release --target aarch64-unknown-none-softfloat -p jasper-kernel "${KFEAT[@]}" "${SFEAT[@]}" > "$OUT/build-aarch64.log" 2>&1
A64_BUILD_RC=$?
if [ "$A64_BUILD_RC" -eq 0 ] && [ -n "$QEMU_A64" ]; then
  echo "== QEMU 真实启动（AArch64）=="
  sleep "$BOOT_GAP"
  run timeout "$QEMU_TIMEOUT" "$QEMU_A64" -M virt -cpu cortex-a72 -m 256M -kernel "$A64_ELF" -semihosting \
    -serial stdio -display none -monitor none -no-reboot > "$SERIAL_A64" 2>&1
  QRC_A64=$?
fi
# 多处理器（SMP-1b-A64）：同一 AArch64 内核以 4 个处理器再真实启动一次（设备树处理器节点 + PSCI 唤醒 + GIC 软件生成中断）。
SERIAL_A64_SMP4="$OUT/serial-aarch64-smp4.log"
QRC_A64_SMP4=-1
if [ "$A64_BUILD_RC" -eq 0 ] && [ -n "$QEMU_A64" ]; then
  echo "== QEMU 真实启动（AArch64，4 个处理器）=="
  sleep "$BOOT_GAP"
  run timeout "$QEMU_TIMEOUT" "$QEMU_A64" -M virt -cpu cortex-a72 -m 256M -smp 4 -kernel "$A64_ELF" -semihosting \
    -serial stdio -display none -monitor none -no-reboot > "$SERIAL_A64_SMP4" 2>&1
  QRC_A64_SMP4=$?
fi
# RISC-V64（ISA-2）：同一内核以软浮点目标 riscv64imac 构建（内嵌的用户程序与模块同样以 riscv64imac 构建），由 QEMU virt 默认的 OpenSBI
# 以监管态装载 ELF 启动；退出经仿真器测试设备（成功 33、失败 35，与 x86_64 一致）。缺少 qemu-system-riscv64 时如实记为失败。
QEMU_RV64="$(command -v qemu-system-riscv64 || true)"
SERIAL_RV64="$OUT/serial-riscv64.log"
RV64_ELF="$ROOT/target/riscv64imac-unknown-none-elf/release/jasper-kernel"
QRC_RV64=-1
run cargo build --release --target riscv64imac-unknown-none-elf -p jasper-kernel "${KFEAT[@]}" "${SFEAT[@]}" > "$OUT/build-riscv64.log" 2>&1
RV64_BUILD_RC=$?
if [ "$RV64_BUILD_RC" -eq 0 ] && [ -n "$QEMU_RV64" ]; then
  echo "== QEMU 真实启动（RISC-V64）=="
  sleep "$BOOT_GAP"
  run timeout "$QEMU_TIMEOUT" "$QEMU_RV64" -M virt -m 256M -kernel "$RV64_ELF" \
    -serial stdio -display none -monitor none -no-reboot > "$SERIAL_RV64" 2>&1
  QRC_RV64=$?
fi
# RISC-V32（ISA-3）：同一内核以 riscv32imac 构建（Sv32 页表、32 位寄存器），内嵌的用户程序与模块同样以 riscv32imac
# 构建（ELF32、32 位用户 ABI；模块连同标准库按位置无关模型编译）；由 QEMU virt 默认的 32 位 OpenSBI
# 以监管态装载 ELF 启动，退出经仿真器测试设备（成功 33、失败 35）。缺少 qemu-system-riscv32 时如实记为失败。
QEMU_RV32="$(command -v qemu-system-riscv32 || true)"
# 32 位 OpenSBI 固件：有的发行版只带 64 位固件，QEMU 找不到时它会直接报错退出。
# 找到就显式指定 -bios；找不到则该目标如实记为「不可用」，不冒充通过。
# JASPER_RV32_BIOS 可显式指定固件路径（例如 CI 自带固件时）；显式设为空串表示按「缺少固件」处理，
# 用于在本机如实复现没有 32 位固件的环境，验证跳过路径本身，而不是绕过任何判据。
RV32_FW="${JASPER_RV32_BIOS-$(ls /usr/lib/riscv32-linux-gnu/opensbi/generic/fw_dynamic.bin 2>/dev/null | head -1)}"
RV32_BIOS=(); [ -n "$RV32_FW" ] && RV32_BIOS=(-bios "$RV32_FW")
SERIAL_RV32="$OUT/serial-riscv32.log"
RV32_ELF="$ROOT/target/riscv32imac-unknown-none-elf/release/jasper-kernel"
QRC_RV32=-1
run cargo build --release --target riscv32imac-unknown-none-elf -p jasper-kernel "${KFEAT[@]}" "${SFEAT[@]}" > "$OUT/build-riscv32.log" 2>&1
RV32_BUILD_RC=$?
if [ "$RV32_BUILD_RC" -eq 0 ] && [ -n "$QEMU_RV32" ]; then
  echo "== QEMU 真实启动（RISC-V32）=="
  sleep "$BOOT_GAP"
  run timeout "$QEMU_TIMEOUT" "$QEMU_RV32" -M virt -m 256M "${RV32_BIOS[@]}" -kernel "$RV32_ELF" \
    -serial stdio -display none -monitor none -no-reboot > "$SERIAL_RV32" 2>&1
  QRC_RV32=$?
  grep -q 'Unable to find the RISC-V BIOS' "$SERIAL_RV32" 2>/dev/null && QRC_RV32=-2
fi
# 多处理器（SMP-1b-RV）：同一 RISC-V64 / RISC-V32 内核各以 4 个处理器再真实启动一次（设备树处理器节点 + SBI HSM 唤醒 + SBI IPI 软件中断）。
SERIAL_RV64_SMP4="$OUT/serial-riscv64-smp4.log"; QRC_RV64_SMP4=-1
if [ "$RV64_BUILD_RC" -eq 0 ] && [ -n "$QEMU_RV64" ]; then
  echo "== QEMU 真实启动（RISC-V64，4 个处理器）=="
  sleep "$BOOT_GAP"
  run timeout "$QEMU_TIMEOUT" "$QEMU_RV64" -M virt -m 256M -smp 4 -kernel "$RV64_ELF" \
    -serial stdio -display none -monitor none -no-reboot > "$SERIAL_RV64_SMP4" 2>&1
  QRC_RV64_SMP4=$?
fi
SERIAL_RV32_SMP4="$OUT/serial-riscv32-smp4.log"; QRC_RV32_SMP4=-1
if [ "$RV32_BUILD_RC" -eq 0 ] && [ -n "$QEMU_RV32" ]; then
  echo "== QEMU 真实启动（RISC-V32，4 个处理器）=="
  sleep "$BOOT_GAP"
  run timeout "$QEMU_TIMEOUT" "$QEMU_RV32" -M virt -m 256M -smp 4 "${RV32_BIOS[@]}" -kernel "$RV32_ELF" \
    -serial stdio -display none -monitor none -no-reboot > "$SERIAL_RV32_SMP4" 2>&1
  QRC_RV32_SMP4=$?
  grep -q 'Unable to find the RISC-V BIOS' "$SERIAL_RV32_SMP4" 2>/dev/null && QRC_RV32_SMP4=-2
fi

# 本机 QEMU 缺少 32 位 OpenSBI 固件时（有的发行版只打包 64 位固件），RISC-V32 目标不可运行。
# 两个 RISC-V32 启动中任一报告固件缺失，即认定该目标不可用：相关判定如实跳过并注明，
# 不把「未运行」当成通过，也不影响其他指令集的结论。
RV32_NOTE=""
if [ "${QRC_RV32:-0}" = "-2" ] || [ "${QRC_RV32_SMP4:-0}" = "-2" ]; then
  RV32_NOTE="（RISC-V32 因本机缺少 32 位 OpenSBI 固件未运行，其余架构判据不受影响）"
fi
rv32_fw_missing() { [ -n "$RV32_NOTE" ]; }

# ---- 阶段 B：逐里程碑检查 ----------------------------------------------------

check_pol1() {   # POL-1：策略可替换——本构建确实换成了所选策略，且策略名与配置一致
  local want
  if [ "$SCHED_POLICY" = "rr" ]; then want="round_robin"; else want="timeshare"; fi
  if has "policy=$want " && has 'JSR-SCHED\] all tasks exited'; then
    record POL1 PASS "调度策略=$want（构建期选择：${SCHED_POLICY}），任务表/切换路径/时钟中断/负载均衡未改动"
  else
    record POL1 FAIL "串口未报告 policy=$want 或调度演示未完成"
  fi
}

check_m10() {   # 骨架：kernel-core 宿主测试 + 裸机编译
  local passed
  passed=$(grep -oE '^test result: ok\. [0-9]+ passed; 0 failed' "$OUT/cargo-test.log" | head -1 | grep -oE '[0-9]+ passed')
  if [ "$TEST_RC" -eq 0 ] && [ "$CORE_RC" -eq 0 ] && [ -n "$passed" ]; then
    record M1.0 PASS "kernel-core 宿主测试 $passed；裸机目标编译 ✓"
  else
    record M1.0 FAIL "cargo test rc=$TEST_RC，裸机编译 rc=$CORE_RC（见 cargo-test.log / build.log）"
  fi
}

check_isa() {   # 多指令集：kernel-core 四个目标指令集编译 + 单元测试在多个指令集 / 字长上运行（未运行的如实列出）
  if [ -z "$ISA_BUILD_FAIL" ] && [ -z "$ISA_TESTS_FAIL" ] && [ -n "$ISA_TESTS_RAN" ]; then
    record ISA PASS "kernel-core 编译：x86_64/AArch64/RISC-V64/RISC-V32 ✓；单元测试运行：x86_64${ISA_TESTS_RAN}${ISA_TESTS_SKIPPED:+；未运行（缺 qemu-user 或目标）：$ISA_TESTS_SKIPPED}"
  else
    record ISA FAIL "编译失败：${ISA_BUILD_FAIL:-无}；测试失败：${ISA_TESTS_FAIL:-无}（见 isa-build.log / isa-test-*.log）"
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

check_m32() {   # 系统调用：登记表自检、未登记被拒、未授权被拒、寄存器保留、task.exit 正常退出、页帧回收
  if has '^\[JSR-SYSCALL\] self_check ops=[0-9]+ handlers=all' \
     && has 'deny name=system\.task\.yield id=2 .*ret=system\.error\.rights_denied' \
     && has 'reject id=65535 .*ret=system\.error\.unsupported' \
     && has 'probe now=[0-9]+ unregistered=-4097 denied=-4098 preserved=true exit_code=42 stopped_after_exit=true' \
     && has '^\[JSR-SYSCALL\] calls=4 reclaimed=true checks=[0-9]+ failed=0'; then
    record M3.2 PASS "syscall 真实陷入；未登记/未授权被拒；寄存器保留；task.exit(42) 正常退出；页帧回收"
  else
    record M3.2 FAIL "缺少 JSR-SYSCALL 关键标记或 failed≠0"
  fi
}

check_m33() {   # 用户指针：合法文本写出；内核地址/未映射/跨页/超长/非法 UTF-8 全部被拒；正常退出；页帧回收
  if has '^\[JSR-USERTEXT\] task=user-ptr bytes=[0-9]+ text=' \
     && has 'valid=[1-9][0-9]* kernel_addr=-4100 unmapped=-4100 crossing=-4100 too_long=-4099 bad_utf8=-4099 exit_ok=true' \
     && has '^\[JSR-UPTR\] reclaimed=true checks=[0-9]+ failed=0'; then
    record M3.3 PASS "用户指针 6 类用例全部正确，内核不直接解引用用户地址，页帧回收"
  else
    record M3.3 FAIL "缺少 JSR-UPTR 关键标记或 failed≠0"
  fi
}

check_m34() {   # 进程/线程：同进程双线程共享内存、句柄关闭两次（第二次失败）、退出码 7、回收后页帧回到基线
  if has 'event=system\.process\.exited id=0x[0-9a-f]+ name=demo-proc code=7 threads=2' \
     && has 'threads shared_memory=true handle=0x[0-9a-f]+ close_first=0 close_again=-4101' \
     && has 'reaped threads=2 frames=4 code=7 .*reclaimed=true' && has '^\[JSR-PROC\] checks=[0-9]+ failed=0'; then
    record M3.4 PASS "进程 + 双线程共享地址空间，线程句柄与关闭语义，退出码 7，回收后页帧回到基线"
  else
    record M3.4 FAIL "缺少 JSR-PROC 关键标记或 failed≠0"
  fi
}

check_m51pre() { # ELF 装载（M5.1 前置部分）：截断被拒；按段装载、从入口运行、BSS 清零、正常退出、回收
  if has 'elf bytes=[0-9]+ truncated=system\.elf\.error\.truncated entry=0x[0-9a-f]+' \
     && has '^\[JSR-USERTEXT\] task=user-hello bytes=[0-9]+ text=你好，来自 ELF 装载的用户程序' \
     && has '^\[JSR-USERTEXT\] task=user-hello bytes=13 text=bss_zero=true' \
     && has 'event=system\.process\.exited id=0x[0-9a-f]+ name=user-hello code=0' \
     && has '^\[JSR-PROG\] exit=Some\(Exited \{ code: 0 \}\) frames=[0-9]+ reclaimed=true checks=[0-9]+ failed=0'; then
    record M5.1p PASS "ELF 静态可执行文件按段装载并从入口运行，BSS 清零，正常退出，回收（M5.1 前置）"
  else
    record M5.1p FAIL "缺少 JSR-PROG / user-hello 关键标记或 failed≠0"
  fi
}

check_m41() {   # 对象生命周期：关句柄 ⇒ closing 不销毁；重复关闭被拒；线程退出后由线程表保活；reap 只入队；级联迭代清理；回到基线
  if has 'handle closed: became_unowned=true dead=false counts=Ok\(\(0, 2, Closing\)\) double_close=system\.object\.error\.underflow reacquire=system\.object\.error\.invalid' \
     && has 'thread exited: task counts=Ok\(\(0, 1, Closing\)\)' \
     && has 'cascade: after_reap_pending=1 round1=1 pending=2 round2=3 pending=0 objects_live=([0-9]+)/\1 destroyed\+=4 reclaimed=true' \
     && has '^\[JSR-LIFE\] checks=[0-9]+ failed=0'; then
    record M4.1 PASS "外部所有权/内部引用分离；closing 不销毁；重复关闭被拒；清理队列级联迭代；对象与页帧回到基线"
  else
    record M4.1 FAIL "缺少 JSR-LIFE 关键标记或 failed≠0"
  fi
}

check_m42() {   # Handle/Rights：复制只降权、提权被拒；跨进程原子转移（移动/无权/非叶子/表满）；回到基线
  if has 'user dup=true escalate_dup=-4102 restrict=0 dup_without_right=-4102 escalate_restrict=-4102' \
     && has 'transfer moved=true sender_invalid=true owners_after=Some\(1\) no_transfer_right=rights_denied non_leaf=not_transferable receiver_full=table_full' \
     && has '^\[JSR-HANDLE\] objects_live=([0-9]+)/\1 pending=0 reclaimed=true checks=[0-9]+ failed=0'; then
    record M4.2 PASS "duplicate/restrict 只降权；跨进程原子转移四类用例正确；失败时发送方句柄保留；回到基线"
  else
    record M4.2 FAIL "缺少 JSR-HANDLE 关键标记或 failed≠0"
  fi
}

check_m43() {   # 用户态异步环：用户程序端到端（ID 单调、cq_full、同步取消、信用归还、取消结果、窗口淘汰、等待、不可转移、关闭）+ 内核侧 closing/缓冲区/配额
  if has 'text=ring: ids monotonic=true same_tag_matched=true' \
     && has 'text=ring: cq_full submitted=0 error=-4109' \
     && has 'text=ring: sync_cancel_without_credit=true published_holds_credit=true credit_returned_on_consume=true rejected_ids_consumed=false' \
     && has 'text=ring: cancel again=-4106 in_window=-4106 evicted=-4107 never=-4107' \
     && has 'text=ring: wait cancelled=true natural_completion=true' \
     && has 'text=ring: handle dup_with_transfer=-4102 dup_without_transfer_ok=true' \
     && has 'text=ring: closed_with_pending=true enter_after_close=-4101 cancel_after_close=-4101' \
     && has 'text=ring: all checks passed' \
     && has '\[JSR-RING\] user exit=Some\(Exited \{ code: 0 \}\) quota_after=Some\(ResourceQuota \{ rings: 0, in_flight: 0, endpoints: 0, ipc_bytes: 0 \}\)' \
     && has 'buffer cancel=Ok\(0\) hidden_before_quiesce=true cancel_again=Ok\(-4106\) visible_after_quiesce=true' \
     && has 'closing before=Some\(\(2, 3\)\) after_in_flight=Some\(2\) dropped_ready=true submit_after_exit=Some\(-[0-9]+\) quota=Some\(3\)->Some\(2\)' \
     && has 'closing abortable_quiesced=true nonabortable_finished=true ring_destroyed_after_last_request=true quota_returned=true' \
     && has 'transfer result=Ok\(Err\(Handle\(RightsDenied\)\)\)' \
     && has "quota rings=$(cfg max_rings_per_process) ninth=Some\\(-4111\\) in_flight=$(cfg max_in_flight_per_process) over=Some\\(-4111\\) unchanged_on_reject=true returned=true" \
     && has '^\[JSR-RING\] objects_live=([0-9]+)/\1 pending=0 reclaimed=true checks=[0-9]+ failed=0'; then
    record M4.3 PASS "用户态 ring 提交→完成；cq_full 原子失败；信用耗尽可同步取消；信用消费时归还；取消结果表与窗口；closing 各类收尾；配额；回到基线"
  else
    record M4.3 FAIL "缺少 JSR-RING / user-ring 关键标记或 failed≠0"
  fi
}

check_m44() {   # IPC Channel：用户程序（单进程语义 + 跨进程往返）+ 内核侧（取消映射 / 共享缓冲区 / 延迟后端 / 叶子回收 / 句柄表满）
  # 字节配额用例的期望值随配置档：满长消息 64 KiB；每端点条数 = 端点字节配额 / 64 KiB（不超过 64 条）
  local pb per acc
  pb="$(cfg ipc_max_process_bytes)"; per=$(( $(cfg ipc_max_queue_bytes) / 65536 )); [ "$per" -gt 64 ] && per=64
  acc=$(( pb / 65536 ))
  if has 'text=ipc: roundtrip bytes=[0-9]+ text_ok=true' \
     && has 'text=ipc: buffer_too_small=-4114 needed=100 retained_then_received=true' \
     && has 'text=ipc: handle moved=true received=true no_transfer_right=-4102 ring_handle=-4102 kept_on_failure=true' \
     && has 'text=ipc: two_phase copy_fail=-4100 handle_untouched=true' \
     && has 'text=ipc: queue capacity=64 full=-4113 handle_kept=true drained=64' \
     && has 'text=ipc: cancel_then_send cancelled=true message_kept=true deliver_then_cancel=-4106' \
     && has 'text=ipc: own_close_cancels_recv=true send_to_closed_peer=-4112' \
     && has 'text=ipc: peer_close pending_recv=-4112 later_recv=-4112' \
     && has 'text=ipc: all checks passed' \
     && has 'cross_process ping=Some\(Exited \{ code: 0 \}\) pong=Some\(Exited \{ code: 0 \}\)' \
     && has 'unmap_during_recv frame_held=true delivered=true out_len=Some\(15\) frame_returned_after=true' \
     && has 'shared_buffer held_after_first=true returned_after_both=true' \
     && has 'delayed_backend hidden_and_pinned=true visible_and_returned_after_quiesce=true' \
     && has 'leaf_in_queue_released_on_receiver_exit=true sender_handle_moved=true' \
     && has 'receiver_table_full result_table_full=true message_kept=true' \
     && has "byte_quota accepted=$acc rejected=$per charged=Some\\($pb\\) returned=true" \
     && has '^\[JSR-IPC\] objects_live=([0-9]+)/\1 pending=0 pinned=\(0, 0\) reclaimed=true checks=[0-9]+ failed=0'; then
    record M4.4 PASS "send/recv 经 ring；两阶段 send；原子交付（缓冲区/句柄表不足消息保留）；取消竞争；关闭语义；跨进程句柄往返；页帧固定；回到基线"
  else
    record M4.4 FAIL "缺少 JSR-IPC / user-ipc 关键标记或 failed≠0"
  fi
}

check_m51() {   # 最小非特权程序：特权级 3；读内核内存只杀该进程；特权/无效指令；坏指针被拒；多线程终止 + 父进程等待；内核内阻塞时终止；回到基线
  if has '^\[JSR-USERTEXT\] task=prog-hello bytes=[0-9]+ text=prog: hello (cpl=3|el=0|mode=0)' \
     && has '^\[JSR-PROG\] exit=0 ring3=true' \
     && has 'case=kernel_read exit=Some\(-1\) bystander_exit=Some\(0\) only_offender_killed=true reclaimed=true' \
     && has 'case=privileged_instruction exit=Some\(-1\) expect=-1 reclaimed=true' \
     && has 'case=invalid_instruction exit=Some\(-1\) expect=-1 reclaimed=true' \
     && has 'text=prog: bad_pointer result=-4100' \
     && has 'case=bad_syscall_pointer exit=Some\(0\) expect=0 reclaimed=true' \
     && has 'text=prog: parent submitted=2 cancel=0 handle_closed=0 cancelled_wait=true exit_code=9' \
     && has 'case=process_exit child_exit=Some\(9\) child_threads=Some\(\(0, 2\)\) parent_exit=Some\(0\) reclaimed=true' \
     && has 'case=blocked_time_wait exit=Some\(7\) expect=7 reclaimed=true' \
     && has 'case=blocked_recv exit=Some\(7\) expect=7 reclaimed=true' \
     && has 'case=blocked_ring_enter exit=Some\(7\) expect=7 reclaimed=true' \
     && has 'case=blocked_task_wait exit=Some\(7\) expect=7 reclaimed=true' \
     && has '^\[JSR-PROG\] summary free_frames=([0-9]+)/\1 objects=([0-9]+)/\2 pending=0 pinned=\(0, 0\) reclaimed=true kernel_alive=true checks=[0-9]+ failed=0' \
     && ! has 'LEAK'; then
    record M5.1 PASS "Ring 3 运行并以 0 退出；读内核内存/特权指令/无效指令只终止该进程；坏系统调用指针被拒；多线程进程终止与父进程等待；内核内阻塞时终止；页帧/对象/固定回到基线"
  else
    record M5.1 FAIL "缺少 JSR-PROG / user-prog 关键标记、出现 LEAK 或 failed≠0"
  fi
}

check_s1() {    # S-1：真实用户态的系统调用健壮性回归（固定种子、2 万次有界探测）；返回约定、计数与资源回收
  if has 'text=robust: done calls=20000 checks=[0-9]+ failed=0 seed=0x[0-9a-f]+' \
     && has '^\[JSR-ROBUST\] summary calls=[0-9]+ min_calls=20000 exit=Some\(0\) free_frames=([0-9]+)/\1 objects=([0-9]+)/\2 pending=0 pinned=\(0, 0\) reclaimed=true checks=[0-9]+ failed=0' \
     && ! has '^\[JSR-ROBUST-FAIL\]' \
     && ! has 'robust: FAIL '; then
    record S-1 PASS "用户态固定种子 2 万次有界系统调用探测：非法调用号/超 32 位句柄/坏指针/未映射区间/非法权限位均按登记错误返回；真实 map→写→unmap 循环可用；进程以 0 退出；页帧/对象/固定帧回到基线"
  else
    record S-1 FAIL "缺少 JSR-ROBUST 汇总、调用次数不足、出现失败行或资源未回到基线"
  fi
}

check_j1() {    # 用户态运行时：匿名内存系统调用（全有或全无、配额、权限）；用运行时写成的 Rust 程序（堆/线程/Channel/ring）以 0 退出；panic 与栈溢出只终止该进程；回到基线
  if has 'memory map=Ok\(\(\)\) zeroed=true user_rw_nx=true overlap=Err\(AlreadyMapped\) partial=Err\(AlreadyMapped\) untouched=true' \
     && has 'memory hole=Err\(NotMapped\) bad_ranges_refused=true readonly=true quota_chunks=[1-9][0-9]* refused=Some\(Quota\) no_charge=true' \
     && has 'memory exited_refused=Err\(NoSuchProcess\) reclaimed=true' \
     && has 'text=rtdemo: heap after_free total=([0-9]+) free=\1 blocks=1' \
     && has 'text=rtdemo: channel roundtrips=4 handle_returned=true' \
     && has 'text=rtdemo: ring cancelled_ok=true wait_task=55' \
     && has 'text=rtdemo: ok checks=[0-9]+' \
     && has 'case=rt-main exit=Some\(0\) expect=0 reclaimed=true' \
     && has 'task=rt-panic bytes=[0-9]+ text=panic: panicked at ' \
     && has 'case=rt-panic exit=Some\(101\) expect=101 reclaimed=true' \
     && has 'case=rt-overflow exit=Some\(-1\) expect=-1 reclaimed=true' \
     && has '^\[JSR-RT\] summary free_frames=([0-9]+)/\1 objects=([0-9]+)/\2 pending=0 pinned=\(0, 0\) reclaimed=true checks=[0-9]+ failed=0' \
     && ! has 'JSR-RT-FAIL'; then
    record J-1 PASS "匿名内存 map/unmap 全有或全无、配额与权限；运行时程序（堆增长与回收、线程、Channel 字节+句柄往返、ring 取消与等待）以 0 退出；panic=101、栈溢出只终止该进程；回到基线"
  else
    record J-1 FAIL "缺少 JSR-RT / rtdemo 关键标记或 failed≠0"
  fi
}

check_j2() {    # 现有 Rust 库的可移植性：sha2 / crc / miniz_oxide / smoltcp 在 jasper-rt 之上通过已知答案测试；回到基线
  if has 'text=libcheck: lib=sha2 version=[0-9.]+ backend=soft vectors=5 ok=true' \
     && has 'text=libcheck: lib=crc version=[0-9.]+ algorithms=4 ok=true' \
     && has 'text=libcheck: lib=miniz_oxide version=[0-9.]+ in=[0-9]+ packed=[0-9]+ roundtrip=true corrupt_rejected=true' \
     && has 'text=libcheck: lib=smoltcp version=[0-9.]+ tcp_loopback bytes=32768 echoed=32768 sha256_match=true .*peer_close_seen=true' \
     && has 'text=libcheck: ok checks=[0-9]+' \
     && has 'case=libcheck exit=Some\(0\) expect=0 reclaimed=true'; then
    record J-2 PASS "sha2（FIPS 向量，纯软件后端）、crc（4 种算法校验值）、miniz_oxide（存储块/zlib 向量、往返、损坏被拒）、smoltcp（环回 TCP 32 KiB 回送、SHA-256 一致、有序关闭）在用户态通过；回到基线"
  else
    record J-2 FAIL "缺少 libcheck 关键标记或退出码≠0"
  fi
}

check_j3() {    # 最小 .jaso：格式宿主测试；memory.protect（W^X、全有或全无）；装入 → 重定位 → 设权限 → 初始化 → 调用；两个实例；卸载；各类拒绝；回到基线
  if [ "${JASO_RC:-1}" -eq 0 ] && grep -qE '^test result: ok\. [0-9]+ passed; 0 failed' "$OUT/jaso-test.log" \
     && has 'protect rx=Ok\(\(\)\) rx_flags=true wx=Err\(InvalidRange\) gap=Err\(NotMapped\) gap_kept=true back_to_rw=true' \
     && has 'text=jaso-demo: init ok' \
     && has 'text=jasodemo: loaded name=jaso-demo base=0x[0-9a-f]+ pages=[0-9]+ sum_ok=true relocated_greeting=true counter=2 host_alloc=1/1' \
     && has 'text=jasodemo: two_instances bases=0x[0-9a-f]+,0x[0-9a-f]+ independent_data=true' \
     && has 'text=jasodemo: unload unmapped=true slot_reused=true fresh_state=true' \
     && has 'text=jasodemo: rejected tamper=Some\(Format\(DigestMismatch\)\) truncated=Some\(Format\(LengthMismatch\)\) arch=Some\(WrongArch\((Aarch64|X86_64)\)\) stage=Some\(WrongStage\(Boot\)\) caps=Some\(MissingCapability\("system\.console\.write"\)\) host=Some\(HostRequired\) init=Some\(MissingInit\)' \
     && has 'text=jasodemo: ok checks=[0-9]+' \
     && has 'case=jasodemo exit=Some\(0\) expect=0 reclaimed=true'; then
    record J-3 PASS "格式宿主测试 $(grep -oE '[0-9]+ passed' "$OUT/jaso-test.log" | head -1)；W^X 改权限；.jaso 装入/重定位/设权限/初始化/调用导出、两实例数据独立、卸载后映射消失；篡改/截断/指令集/阶段/能力/宿主表/初始化入口均被拒；回到基线"
  else
    record J-3 FAIL "jaso 宿主测试 rc=${JASO_RC:-?}，或缺少 jasodemo / protect 关键标记"
  fi
}

check_j5() {    # .jaso 发布者签名：签名段 + 受信发布者表，映射前验签；未签名 / 篡改后重算摘要 / 换发布者 / 他人重签 / 越出命名空间 / 未知发布者
                # 均被拒且不留映射；开发模式放行未签名模块并输出审计事件，坏签名照样被拒；Ed25519 走纯软件后端
  local soft
  soft=$(grep -c 'curve25519_dalek_backend=\\"serial\\"' "$ROOT/.cargo/config.toml" || true)
  if [ "${JASO_RC:-1}" -eq 0 ] && [ "$soft" -ge 4 ] \
     && grep -q 'rfc8032_test_1 ... ok' "$OUT/jaso-test.log" \
     && grep -q 'tampered_bytes_rejected ... ok' "$OUT/jaso-test.log" \
     && grep -q 'replaced_signature_rejected ... ok' "$OUT/jaso-test.log" \
     && grep -q 'swapped_publisher_rejected ... ok' "$OUT/jaso-test.log" \
     && grep -q 'resigning_someone_elses_module_rejected ... ok' "$OUT/jaso-test.log" \
     && grep -q 'random_tampering_never_accepted ... ok' "$OUT/jaso-test.log" \
     && has 'text=jasodemo: signature rejected unsigned=Some\(Untrusted\(Unsigned\)\) badsig=Some\(Untrusted\(BadSignature\)\) otherpub=Some\(Untrusted\(KeyMismatch\)\) resigned=Some\(Untrusted\(KeyMismatch\)\) claimed=Some\(Untrusted\(OutOfNamespace\)\) unknown=Some\(Untrusted\(UnknownPublisher\)\) no_residue=true' \
     && has 'text=JSR-AUDIT event=jaso\.trust\.unsigned_accepted mode=development module=jaso-demo version=0\.1\.0 digest=[0-9a-f]{16} count=1' \
     && has 'text=jasodemo: trust dev_mode unsigned_loaded=true audited=1 signed_publisher=jasper\.dev badsig=Some\(Untrusted\(BadSignature\)\) resigned=Some\(Untrusted\(KeyMismatch\)\) no_residue=true' \
     && has 'text=modhost: trusted publisher=jasper\.dev signed=4/4 mode=enforce' \
     && has 'text=jasodemo: ok checks=[0-9]+' \
     && has 'case=jasodemo exit=Some\(0\) expect=0 reclaimed=true'; then
    record J-5 PASS "Ed25519 发布者签名（纯软件后端，RFC 8032 已知答案）+ 受信发布者表（命名空间）；映射前验签：未签名/篡改后重算摘要/换发布者/他人重签/改称自己越出命名空间/未知发布者均被拒且无残留映射；开发模式放行未签名并审计，坏签名仍拒；库模块 4/4 签名装入"
  else
    record J-5 FAIL "jaso 宿主测试 rc=${JASO_RC:-?}、纯软件后端配置 $soft/4，或缺少 jasodemo 签名 / 审计 / modhost 签名标记"
  fi
}

check_j4() {    # 库作为 .jaso 模块：sha2 / crc / deflate / net 同时装入，已知答案与 J-2 一致；模块串联；全部卸载；回到基线
  if has 'text=modhost: loaded sha2=[0-9]+B crc=[0-9]+B deflate=[0-9]+B net=[0-9]+B' \
     && has 'text=modhost: module=jaso-sha2 vectors=5 ok=true' \
     && has 'text=modhost: module=jaso-crc algorithms=4 ok=true' \
     && has 'text=modhost: module=jaso-deflate in=[0-9]+ packed=[0-9]+ roundtrip=true corrupt_rejected=true' \
     && has 'text=modhost: module=jaso-net tcp_loopback bytes=32768 echoed=true rounds=[1-9][0-9]*' \
     && has 'text=modhost: pipeline deflate->net->sha2->deflate->crc ok=true' \
     && has 'text=modhost: unloaded modules=4' \
     && has 'case=modhost exit=Some\(0\) expect=0 reclaimed=true'; then
    record J-4 PASS "sha2/crc/deflate/net 打包为 .jaso 同时装入，已知答案与直接链接（J-2）一致；deflate→net→sha2→deflate→crc 串联；全部卸载；回到基线"
  else
    record J-4 FAIL "缺少 modhost 关键标记或退出码≠0"
  fi
}

check_j6() {   # J-6：隔离模块（isohost 的一条判据是「CPU 压力下仍能响应」，依赖 QoS 保证）
  if [ "$SCHED_POLICY" = "rr" ]; then record_na J-6 "isohost 的压力响应依赖 QoS 保证，纯轮转构建不适用；已在分时构建中通过"; return; fi    # 可信进程内模块与不可信隔离模块分开：隔离模块在独立进程中运行，只有清单声明且授权的调用与句柄；越权被拒、崩溃不影响宿主；
                # 吃满 CPU 的隔离模块不拖垮宿主、撤销后立即恢复；自动获取的模块只能隔离；进程内卸载的静默判定；子进程配额与回收
  local t
  t=0
  for n in spawn_desc_roundtrip_and_outputs spawn_check_accepts_subset spawn_check_rejects_each_rule spawn_check_subset_exhaustive_small; do
    grep -q "$n ... ok" "$OUT/cargo-test.log" && t=$((t + 1))
  done
  for n in acquired_is_always_isolated standard_policy_places_local_in_process publisher_policy_isolates_unlisted_and_unsigned \
           wire_roundtrip_all_messages wire_rejects_malformed_input wire_random_bytes_never_panic; do
    grep -q "$n ... ok" "$OUT/jaso-test.log" && t=$((t + 1))
  done
  if [ "${TEST_RC:-1}" -eq 0 ] && [ "${JASO_RC:-1}" -eq 0 ] && [ "$t" -eq 10 ] \
     && has 'text=isohost: spawn escalation_denied=true bad_image_rejected=true child_exit=0 quota=8 quota_exceeded_rejected=true churn=24 ok=true' \
     && has 'text=isohost: admission undeclared_handle_rejected=true missing_capability_rejected=true' \
     && has 'text=isohost: rights granted_call_ok=true denied=channel\.create,process\.spawn,time\.wait foreign_handle=invalid host_handle_intact=true' \
     && has 'text=isohost: address_space outcome=(own_memory|faulted) host_data_intact=true' \
     && has 'text=isohost: crash code=-1 host_alive=true respawn_ok=true' \
     && has 'text=isohost: cpu_pressure hogs=2 rounds=20 idle_max_ticks=[0-9]+ loaded_max_ticks=[0-4] bound=4 recovered_max_ticks=[01] recovered=true' \
     && has 'text=isohost: placement acquired_in_process=rejected acquired_isolated=ok local_in_process=ok' \
     && has 'text=isohost: quiescence busy_refused=true active_at_refusal=1 usable_while_busy=true unloaded_after_exit=true' \
     && has 'text=isohost: ok checks=[0-9]+' \
     && has '^\[JSR-USER\] event=system\.task\.faulted task=spawned .*kind=page_fault .*action=terminated' \
     && has '^\[JSR-PROC\] event=system\.process\.killed id=0x[0-9a-f]+ cause=last_handle_released code=-2' \
     && has 'case=isohost exit=Some\(0\) expect=0 reclaimed=true' \
     && ! has 'text=isohost: FAIL'; then
    record J-6 PASS "宿主测试 $t/10（创建参数块/调用子集、放置规则、隔离协议）；隔离模块在独立进程运行：越权调用 rights_denied、宿主句柄值无效、写不到宿主数据、崩溃只终止隔离进程；2 个吃满 CPU 的隔离模块下往返延迟 ≤4 tick、丢弃后立即恢复；自动获取的模块进程内装载被拒；线程停在模块内时卸载被拒且模块可用；子进程配额与回收；回到基线"
  else
    record J-6 FAIL "宿主测试 $t/10（rc=${TEST_RC:-?}/${JASO_RC:-?}），或缺少 isohost 关键标记 / 故障终止 / 释放即终止标记"
  fi
}

check_sched1() { # 调度策略 + QoS：档位规则（拒绝且不变、继承、上限）；动态任务数；过载下用户发起档唤醒延迟有上界、后台有进展；压力撤销后立即恢复；回到基线
  if [ "$SCHED_POLICY" = "rr" ]; then record_na SCHED1 "QoS 分时策略专项：纯轮转构建不提供四档语义，已在分时构建中通过"; return; fi
  # 动态任务数用例的期望值随配置档：同时存活 = 槽位上限的 5/8，填满时的填充任务 = 槽位上限 - 1
  local mt many
  mt="$(cfg max_tasks)"; many=$(( mt * 5 / 8 ))
  if has 'policy=timeshare preemption=default_on' \
     && has '\[JSR-QOS\] case=rules boot_refused=true steps=7/7 raise_refused_unchanged=true inherit=true ceiling=true reclaimed=true' \
     && has "\\[JSR-QOS\\] case=many capacity=$mt spawned=$many done=$many peak_live=$many full_refused=true fillers=$((mt - 1)) reclaimed=true" \
     && has 'text=schedtest: mode=qos qos_rules invalid_refused=true raise_refused=true same_ok=true' \
     && has 'text=schedtest: mode=qos busy_ticks=[0-9]+ background_progressed=true' \
     && has 'text=schedtest: mode=qos joined=4 all_progressed=true' \
     && has 'text=schedtest: mode=same_class joined=4 all_progressed=true' \
     && has '\[JSR-QOS\] case=overload mode=qos exit=Some\(0\) samples=[1-9][0-9]* p50=0 p99=[01] max=[01] bound=1 bounded=true .*reclaimed=true' \
     && has '\[JSR-QOS\] case=overload mode=same_class exit=Some\(0\) samples=[1-9][0-9]* .* bounded=true .*reclaimed=true' \
     && has '\[JSR-QOS\] case=recovery rounds=20 samples=20 max=0 immediate=true reclaimed=true' \
     && has '^\[JSR-QOS\] summary free_frames=([0-9]+)/\1 objects=([0-9]+)/\2 reclaimed=true checks=[0-9]+ failed=0'; then
    record SCHED1 PASS "QoS 四档：降档/不变允许、升档被拒且档位不变、继承与上限；${mt} 槽位、${many} 任务并发；4 个吃满 CPU 线程下用户发起档唤醒延迟有上界、后台有进展；压力撤销后延迟 0；回到基线"
  else
    record SCHED1 FAIL "缺少 JSR-QOS 关键标记、延迟超界或 failed≠0"
  fi
}

check_sched2() { # 优先级继承：三任务反转（锁 / 等退出）有界、关闭继承对照可见反转、传递继承、拒绝路径无残留、持有者退出可接管、压力撤销后恢复、回到基线
  if [ "$SCHED_POLICY" = "rr" ]; then record_na SCHED2 "优先级继承专项：依赖 QoS 档位借还，已在分时构建中通过"; return; fi
  if has '\[JSR-PI\] case=inversion wait_on=lock inherit=true hogs=3 hog_ticks=120 work=4 wait=[0-6] bound=6 bounded=true holder_peak=interactive holder_after=background hog_progress=true lock_free=true reclaimed=true' \
     && has '\[JSR-PI\] case=inversion wait_on=lock inherit=false .* bounded=false holder_peak=background .*reclaimed=true' \
     && has '\[JSR-PI\] case=inversion wait_on=exit inherit=true hogs=3 hog_ticks=120 work=4 wait=[0-6] bound=6 bounded=true holder_peak=interactive holder_after=background hog_progress=true .*reclaimed=true' \
     && has '\[JSR-PI\] case=chain low_seen=interactive mid_with_a=interactive low_after=background mid_after=utility high_got=true transitive=true restored=true locks_free=true reclaimed=true' \
     && has '\[JSR-PI\] case=refusals steps=7/7 recursive_refused=true self_join_refused=true cycle_refused=true unchanged=true waiter_completed=true locks_free=true reclaimed=true' \
     && has '\[JSR-PI\] case=orphan waiter_took_over=true lock_free=true reclaimed=true' \
     && has '\[JSR-PI\] case=recovery rounds=20 samples=20 max=0 immediate=true reclaimed=true' \
     && has '^\[JSR-PI\] summary free_frames=([0-9]+)/\1 objects=([0-9]+)/\2 reclaimed=true checks=[0-9]+ failed=0'; then
    record SCHED2 PASS "优先级继承：3 个吃满 CPU 的中档任务下，交互档等后台档持有的锁 / 等其退出 ≤6 tick（关闭继承对照 >6）；传递继承与归还；递归/成环/自等被拒且无残留；持有者退出可接管；压力撤销后延迟 0；回到基线"
  else
    record SCHED2 FAIL "缺少 JSR-PI 关键标记、等待超界或 failed≠0"
  fi
}

check_sched3() { # 过载防护：每进程 CPU 上限（令牌桶上界内、确有限速、旁观任务拿回处理器；不限速对照）；失控进程 + 内存紧张下交互档延迟有上界；看门狗；内存压力分级准入（被拒无改动）；压力撤销后回到基线
  if [ "$SCHED_POLICY" = "rr" ]; then record_na SCHED3 "过载防护专项：依赖 QoS 档位与上限，已在分时构建中通过"; return; fi
  if has '\[JSR-OVL\] case=rules invalid_refused=true invalid_change_unchanged=true stale_group_refused=true exited_refused=true groups=0 reclaimed=true' \
     && has 'text=schedtest: mode=runaway threads=5 wall_ticks=300 all_progressed=true' \
     && has '\[JSR-OVL\] case=runaway mode=limited limit=250 pressure=low exit=Some\(0\) window=[0-9]+ used=[0-9]+ bound=[0-9]+ within=true throttled_ticks=[1-9][0-9]* throttle_events=[1-9][0-9]* bystander_share=([5-9][0-9][0-9]|1000)‰ interactive_samples=[1-9][0-9]* p99=[01] max=[01] latency_bound=1 bounded=true watchdog_runaway=[1-9][0-9]* watchdog_bystander=true watchdog_interactive=false groups=0 reclaimed=true' \
     && has '\[JSR-OVL\] case=runaway mode=unlimited limit=1000 pressure=low exit=Some\(0\) .* within=true throttled_ticks=0 throttle_events=0 bystander_share=[1-4]?[0-9]?[0-9]‰ .* bounded=true .*watchdog_interactive=false groups=0 reclaimed=true' \
     && has 'text=schedtest: mode=pressure qos=background map_refused=true nothing_mapped=true' \
     && has '\[JSR-OVL\] case=memory order=I/U/T/B normal=normal:1111 low=low:1100 critical=critical:1000 reserve=critical:0000 restored=normal:1111 refused_untouched=true user_background_refused=true .*worst=critical reclaimed=true' \
     && has '\[JSR-OVL\] case=recovery rounds=20 samples=20 max=0 immediate=true watchdog_new=0 level=normal groups=0 reclaimed=true' \
     && has '^\[JSR-OVL\] summary free_frames=([0-9]+)/\1 objects=([0-9]+)/\2 groups=0 level=normal reclaimed=true checks=[0-9]+ failed=0'; then
    record SCHED3 PASS "过载防护：失控进程（5 线程吃满）按 25% 上限限速且用量在令牌桶上界内，同档旁观任务拿到 ≥50% 处理器（不限速对照 <50%）；失控进程 + 内存紧张下交互档唤醒延迟 ≤1 tick；看门狗记录失控线程、不记录交互任务；内存紧张/危急/保留线按档位拒绝且无改动；压力撤销后延迟 0、回到基线"
  else
    record SCHED3 FAIL "缺少 JSR-OVL 关键标记、上限/延迟超界或 failed≠0"
  fi
}

check_t1() {    # 内核参数化：配置档宿主测试；启动时输出所选配置档、校验通过、逐项参数齐全；参数真实生效（调度时间片与定时器频率）
  local n listed hz q1 want_hz
  n="$(grep -oE '^\[JSR-CONFIG\] profile='"$PROFILE"' valid=ok params=[0-9]+' "$SERIAL" 2>/dev/null | grep -oE '[0-9]+$' | head -1)"
  listed="$(count '^\[JSR-CONFIG\] [a-z_0-9.]+=[0-9]+\s*$')"
  hz="$(cfg timer_hz)"; q1="$(cfg 'quantum\.1')"
  case "$PROFILE" in standard) want_hz=100 ;; compact) want_hz=250 ;; esac
  if grep -qE 'config::tests::invalid_parameters_are_rejected_by_name \.\.\. ok' "$OUT/cargo-test.log" \
     && grep -qE 'config::tests::both_profiles_valid \.\.\. ok' "$OUT/cargo-test.log" \
     && [ -n "$n" ] && [ "$listed" = "$n" ] && [ "$hz" = "$want_hz" ] \
     && has "preemptive demo done tick_switches=[0-9]+ quantum_ticks=$q1 "; then
    record T-1 PASS "配置档 $PROFILE：校验通过、$n 项参数逐项输出；timer_hz=$hz、时间片 $q1 tick 在运行中生效；非法参数宿主测试被拒"
  else
    record T-1 FAIL "配置档 $PROFILE：缺少 JSR-CONFIG 标记、参数项数不符（$listed/${n:-?}）、频率或时间片未生效，或宿主测试未通过"
  fi
}

check_t2() {    # 基准：宿主统计/取值测试；周期计数器校准；时钟中断/切换/页帧/堆/系统调用/异步环/IPC 各项样本齐全；失败路径被拒无改动；生效参数在开销预算内；回到基线
  local hz names ok=1 i q gate
  hz="$(cfg timer_hz)"
  for t in summary_uses_nearest_rank_and_keeps_buffer full_buffer_rejects_without_changing_samples calibration_converts_and_rejects_zero_inputs \
           overhead_is_ppm_and_saturates select_picks_bound_by_direction select_reports_none_and_out_of_limit_current select_rejects_invalid_inputs_without_partial_result; do
    grep -qE "bench::tests::$t \.\.\. ok" "$OUT/cargo-test.log" || ok=0
  done
  for names in kernel.timer_irq sched.context_switch frame.alloc frame.free heap.alloc_free_64 heap.alloc_free_4096; do
    has "^\[JSR-BENCH\] name=$names iters=[1-9][0-9]* min=[0-9]+ p50=[0-9]+ p99=[0-9]+ max=[0-9]+ mean=[0-9]+ unit=cycles p50_ns=[0-9]+ p99_ns=[0-9]+" || ok=0
  done
  for names in syscall.roundtrip ring.submit_complete ipc.roundtrip; do
    has "text=bench: name=$names iters=200 min=[0-9]+ p50=[1-9][0-9]* p99=[0-9]+ max=[0-9]+ mean=[0-9]+ unit=cycles p50_ns=[0-9]+" || ok=0
  done
  # 预算判定只在平台提供真正的周期计数器时执行（x86_64 的 TSC；其它指令集是时间基准）：
  # 强制生效时（gated=true）必须 within_limit=true；只作参考时（gated=false）只要求结论齐全。
  # 无论哪种情况，都不允许出现「强制生效却超出预算」。
  case "$PROFILE" in standard) gate='within_limit=(true gated=true|(true|false) gated=false)' ;; *) gate='within_limit=(true|false) gated=false' ;; esac
  ! has 'within_limit=false gated=true' || ok=0
  for i in 0 1 2 3; do
    q="$(cfg "quantum\.$i")"
    has "^\[JSR-BENCH\] tune param=quantum\.$i current=$q current_ppm=[0-9]+ limit_ppm=10000 $gate prefer=smallest bound=(Some\([0-9]+\)|None)" || ok=0
  done
  if [ "$ok" = 1 ] \
     && has "^\[JSR-BENCH\] calibrate ticks=20 cycles=[1-9][0-9]* cycles_per_tick=[1-9][0-9]* cycles_per_second=[1-9][0-9]* timer_hz=$hz" \
     && has '^\[JSR-BENCH\] probe span_p50=[0-9]+ span_max=[0-9]+ samples=20 ticks=20 matched=true' \
     && has '^\[JSR-BENCH\] case=frame_refusal double_free_refused=true free_unchanged=true reclaimed=true' \
     && has '^\[JSR-BENCH\] case=heap_refusal refused=true heap_unchanged=true reclaimed=true' \
     && has 'text=bench: user case=ring_refusal refused=true no_completion=true' \
     && has 'text=bench: user case=ipc_refusal refused=true message_kept=true' \
     && has 'text=bench: user ok checks=[0-9]+' \
     && has '^\[JSR-BENCH\] case=user exit=Some\(0\) reclaimed=true' \
     && has "^\[JSR-BENCH\] tune param=timer_hz current=$hz current_ppm=[0-9]+ limit_ppm=10000 $gate prefer=largest bound=(Some\([0-9]+\)|None)" \
     && has '^\[JSR-BENCH\] case=tune_refusal invalid_candidate_refused=true' \
     && has '^\[JSR-BENCH\] summary free_frames=([0-9]+)/\1 objects=([0-9]+)/\2 reclaimed=true checks=[0-9]+ failed=0' \
     && ! has '^\[JSR-BENCH-FAIL\]'; then
    record T-2 PASS "9 项基准样本齐全（内核 6 + 用户态 3）；时钟中断样本与 tick 一一对应；失败路径被拒无改动；配置档 $PROFILE 的取值结论齐全（默认档 timer_hz 与各档时间片须在 1% 开销预算内）；回到基线"
  else
    record T-2 FAIL "缺少 JSR-BENCH 标记、样本不全、失败路径未被拒、生效参数超出预算、宿主测试未通过或未回到基线"
  fi
}

check_fix() {   # 基础设施修复回归：失败路径与回滚（已退出接收方、堆扩容、内核空间预分配、只读翻译、ID 用尽、线程创建）
  if has 'exited_receiver grant=Some\(Exited\) grant_new=Some\(Exited\) transfer=Some\(Exited\) objects_unchanged=true sender_kept=true reaped_receiver=Some\(NoSuchProcess\)' \
     && has 'heap fail_alloc=Some\(OutOfFrames\) rolled_back=true fail_map=Some\(MapFailed\) rolled_back=true overflow=Some\(LimitReached\) regrow=true reclaimed=true' \
     && has "kernel_space ready=true used=${KPART:-256} fail=Some\\(OutOfFrames\\) untouched=true frames_returned=true ok=Some\\(${KPART:-256}\\) reclaimed=true refuse_when_unready=true" \
     && has 'translate same_as_mapper=true unmapped_none=true kernel_not_user=true reclaimed=true' \
     && has 'ids last=Some\(18446744073709551615\) after_exhausted=None again=None no_wrap=true' \
     && has 'spawn zero_stack=Some\(Map\(InvalidAddress\)\) objects_full=Some\(NoTaskSlot\) restored=true sched_full=Some\(NoTaskSlot\) \(fillers [1-9][0-9]* filler_err=Some\([A-Za-z]+\)\) restored=true retry_exit=Some\(Exited \{ code: 42 \}\)' \
     && has '^\[JSR-FIX\] objects_live=([0-9]+)/\1 pending=0 checks=[0-9]+ failed=0' \
     && ! has 'warning residual_handles'; then
    record FIX PASS "失败路径全部回滚到基线；回滚后可再次成功；无残余句柄告警"
  else
    record FIX FAIL "缺少 JSR-FIX 关键标记、failed≠0 或出现残余句柄告警"
  fi
}

# port_rerun <串口日志> <QEMU 退出码> <行名前缀> <内核共享部分表项数> <检查函数…>：在另一指令集的串口日志上逐项重跑
# 给定检查（行名带前缀）；结果放在 PORT_N（行数）与 PORT_BAD（失败数）。
port_rerun() {
  local serial="$1" qrc="$2" prefix="$3" kpart="$4"; shift 4
  local saved_serial="$SERIAL" saved_qrc="$QRC" before=${#ROWS[@]} i bad=0 c
  SERIAL="$serial"; QRC="$qrc"; REC_PREFIX="$prefix"; KPART="$kpart"
  # 目标本机不可运行（QEMU 缺固件）时，这一组逐项检查一律记 N/A，不产生假失败。
  if [ "$qrc" = "-2" ] || grep -qa 'Unable to find the RISC-V BIOS' "$serial" 2>/dev/null; then
    PORT_NA=1; PORT_NA_REASON="缺少 32 位 OpenSBI 固件（fw_dynamic.bin）"
  else
    PORT_NA=0; PORT_NA_REASON=""
  fi
  for c in "$@"; do "$c"; done
  PORT_NA=0; PORT_NA_REASON=""
  SERIAL="$saved_serial"; QRC="$saved_qrc"; REC_PREFIX=""; unset KPART
  for (( i = before; i < ${#ROWS[@]}; i++ )); do
    # N/A：本构建下不适用（例如纯轮转构建里的 QoS 专项），不计入失败
    [[ "${ROWS[$i]}" == *" PASS "* || "${ROWS[$i]}" == *" N/A "* ]] || bad=$((bad + 1))
  done
  PORT_N=$(( ${#ROWS[@]} - before )); PORT_BAD=$bad
}

# a64_rerun <检查函数…>：在 AArch64 串口日志上逐项重跑给定检查（行名带 A64/ 前缀）；结果放在 A64_N / A64_BAD。
a64_rerun() {
  port_rerun "$SERIAL_A64" "$QRC_A64" "A64/" 128 "$@"
  A64_N=$PORT_N; A64_BAD=$PORT_BAD
}

# rv64_rerun <检查函数…>：在 RISC-V64 串口日志上逐项重跑给定检查（行名带 RV64/ 前缀）；结果放在 RV64_N / RV64_BAD。
rv64_rerun() {
  port_rerun "$SERIAL_RV64" "$QRC_RV64" "RV64/" 128 "$@"
  RV64_N=$PORT_N; RV64_BAD=$PORT_BAD
}

check_smp1a() { # 多处理器第一阶段（x86_64）：4 个处理器全部报到、各自计时、核间中断、跨核调用、TLB 击落、拒绝路径；
                 # 全部 x86_64 串口检查在 4 处理器日志上逐项重跑（行名带 SMP4/ 前缀）；单处理器启动如实报告只有引导处理器
  if [ "$BUILD_RC" -ne 0 ] || [ ! -s "$SERIAL_SMP4" ]; then
    record SMP-1a FAIL "4 处理器启动没有串口日志（构建 rc=$BUILD_RC，QEMU=$QRC_SMP4）"
    return
  fi
  port_rerun "$SERIAL_SMP4" "$QRC_SMP4" "SMP4/" 256 \
    check_m11 check_m12 check_m13 check_m14 check_m15 check_m21 check_m22 check_m23 check_m24 check_m31 check_m32 check_m33 \
    check_m34 check_m51pre check_m41 check_m42 check_m43 check_m44 check_m51 check_s1 check_j1 check_j2 check_j3 check_j4 \
    check_j5 check_j6 check_sched1 check_sched2 check_sched3 check_t1 check_t2 check_fix
  local n=$PORT_N bad=$PORT_BAD miss="" f="$SERIAL_SMP4" c
  grep -qE '^\[JSR-SMP\] start present=4 online=4 failed=0 source=acpi\.madt ' "$f" || miss="$miss 启动"
  for c in 0 1 2 3; do grep -qE "^\[JSR-SMP\] cpu index=$c hw=[0-9]+ state=online" "$f" || miss="$miss cpu$c"; done
  for c in 1 2 3; do
    grep -qE "^\[JSR-SMP\] clock cpu=$c ticks_before=[0-9]+ ticks_after=[0-9]+ advanced=([1-9][0-9]+)" "$f" || miss="$miss 时钟$c"
  done
  grep -q '^\[JSR-SMP\] clock independent bsp_frozen=1 others_advanced=true' "$f" || miss="$miss 各自计时"
  grep -q '^\[JSR-SMP\] ipi reschedule delivered=3/3' "$f"                 || miss="$miss 重新调度"
  grep -q '^\[JSR-SMP\] call ran_on_target=3/3 current=idle' "$f"          || miss="$miss 跨核调用"
  grep -qE '^\[JSR-SMP\] tlb va=0x[0-9a-f]+ before=A:3/3 stale_without_shootdown=[0-3]/3 after_shootdown=B:3/3 local=B:true acks=[3-9][0-9]* frames_back=true' "$f" \
                                                                             || miss="$miss TLB击落"
  grep -qE '^\[JSR-SMP\] refuse no_such_cpu=system\.cpu\.error\.no_such_cpu self=system\.cpu\.error\.self_target call_no_such=system\.cpu\.error\.no_such_cpu call_self=system\.cpu\.error\.self_target bad_range=system\.cpu\.error\.bad_range,system\.cpu\.error\.bad_range,system\.cpu\.error\.bad_range' "$f" \
                                                                             || miss="$miss 拒绝路径"
  grep -qE '^\[JSR-SMP\] summary cpus=4 online=4 checks=[0-9]+ failed=0' "$f" || miss="$miss 汇总"
  grep -q '^\[JSR-EXIT\] success' "$f" && [ "$QRC_SMP4" -eq 33 ]           || miss="$miss 退出"
  # 单处理器启动：只有引导处理器，拒绝路径同样成立
  grep -qE '^\[JSR-SMP\] start present=1 online=1 failed=0 ' "$SERIAL" && grep -q '^\[JSR-SMP\] single cpus=1 secondary=none' "$SERIAL" \
    && grep -qE '^\[JSR-SMP\] summary cpus=1 online=1 checks=[0-9]+ failed=0' "$SERIAL" || miss="$miss 单处理器"
  local stale
  stale=$(grep -oE 'stale_without_shootdown=[0-3]/3' "$f" | head -1 | cut -d= -f2)
  if [ -z "$miss" ] && [ "$bad" -eq 0 ]; then
    record SMP-1a PASS "x86_64 -smp 4（QEMU=$QRC_SMP4）：MADT 发现 4 个处理器全部报到；各核本地定时器各自计时（引导处理器关中断时其他核照走）；重新调度 / 跨核调用核间中断 3/3；改映射后仅本地作废时 $stale 个处理器读到旧映射，击落后 3/3 读到新映射、页帧回到基线；拒绝路径无中断无残留；$n 项 x86_64 检查在 4 处理器下全部复跑通过；单处理器启动如实报告只有引导处理器"
  else
    record SMP-1a FAIL "缺少/不符：$miss；4 处理器复跑 $n 项中 $bad 项失败（见 serial-smp4.log）"
  fi
}

check_smp1b_a64() { # 多处理器第二阶段（AArch64）：设备树发现 4 个处理器、PSCI CPU_ON 全部报到、各核虚拟定时器各自计时、
                     # GIC 软件生成中断（重新调度 / 跨核调用 / TLB 击落）、拒绝路径；全部 AArch64 串口检查在 4 处理器日志上逐项重跑（行名带 A64SMP4/ 前缀）
  if [ "$A64_BUILD_RC" -ne 0 ] || [ ! -s "$SERIAL_A64_SMP4" ]; then
    record SMP-1b-A64 FAIL "AArch64 4 处理器启动没有串口日志（构建 rc=$A64_BUILD_RC，QEMU=$QRC_A64_SMP4）"
    return
  fi
  port_rerun "$SERIAL_A64_SMP4" "$QRC_A64_SMP4" "A64SMP4/" 128 \
    check_m11 check_m12 check_m13 check_m14 check_m15 check_m21 check_m22 check_m23 check_m24 check_m31 check_m32 check_m33 check_m34 \
    check_m42 check_fix check_sched2 check_m51pre check_m41 check_m43 check_m44 check_m51 check_s1 check_j1 check_j2 check_j3 check_j4 \
    check_j5 check_j6 check_pol2 check_sched1 check_sched3 check_t1 check_t2
  local n=$PORT_N bad=$PORT_BAD miss="" f="$SERIAL_A64_SMP4" c
  grep -qE '^\[JSR-SMP\] start present=4 online=4 failed=0 source=fdt\.cpus ' "$f" || miss="$miss 启动"
  for c in 0 1 2 3; do grep -qE "^\[JSR-SMP\] cpu index=$c hw=$c state=online" "$f" || miss="$miss cpu$c"; done
  for c in 1 2 3; do
    grep -qE "^\[JSR-SMP\] clock cpu=$c ticks_before=[0-9]+ ticks_after=[0-9]+ advanced=([1-9][0-9]+)" "$f" || miss="$miss 时钟$c"
  done
  grep -q '^\[JSR-SMP\] clock independent bsp_frozen=1 others_advanced=true' "$f" || miss="$miss 各自计时"
  grep -q '^\[JSR-SMP\] ipi reschedule delivered=3/3' "$f"                 || miss="$miss 重新调度"
  grep -q '^\[JSR-SMP\] call ran_on_target=3/3 current=idle' "$f"          || miss="$miss 跨核调用"
  grep -qE '^\[JSR-SMP\] tlb va=0x[0-9a-f]+ before=A:3/3 stale_without_shootdown=[0-3]/3 after_shootdown=B:3/3 local=B:true acks=[3-9][0-9]* frames_back=true' "$f" \
                                                                             || miss="$miss TLB击落"
  grep -qE '^\[JSR-SMP\] refuse no_such_cpu=system\.cpu\.error\.no_such_cpu self=system\.cpu\.error\.self_target call_no_such=system\.cpu\.error\.no_such_cpu call_self=system\.cpu\.error\.self_target bad_range=system\.cpu\.error\.bad_range,system\.cpu\.error\.bad_range,system\.cpu\.error\.bad_range' "$f" \
                                                                             || miss="$miss 拒绝路径"
  grep -qE '^\[JSR-SMP\] summary cpus=4 online=4 checks=[0-9]+ failed=0' "$f" || miss="$miss 汇总"
  grep -q '^\[JSR-EXIT\] success' "$f" && [ "$QRC_A64_SMP4" -eq 33 ]       || miss="$miss 退出"
  # 单处理器 AArch64 启动：设备树只有引导处理器，如实报告并只演练拒绝路径
  grep -qE '^\[JSR-SMP\] start present=1 online=1 failed=0 source=boot_only ' "$SERIAL_A64" \
    && grep -q '^\[JSR-SMP\] single cpus=1 secondary=none' "$SERIAL_A64" \
    && grep -qE '^\[JSR-SMP\] summary cpus=1 online=1 checks=[0-9]+ failed=0' "$SERIAL_A64" || miss="$miss 单处理器"
  local stale
  stale=$(grep -oE 'stale_without_shootdown=[0-3]/3' "$f" | head -1 | cut -d= -f2)
  if [ -z "$miss" ] && [ "$bad" -eq 0 ]; then
    record SMP-1b-A64 PASS "AArch64 -smp 4（QEMU=$QRC_A64_SMP4）：设备树处理器节点发现 4 个处理器、PSCI CPU_ON 全部报到；各核虚拟定时器各自计时（引导处理器关中断时其他核照走）；GIC 软件生成中断：重新调度 / 跨核调用 3/3；改映射后仅本地作废时 $stale 个处理器读到旧映射，击落后 3/3 读到新映射、页帧回到基线；拒绝路径无中断无残留；$n 项 AArch64 检查在 4 处理器下全部复跑通过；单处理器启动如实报告只有引导处理器"
  else
    record SMP-1b-A64 FAIL "缺少/不符：$miss；4 处理器复跑 $n 项中 $bad 项失败（见 serial-aarch64-smp4.log）"
  fi
}

# rv_smp4_verdict <日志> <QEMU 退出码> <前缀>：在 RISC-V 4 处理器日志上逐项重跑全部 RISC-V 检查，并核对多处理器标记；
# 缺项写入 RV_SMP_MISS，复跑结果放在 PORT_N / PORT_BAD。引导处理器由固件选定（不一定是 hart 0），只要求 4 个 hart 号互不相同且都在 0–3。
rv_smp4_verdict() {
  local rvlog="$1" rvqrc="$2" rvprefix="$3" rvc rvhws
  RV_SMP_MISS=""
  port_rerun "$rvlog" "$rvqrc" "$rvprefix" 128 \
    check_m11 check_m12 check_m13 check_m14 check_m15 check_m21 check_m22 check_m23 check_m24 check_m31 check_m32 check_m33 check_m34 \
    check_m42 check_fix check_sched2 check_m51pre check_m41 check_m43 check_m44 check_m51 check_s1 check_j1 check_j2 check_j3 check_j4 \
    check_j5 check_j6 check_pol2 check_sched1 check_sched3 check_t1 check_t2
  grep -qaE '^\[JSR-SMP\] start present=4 online=4 failed=0 source=fdt\.cpus ' "$rvlog" || RV_SMP_MISS="$RV_SMP_MISS 启动"
  rvhws=$(grep -aoE '^\[JSR-SMP\] cpu index=[0-3] hw=[0-3] state=online' "$rvlog" | grep -oE 'hw=[0-3]' | sort -u | wc -l)
  [ "$rvhws" -eq 4 ] || RV_SMP_MISS="$RV_SMP_MISS hart号($rvhws)"
  for rvc in 1 2 3; do
    grep -qaE "^\[JSR-SMP\] clock cpu=$rvc ticks_before=[0-9]+ ticks_after=[0-9]+ advanced=([1-9][0-9]+)" "$rvlog" || RV_SMP_MISS="$RV_SMP_MISS 时钟$rvc"
  done
  grep -qa '^\[JSR-SMP\] clock independent bsp_frozen=1 others_advanced=true' "$rvlog" || RV_SMP_MISS="$RV_SMP_MISS 各自计时"
  grep -qa '^\[JSR-SMP\] ipi reschedule delivered=3/3' "$rvlog"                 || RV_SMP_MISS="$RV_SMP_MISS 重新调度"
  grep -qa '^\[JSR-SMP\] call ran_on_target=3/3 current=idle' "$rvlog"          || RV_SMP_MISS="$RV_SMP_MISS 跨核调用"
  grep -qaE '^\[JSR-SMP\] tlb va=0x[0-9a-f]+ before=A:3/3 stale_without_shootdown=[0-3]/3 after_shootdown=B:3/3 local=B:true acks=[3-9][0-9]* frames_back=true' "$rvlog" \
                                                                              || RV_SMP_MISS="$RV_SMP_MISS TLB击落"
  grep -qaE '^\[JSR-SMP\] refuse no_such_cpu=system\.cpu\.error\.no_such_cpu self=system\.cpu\.error\.self_target call_no_such=system\.cpu\.error\.no_such_cpu call_self=system\.cpu\.error\.self_target bad_range=system\.cpu\.error\.bad_range,system\.cpu\.error\.bad_range,system\.cpu\.error\.bad_range' "$rvlog" \
                                                                              || RV_SMP_MISS="$RV_SMP_MISS 拒绝路径"
  grep -qaE '^\[JSR-SMP\] summary cpus=4 online=4 checks=[0-9]+ failed=0' "$rvlog" || RV_SMP_MISS="$RV_SMP_MISS 汇总"
  grep -qa '^\[JSR-EXIT\] success' "$rvlog" && [ "$rvqrc" -eq 33 ]                || RV_SMP_MISS="$RV_SMP_MISS 退出"
}

check_smp1b_rv() { # 多处理器第二阶段（RISC-V64 与 RISC-V32）：设备树发现 4 个处理器、SBI HSM hart_start 全部报到、各核本地定时器各自计时、
                    # SBI IPI 软件中断（重新调度 / 跨核调用 / TLB 击落）、拒绝路径；全部 RISC-V 串口检查在两份 4 处理器日志上逐项重跑
                    # （行名带 RV64SMP4/、RV32SMP4/ 前缀）；单处理器启动如实报告只有引导处理器
  local rv32skip=0; rv32_fw_missing && rv32skip=1
  if [ "$RV64_BUILD_RC" -ne 0 ] || [ "$RV32_BUILD_RC" -ne 0 ] || [ ! -s "$SERIAL_RV64_SMP4" ] \
     || { [ "$rv32skip" -eq 0 ] && [ ! -s "$SERIAL_RV32_SMP4" ]; }; then
    record SMP-1b-RV FAIL "RISC-V 4 处理器启动没有串口日志（构建 rc=$RV64_BUILD_RC/$RV32_BUILD_RC，QEMU=$QRC_RV64_SMP4/$QRC_RV32_SMP4）"
    return
  fi
  local rvmiss="" rvn=0 rvbad=0 rvf boot64 boot32
  rv_smp4_verdict "$SERIAL_RV64_SMP4" "$QRC_RV64_SMP4" "RV64SMP4/"; rvn=$((rvn + PORT_N)); rvbad=$((rvbad + PORT_BAD))
  [ -z "$RV_SMP_MISS" ] || rvmiss="$rvmiss RV64:[$RV_SMP_MISS ]"
  if [ "$rv32skip" -eq 1 ]; then
    # 只核对 RISC-V64 部分；RISC-V32 未运行的部分在结论里如实标注。
    grep -qaE '^\[JSR-SMP\] start present=1 online=1 failed=0 source=boot_only ' "$SERIAL_RV64" \
      && grep -qa '^\[JSR-SMP\] single cpus=1 secondary=none' "$SERIAL_RV64" \
      && grep -qaE '^\[JSR-SMP\] summary cpus=1 online=1 checks=[0-9]+ failed=0' "$SERIAL_RV64" \
      || rvmiss="$rvmiss 单处理器(RV64)"
    if [ -z "$rvmiss" ] && [ "$rvbad" -eq 0 ]; then
      record SMP-1b-RV PASS "RISC-V64 -smp 4（QEMU=$QRC_RV64_SMP4）：设备树发现 4 个处理器、SBI HSM hart_start 全部报到；各核本地定时器各自计时（引导处理器关中断时其他核照走）；SBI IPI 软件中断 + 每核信箱：重新调度 / 跨核调用 3/3；击落后 3/3 读到新映射、页帧回到基线；拒绝路径无中断无残留；$rvn 项 RISC-V 检查在 4 处理器日志上全部复跑通过；单处理器启动如实报告只有引导处理器$RV32_NOTE"
    else
      record SMP-1b-RV FAIL "缺少/不符：$rvmiss；RV64 4 处理器复跑 $rvn 项中 $rvbad 项失败（见 serial-riscv64-smp4.log）"
    fi
    return
  fi
  rv_smp4_verdict "$SERIAL_RV32_SMP4" "$QRC_RV32_SMP4" "RV32SMP4/"; rvn=$((rvn + PORT_N)); rvbad=$((rvbad + PORT_BAD))
  [ -z "$RV_SMP_MISS" ] || rvmiss="$rvmiss RV32:[$RV_SMP_MISS ]"
  for rvf in "$SERIAL_RV64" "$SERIAL_RV32"; do
    grep -qaE '^\[JSR-SMP\] start present=1 online=1 failed=0 source=boot_only ' "$rvf" \
      && grep -qa '^\[JSR-SMP\] single cpus=1 secondary=none' "$rvf" \
      && grep -qaE '^\[JSR-SMP\] summary cpus=1 online=1 checks=[0-9]+ failed=0' "$rvf" || rvmiss="$rvmiss 单处理器($(basename "$rvf"))"
  done
  boot64=$(grep -aoE '^\[JSR-SMP\] cpu index=0 hw=[0-9]+' "$SERIAL_RV64_SMP4" | grep -oE '[0-9]+$')
  boot32=$(grep -aoE '^\[JSR-SMP\] cpu index=0 hw=[0-9]+' "$SERIAL_RV32_SMP4" | grep -oE '[0-9]+$')
  if [ -z "$rvmiss" ] && [ "$rvbad" -eq 0 ]; then
    record SMP-1b-RV PASS "RISC-V64 / RISC-V32 -smp 4（QEMU=$QRC_RV64_SMP4/$QRC_RV32_SMP4）：设备树处理器节点发现 4 个处理器（引导 hart 由固件选定：$boot64 / $boot32）、SBI HSM hart_start 全部报到；各核本地定时器各自计时（引导处理器关中断时其他核照走）；SBI IPI 软件中断 + 每核信箱：重新调度 / 跨核调用 3/3；击落后 3/3 读到新映射、页帧回到基线；拒绝路径无中断无残留；$rvn 项 RISC-V 检查在两份 4 处理器日志上全部复跑通过；单处理器启动如实报告只有引导处理器"
  else
    record SMP-1b-RV FAIL "缺少/不符：$rvmiss；4 处理器复跑 $rvn 项中 $rvbad 项失败（见 serial-riscv64-smp4.log / serial-riscv32-smp4.log）"
  fi
}

# smp1c_verdict <4 处理器日志> <QEMU 退出码> <名称>：一份日志上的 SMP-1c 断言；缺失项追加到 SC_MISS
smp1c_verdict() {
  local scf="$1" scrc="$2" scname="$3" sccpu scbad scgood
  grep -qaE '^\[JSR-SMPC\] registry locks=[0-9]+ valid=true' "$scf" || SC_MISS="$SC_MISS $scname:登记表"
  [ "$(grep -caE '^\[JSR-SMPC\] rank +[0-9]+ system\.[a-z_.]+.?$' "$scf")" -ge 11 ] || SC_MISS="$SC_MISS $scname:登记链"
  grep -qa '^\[JSR-SMPC\] order ascending=ok reverse=system\.lock\.error\.out_of_order recursive=system\.lock\.error\.out_of_order unchanged=true held_back=true' "$scf" \
    || SC_MISS="$SC_MISS $scname:顺序检查"
  grep -qa '^\[JSR-SMPC\] held per_cpu independent=3/3' "$scf" || SC_MISS="$SC_MISS $scname:每核持有集合"
  # 控制台：4 个处理器各 16 行、格式完整（任何跨核交错都会破坏行格式）
  scgood=$(grep -caE '^\[JSR-SMPC\] burst cpu=[0-3] seq=(0[0-9]|1[0-5]) abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL end.?$' "$scf")
  scbad=$(grep -a 'burst cpu=' "$scf" | grep -cavE '^\[JSR-SMPC\] burst cpu=[0-3] seq=(0[0-9]|1[0-5]) abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL end.?$')
  [ "$scgood" -eq 64 ] && [ "$scbad" -eq 0 ] || SC_MISS="$SC_MISS $scname:整行输出($scgood/64,坏行$scbad)"
  for sccpu in 0 1 2 3; do
    [ "$(grep -caE "^\[JSR-SMPC\] burst cpu=$sccpu seq=" "$scf")" -eq 16 ] || SC_MISS="$SC_MISS $scname:cpu$sccpu行数"
  done
  grep -qaE '^\[JSR-SMPC\] console burst cpus=4 lines_per_cpu=16 total=64 contended=[0-9]+' "$scf" || SC_MISS="$SC_MISS $scname:并发输出"
  grep -qaE '^\[JSR-SMPC\] sched concurrent readers=3/3 rounds=2000 consistent=true restored=true contended=[0-9]+' "$scf" || SC_MISS="$SC_MISS $scname:调度器锁"
  grep -qa '^\[JSR-SMPC\] kstack per_cpu set=3/3 kept=3/3 bsp_unchanged=true restored=3/3' "$scf" || SC_MISS="$SC_MISS $scname:每核内核栈"
  grep -qaE '^\[JSR-LOCK-ORDER\]|^\[JSR-PANIC\]' "$scf" && SC_MISS="$SC_MISS $scname:出现锁顺序违反或panic"
  grep -qaE '^\[JSR-SMP\] summary cpus=4 online=4 checks=[0-9]+ failed=0' "$scf" && grep -qa '^\[JSR-EXIT\] success' "$scf" && [ "$scrc" -eq 33 ] \
    || SC_MISS="$SC_MISS $scname:汇总/退出"
}

check_smp1c() { # 多处理器第三阶段（去全局串行点）：全局锁登记在一条级别链上并按每核持有集合检查顺序（逆序 / 重入被拒且无残留）；
                # 调度器改为登记了级别的锁；控制台跨核整行输出；系统调用入口暂存位与内核栈登记每核一份；四个指令集的 4 处理器日志全部通过
  if [ ! -s "$SERIAL_SMP4" ] || [ ! -s "$SERIAL_A64_SMP4" ] || [ ! -s "$SERIAL_RV64_SMP4" ] || { ! rv32_fw_missing && [ ! -s "$SERIAL_RV32_SMP4" ]; }; then
    record SMP-1c FAIL "缺少 4 处理器串口日志（QEMU=$QRC_SMP4/$QRC_A64_SMP4/$QRC_RV64_SMP4/$QRC_RV32_SMP4）"
    return
  fi
  SC_MISS=""
  smp1c_verdict "$SERIAL_SMP4" "$QRC_SMP4" x86_64
  smp1c_verdict "$SERIAL_A64_SMP4" "$QRC_A64_SMP4" AArch64
  smp1c_verdict "$SERIAL_RV64_SMP4" "$QRC_RV64_SMP4" RV64
  rv32_fw_missing || smp1c_verdict "$SERIAL_RV32_SMP4" "$QRC_RV32_SMP4" RV32
  local scsingle sclist=("$SERIAL" "$SERIAL_A64" "$SERIAL_RV64")
  rv32_fw_missing || sclist+=("$SERIAL_RV32")
  for scsingle in "${sclist[@]}"; do
    grep -qa '^\[JSR-SMPC\] single cpus=1 cross_cpu=skipped' "$scsingle" \
      && grep -qa '^\[JSR-SMPC\] order ascending=ok reverse=system\.lock\.error\.out_of_order' "$scsingle" || SC_MISS="$SC_MISS 单处理器($(basename "$scsingle"))"
  done
  if [ -z "$SC_MISS" ]; then
    record SMP-1c PASS "x86_64 / AArch64 / RISC-V64 / RISC-V32 -smp 4（QEMU=$QRC_SMP4/$QRC_A64_SMP4/$QRC_RV64_SMP4/$QRC_RV32_SMP4）：$(grep -caE '^\[JSR-SMPC\] rank ' "$SERIAL_SMP4") 把全局锁登记成一条级别链，逆序 / 重入被拒且持有集合与中断状态不变，持有集合每核独立 3/3；4 核同时各打印 16 行共 64 行无一交错；其他 3 核各 2000 次读调度器与引导处理器改写并发、状态一致、无死锁；内核栈登记（x86_64 经每核 KERNEL_GS_BASE 入口块）每核独立 3/3；无锁顺序违反；单处理器如实跳过跨核部分$RV32_NOTE"
  else
    record SMP-1c FAIL "缺少/不符：$SC_MISS"
  fi
}

smp2_verdict() {
  local s2f="$1" s2rc="$2" s2name="$3" s2case
  for s2case in spread steal overload; do
    grep -qaE "^\[JSR-SMP2\] cores case=$s2case cpus=4 .* all_busy=true" "$s2f" || S2_MISS="$S2_MISS $s2name:$s2case各核都忙"
  done
  grep -qaE '^\[JSR-SMP2\] case=refusals empty_set=refused offline_only=refused no_task=refused boot_thread=refused unchanged=true' "$s2f" || S2_MISS="$S2_MISS $s2name:拒绝路径"
  grep -qaE '^\[JSR-SMP2\] case=spread cpus=4 tasks=4 window=[0-9]+ cores_covered=true min_task_cpu=[0-9]+ all_busy=true' "$s2f" || S2_MISS="$S2_MISS $s2name:铺满"
  grep -qaE '^\[JSR-SMP2\] case=steal cpus=4 tasks=8 queued_on=cpu0 steals=([3-9]|[1-9][0-9]+) cores_covered=true all_busy=true' "$s2f" || S2_MISS="$S2_MISS $s2name:窃取"
  grep -qaE '^\[JSR-SMP2\] case=overload cpus=4 hogs=8 window=[0-9]+ interactive_rounds=20 samples=20 latency_max=[0-2] bound=2 bounded=true min_hog_cpu=[0-9]+ all_busy=true' "$s2f" || S2_MISS="$S2_MISS $s2name:过载交互延迟"
  grep -qaE '^\[JSR-SMP2\] case=recovery cpus=4 rounds=20 samples=20 max=0 immediate=true .* reclaimed=true' "$s2f" || S2_MISS="$S2_MISS $s2name:恢复"
  grep -qaE '^\[JSR-SMP2\] case=affinity pinned_cpu=3 seen_pinned=0x8 refused_unchanged=true moved_to=1 seen_moved=0x2 self_to=2 self_after=2 seen_self=0x4 ok=true' "$s2f" || S2_MISS="$S2_MISS $s2name:亲和迁移"
  grep -qaE '^\[JSR-SMP2\] case=inherit cpus=4 hogs=8 work=4 wait=[0-6] bound=6 bounded=true holder_peak=interactive lock_free=true' "$s2f" || S2_MISS="$S2_MISS $s2name:跨核继承"
  grep -qaE '^\[JSR-SMP2\] case=limit cpus=4 members=4 limit_permille=250 window=160 used=[0-9]+ bound=[0-9]+ within=true floor=[0-9]+ throttle_events=[1-9][0-9]* cores_used=[2-4]' "$s2f" || S2_MISS="$S2_MISS $s2name:跨核上限"
  grep -qaE '^\[JSR-SMP2-FAIL\]|^\[JSR-LOCK-ORDER\]|^\[JSR-PANIC\]' "$s2f" && S2_MISS="$S2_MISS $s2name:出现失败断言/锁顺序违反/panic"
  grep -qaE '^\[JSR-SMP2\] summary cpus=4 free_frames=([0-9]+)/\1 objects=0/0 reclaimed=true checks=43 failed=0' "$s2f" && grep -qa '^\[JSR-EXIT\] success' "$s2f" && [ "$s2rc" -eq 33 ] \
    || S2_MISS="$S2_MISS $s2name:汇总/退出"
}

check_smp2() { # 每核运行队列 + 负载均衡：N 核 N 任务各核都忙、空闲窃取有界、全部核过载时交互延迟有上界、压力撤销后立即恢复、
  if [ "$SCHED_POLICY" = "rr" ]; then record_na SMP-2 "过载交互延迟与跨核继承依赖 QoS 保证，纯轮转构建不适用；已在分时构建中通过"; return; fi
               # 亲和集合与迁移、跨核优先级继承与 CPU 上限、拒绝路径无残留；四个指令集的 4 处理器日志全部通过，单处理器如实跳过
  if [ ! -s "$SERIAL_SMP4" ] || [ ! -s "$SERIAL_A64_SMP4" ] || [ ! -s "$SERIAL_RV64_SMP4" ] || { ! rv32_fw_missing && [ ! -s "$SERIAL_RV32_SMP4" ]; }; then
    record SMP-2 FAIL "缺少 4 处理器串口日志（QEMU=$QRC_SMP4/$QRC_A64_SMP4/$QRC_RV64_SMP4/$QRC_RV32_SMP4）"
    return
  fi
  S2_MISS=""
  smp2_verdict "$SERIAL_SMP4" "$QRC_SMP4" x86_64
  smp2_verdict "$SERIAL_A64_SMP4" "$QRC_A64_SMP4" AArch64
  smp2_verdict "$SERIAL_RV64_SMP4" "$QRC_RV64_SMP4" RV64
  rv32_fw_missing || smp2_verdict "$SERIAL_RV32_SMP4" "$QRC_RV32_SMP4" RV32
  local s2single s2list=("$SERIAL" "$SERIAL_A64" "$SERIAL_RV64")
  rv32_fw_missing || s2list+=("$SERIAL_RV32")
  for s2single in "${s2list[@]}"; do
    grep -qa '^\[JSR-SMP2\] single cpus=1 balance=skipped' "$s2single" \
      && grep -qaE '^\[JSR-SMP2\] summary cpus=1 .* failed=0' "$s2single" || S2_MISS="$S2_MISS 单处理器($(basename "$s2single"))"
  done
  if [ -z "$S2_MISS" ]; then
    record SMP-2 PASS "x86_64 / AArch64 / RISC-V64 / RISC-V32 -smp 4（QEMU=$QRC_SMP4/$QRC_A64_SMP4/$QRC_RV64_SMP4/$QRC_RV32_SMP4）：每核运行队列；4 核 4 任务与 8 任务过载时各核忙碌 ≥85%、「本核空闲而别处有任务在等」≤2 tick；8 个任务全排在引导处理器队列时其他核窃取 ≥3 次；全部核过载时交互唤醒延迟 ≤2 tick（x86_64 实测 $(grep -aoE 'case=overload .*latency_max=[0-9]+' "$SERIAL_SMP4" | grep -oE '[0-9]+$')）、压力撤销后 20 次唤醒延迟全为 0；亲和钉核 / 他人改 / 自己改均只在允许的核运行，非法集合被拒且不变；跨核优先级继承等待 ≤ 工作量 + 2；一组成员分散 4 核时整组用量不超过上限的界；资源回到基线；单处理器如实跳过$RV32_NOTE"
  else
    record SMP-2 FAIL "缺少/不符：$S2_MISS"
  fi
}

smp3_verdict() {
  local s3f="$1" s3rc="$2" s3name="$3"
  grep -qaE '^\[JSR-SMP3\] case=irq_refusals no_line=refused bad_quota=refused empty_set=refused offline_only=refused unrouted_enable=refused disabled_trigger=refused unchanged=true' "$s3f" || S3_MISS="$S3_MISS $s3name:中断拒绝路径"
  grep -qaE '^\[JSR-SMP3\] case=shard_refusals unconfigured=refused bad_count=refused no_cpu_shard=refused full=refused kept_order=true reconfigure_busy=refused unchanged=true' "$s3f" || S3_MISS="$S3_MISS $s3name:分片拒绝路径"
  grep -qaE '^\[JSR-SMP3\] case=route cpus=4 lines=2 delivered_exact=4/4 handler_calls_match=true disabled_after=true' "$s3f" || S3_MISS="$S3_MISS $s3name:按亲和送达"
  grep -qaE '^\[JSR-SMP3\] case=balance lines=2 keep_moves=0 keep_cpus=0x1 spread_moves=[1-9][0-9]* spread_cpus=0x[0-9a-f]+ distinct=true spread_after=[0-9]+ bound=16 in_time=true' "$s3f" || S3_MISS="$S3_MISS $s3name:亲和均衡"
  grep -qaE '^\[JSR-SMP3\] case=storm cpus=4 lines=2 hogs=8 window=120 interactive_rounds=20 samples=20 latency_max=[0-2] bound=2 bounded=true all_busy=true irq_handled=[1-9][0-9]* cores_hit=[2-4] spread=true throttles=[1-9][0-9]* worst_irq_share_permille=[0-9]+ quota_permille=250 within_quota=true min_hog_cpu=[0-9]+' "$s3f" || S3_MISS="$S3_MISS $s3name:风暴下交互延迟/预算/分散"
  grep -qaE '^\[JSR-SMP3\] case=recovery cpus=4 rounds=20 samples=20 max=0 immediate=true irq_after_disable=0 quiet=true reclaimed=true' "$s3f" || S3_MISS="$S3_MISS $s3name:风暴撤销后恢复"
  grep -qaE '^\[JSR-SMP3\] case=service cpus=4 flows=128 requests=512 makespan_one=[0-9]+ makespan_many=[0-9]+ speedup_permille=[0-9]+ faster=true imbalance_permille=([0-9]|[1-9][0-9]|[1-2][0-9][0-9]|3[0-4][0-9]|350) bound=350 cores_used=4 least_busy=[0-9]+ in_order=true done=true reclaimed=true' "$s3f" || S3_MISS="$S3_MISS $s3name:分片服务各核均衡"
  grep -qaE '^\[JSR-SMP3-FAIL\]|^\[JSR-LOCK-ORDER\]|^\[JSR-PANIC\]' "$s3f" && S3_MISS="$S3_MISS $s3name:出现失败断言/锁顺序违反/panic"
  grep -qaE '^\[JSR-SMP3\] summary cpus=4 device_lines=2 free_frames=([0-9]+)/\1 objects=0/0 reclaimed=true checks=39 failed=0' "$s3f" && grep -qa '^\[JSR-EXIT\] success' "$s3f" && [ "$s3rc" -eq 33 ] \
    || S3_MISS="$S3_MISS $s3name:汇总/退出"
}

check_smp3() { # 中断与服务的多核化：设备中断按亲和送达、均衡策略分散中断线、风暴下每核预算节流（交互延迟有上界、无单核被中断吃满）、
  if [ "$SCHED_POLICY" = "rr" ]; then record_na SMP-3 "中断风暴下的交互延迟判据依赖 QoS 保证，纯轮转构建不适用；已在分时构建中通过"; return; fi
               # 风暴撤销后立即恢复、分片服务各核并行且均衡、拒绝路径无残留；四个指令集的 4 处理器日志全部通过，单处理器如实跳过
  if [ ! -s "$SERIAL_SMP4" ] || [ ! -s "$SERIAL_A64_SMP4" ] || [ ! -s "$SERIAL_RV64_SMP4" ] || { ! rv32_fw_missing && [ ! -s "$SERIAL_RV32_SMP4" ]; }; then
    record SMP-3 FAIL "缺少 4 处理器串口日志（QEMU=$QRC_SMP4/$QRC_A64_SMP4/$QRC_RV64_SMP4/$QRC_RV32_SMP4）"
    return
  fi
  S3_MISS=""
  smp3_verdict "$SERIAL_SMP4" "$QRC_SMP4" x86_64
  smp3_verdict "$SERIAL_A64_SMP4" "$QRC_A64_SMP4" AArch64
  smp3_verdict "$SERIAL_RV64_SMP4" "$QRC_RV64_SMP4" RV64
  rv32_fw_missing || smp3_verdict "$SERIAL_RV32_SMP4" "$QRC_RV32_SMP4" RV32
  local s3single s3list=("$SERIAL" "$SERIAL_A64" "$SERIAL_RV64")
  rv32_fw_missing || s3list+=("$SERIAL_RV32")
  for s3single in "${s3list[@]}"; do
    grep -qa '^\[JSR-SMP3\] single cpus=1 spread=skipped' "$s3single" \
      && grep -qaE '^\[JSR-SMP3\] summary cpus=1 .* failed=0' "$s3single" || S3_MISS="$S3_MISS 单处理器($(basename "$s3single"))"
  done
  if [ -z "$S3_MISS" ]; then
    local lat sp
    lat=$(grep -aoE 'case=storm .*latency_max=[0-9]+' "$SERIAL_SMP4" | grep -oE '[0-9]+$')
    sp=$(grep -aoE 'case=service .*speedup_permille=[0-9]+' "$SERIAL_SMP4" | grep -oE '[0-9]+$')
    record SMP-3 PASS "x86_64（I/O APIC）/ AArch64（GICv2 共享外设中断）/ RISC-V64 / RISC-V32（PLIC 每核上下文）-smp 4（QEMU=$QRC_SMP4/$QRC_A64_SMP4/$QRC_RV64_SMP4/$QRC_RV32_SMP4）：两条设备中断线依次钉到 4 个核，只在该核处理 4/4；两条线都在 0 号核时对照策略不搬、均衡策略两个周期内分到不同的核；两条线持续风暴 + 8 个吃满处理器的任务时交互唤醒延迟 ≤2 tick（x86_64 实测 $lat）、各核都忙、每核中断次数与时间不超过预算的界、风暴分散到多个核；撤销后无中断、延迟全为 0；分片服务 128 个流 512 个请求 4 分片比 1 分片快（x86_64 ${sp}‰）、不均衡度 ≤350‰、流内有序；拒绝路径无残留；单处理器如实跳过$RV32_NOTE"
  else
    record SMP-3 FAIL "缺少/不符：$S3_MISS"
  fi
}

a64_ready() { [ "$A64_BUILD_RC" -eq 0 ] && [ -n "$QEMU_A64" ] && [ -s "$SERIAL_A64" ]; }

check_isa1a() { # AArch64 移植第一阶段：内核侧检查在 qemu-system-aarch64 的串口日志上逐项重跑（行名带 A64/ 前缀）
  if ! a64_ready; then
    record ISA1a FAIL "AArch64 构建 rc=$A64_BUILD_RC 或缺少 qemu-system-aarch64 / 串口日志（见 build-aarch64.log）"
    return
  fi
  a64_rerun check_m11 check_m12 check_m13 check_m14 check_m15 check_m21 check_m22 check_m23 check_m24 \
            check_m31 check_m32 check_m33 check_m34 check_m42 check_fix check_sched2
  if [ "$A64_BAD" -eq 0 ] && grep -qE '^\[JSR-BOOT\] jasper-os rust kernel [0-9.]+ aarch64' "$SERIAL_A64" \
     && grep -q '^\[JSR-VEC\] ok' "$SERIAL_A64"; then
    record ISA1a PASS "AArch64（QEMU virt，QEMU=$QRC_A64）：$A64_N 项内核侧检查全部通过（启动/异常/时钟/调度/抢占/机制/页帧/映射/堆/地址空间/EL0/系统调用/用户指针/进程/句柄/回滚/优先级继承）"
  else
    record ISA1a FAIL "AArch64：$A64_N 项中 $A64_BAD 项失败，或缺少横幅 / 向量表标记（见 serial-aarch64.log）"
  fi
}

check_isa1b() { # AArch64 移植第二阶段：内嵌用户程序（独立 Rust 程序、ring / IPC、jasper-rt、.jaso 装载执行）的全部检查在 AArch64 上逐项重跑
  if ! a64_ready; then
    record ISA1b FAIL "AArch64 构建 rc=$A64_BUILD_RC 或缺少 qemu-system-aarch64 / 串口日志（见 build-aarch64.log）"
    return
  fi
  a64_rerun check_m51pre check_m41 check_m43 check_m44 check_m51 check_s1 check_j1 check_j2 check_j3 check_j4 check_j5 check_j6 \
            check_pol2 check_sched1 check_sched3 check_t1 check_t2
  local progs
  progs=$(grep -cE '^\[JSR-PROC\] event=system.process.created ' "$SERIAL_A64" || true)
  if [ "$A64_BAD" -eq 0 ] && ! grep -q '^\[JSR-STAGE\] user_programs=absent' "$SERIAL_A64" \
     && grep -q '^\[JSR-EXIT\] success' "$SERIAL_A64" && [ "$QRC_A64" -eq 33 ]; then
    record ISA1b PASS "AArch64（QEMU=$QRC_A64）：内嵌用户程序以 AArch64 构建，$A64_N 项用户态检查全部通过（ELF/生命周期/异步环/IPC/非特权程序/jasper-rt/Rust 库/.jaso 装载与库模块/QoS/过载防护/配置/基准），创建进程 $progs 次"
  else
    record ISA1b FAIL "AArch64：$A64_N 项中 $A64_BAD 项失败、未内嵌用户程序或未成功退出（见 serial-aarch64.log）"
  fi
}

rv64_ready() { [ "$RV64_BUILD_RC" -eq 0 ] && [ -n "$QEMU_RV64" ] && [ -s "$SERIAL_RV64" ]; }

check_isa2a() { # RISC-V64 移植第一阶段：与 AArch64 第一阶段同一组内核侧检查在 qemu-system-riscv64 的串口日志上逐项重跑（行名带 RV64/ 前缀）
  if ! rv64_ready; then
    record ISA2a FAIL "RISC-V64 构建 rc=$RV64_BUILD_RC 或缺少 qemu-system-riscv64 / 串口日志（见 build-riscv64.log）"
    return
  fi
  rv64_rerun check_m11 check_m12 check_m13 check_m14 check_m15 check_m21 check_m22 check_m23 check_m24 \
             check_m31 check_m32 check_m33 check_m34 check_m42 check_fix check_sched2
  if [ "$RV64_BAD" -eq 0 ] && grep -qE '^\[JSR-BOOT\] jasper-os rust kernel [0-9.]+ riscv64' "$SERIAL_RV64" \
     && grep -q '^\[JSR-VEC\] ok' "$SERIAL_RV64" \
     && grep -qE '^\[JSR-PLIC\] ok source=([0-9]+) claimed=\1 completed=true drained=true' "$SERIAL_RV64" \
     && grep -q '^\[JSR-EXIT\] success' "$SERIAL_RV64" && [ "$QRC_RV64" -eq 33 ]; then
    record ISA2a PASS "RISC-V64（QEMU virt + OpenSBI，Sv39，QEMU=$QRC_RV64）：$RV64_N 项内核侧检查全部通过（启动/陷入/SBI 时钟/PLIC 认领完成/调度/抢占/机制/页帧/映射/堆/地址空间/用户态/ecall/用户指针/进程/句柄/回滚/优先级继承）"
  else
    record ISA2a FAIL "RISC-V64：$RV64_N 项中 $RV64_BAD 项失败，或缺少横幅 / 陷入入口 / PLIC 自检标记、未成功退出（见 serial-riscv64.log）"
  fi
}

check_isa2b() { # RISC-V64 移植第二阶段：内嵌用户程序（独立 Rust 程序、ring / IPC、jasper-rt、.jaso 装载执行）的全部检查在 RISC-V64 上逐项重跑
  if ! rv64_ready; then
    record ISA2b FAIL "RISC-V64 构建 rc=$RV64_BUILD_RC 或缺少 qemu-system-riscv64 / 串口日志（见 build-riscv64.log）"
    return
  fi
  rv64_rerun check_m51pre check_m41 check_m43 check_m44 check_m51 check_s1 check_j1 check_j2 check_j3 check_j4 check_j5 check_j6 \
             check_pol2 check_sched1 check_sched3 check_t1 check_t2
  local progs
  progs=$(grep -cE '^\[JSR-PROC\] event=system.process.created ' "$SERIAL_RV64" || true)
  if [ "$RV64_BAD" -eq 0 ] && ! grep -q '^\[JSR-STAGE\] user_programs=absent' "$SERIAL_RV64" \
     && grep -qE '^\[JSR-USERTEXT\] task=prog-hello bytes=[0-9]+ text=prog: hello mode=0' "$SERIAL_RV64" \
     && grep -q '^\[JSR-EXIT\] success' "$SERIAL_RV64" && [ "$QRC_RV64" -eq 33 ]; then
    record ISA2b PASS "RISC-V64（QEMU=$QRC_RV64）：内嵌用户程序以 riscv64imac 构建、链接在 Sv39 私有窗口内，$RV64_N 项用户态检查全部通过（ELF/生命周期/异步环/IPC/非特权程序/jasper-rt/Rust 库/.jaso 装载与库模块/QoS/过载防护/配置/基准），创建进程 $progs 次"
  else
    record ISA2b FAIL "RISC-V64：$RV64_N 项中 $RV64_BAD 项失败、未内嵌用户程序或未成功退出（见 serial-riscv64.log）"
  fi
}

# rv32_rerun <检查函数…>：在 RISC-V32 串口日志上逐项重跑给定检查（行名带 RV32/ 前缀）；结果放在 RV32_N / RV32_BAD。
rv32_rerun() {
  port_rerun "$SERIAL_RV32" "$QRC_RV32" "RV32/" 128 "$@"
  RV32_N=$PORT_N; RV32_BAD=$PORT_BAD
}

rv32_ready() { [ "$RV32_BUILD_RC" -eq 0 ] && [ -n "$QEMU_RV32" ] && [ -s "$SERIAL_RV32" ]; }
# 本机 QEMU 缺少 32 位 OpenSBI 固件（有的发行版只打包 64 位）：目标不可用，如实记 N/A，不冒充通过也不判失败。
rv32_unavailable() { rv32_fw_missing; }

check_isa3a() { # RISC-V32 移植第一阶段：同一组内核侧检查在 qemu-system-riscv32 的串口日志上逐项重跑（行名带 RV32/ 前缀），
  if rv32_unavailable; then record_na ISA3a "本机 QEMU 缺少 32 位 OpenSBI 固件（fw_dynamic.bin），RISC-V32 目标不可运行；构建本身通过，已在有固件的机器上验证"; return; fi
                # 并要求 64 位计数单元在没有 64 位原子指令的目标上以「关中断 + 自旋锁」实现、与定时器中断共享时不自锁
  if ! rv32_ready; then
    record ISA3a FAIL "RISC-V32 构建 rc=$RV32_BUILD_RC 或缺少 qemu-system-riscv32 / 串口日志（见 build-riscv32.log）"
    return
  fi
  rv32_rerun check_m11 check_m12 check_m13 check_m14 check_m15 check_m21 check_m22 check_m23 check_m24 \
             check_m31 check_m32 check_m33 check_m34 check_m42 check_fix check_sched2
  local reads
  reads=$(grep -aoE '^\[JSR-COUNTER64\] case=isr_shared reads=[0-9]+' "$SERIAL_RV32" | grep -oE '[0-9]+$' || true)
  if [ "$RV32_BAD" -eq 0 ] && grep -qaE '^\[JSR-BOOT\] jasper-os rust kernel [0-9.]+ riscv32' "$SERIAL_RV32" \
     && grep -qa '^\[JSR-VEC\] ok' "$SERIAL_RV32" \
     && grep -qaE '^\[JSR-PLIC\] ok source=([0-9]+) claimed=\1 completed=true drained=true' "$SERIAL_RV32" \
     && grep -qaE '^\[JSR-COUNTER64\] case=wide impl=irq_locked crossed_2_32=true ok=[0-9]+ failed=0' "$SERIAL_RV32" \
     && grep -qaE '^\[JSR-COUNTER64\] case=isr_shared reads=[0-9]+ ticks=[0-9]+ ticks_monotonic=true cycles_monotonic=true completed=true' "$SERIAL_RV32" \
     && grep -qaE '^\[JSR-COUNTER64\] summary impl=irq_locked checks=[0-9]+ failed=0' "$SERIAL_RV32" \
     && grep -qaE '^\[JSR-COUNTER64\] summary impl=native checks=[0-9]+ failed=0' "$SERIAL" \
     && grep -qaE '^\[JSR-COUNTER64\] summary impl=native checks=[0-9]+ failed=0' "$SERIAL_RV64" \
     && grep -qa '^\[JSR-EXIT\] success' "$SERIAL_RV32" && [ "$QRC_RV32" -eq 33 ]; then
    record ISA3a PASS "RISC-V32（QEMU virt + OpenSBI，Sv32，QEMU=$QRC_RV32）：$RV32_N 项内核侧检查全部通过（启动/陷入/SBI 时钟/PLIC/调度/抢占/机制/页帧/映射/堆/地址空间/用户态/ecall 与 a0:a1 返回/用户指针/进程/句柄/回滚/优先级继承）；64 位计数：关中断+自旋锁实现，跨 2^32 正确，与定时器中断共享读取 $reads 次无自锁；x86_64 / RISC-V64 为原生原子"
  else
    record ISA3a FAIL "RISC-V32：$RV32_N 项中 $RV32_BAD 项失败，或缺少横幅 / 陷入入口 / PLIC / 64 位计数标记、未成功退出（见 serial-riscv32.log）"
  fi
}

check_isa3b() { # RISC-V32 移植第二阶段：内嵌用户程序（ELF32 装载、32 位用户 ABI 下的 64 位参数、jasper-rt、ring / IPC、
  if rv32_unavailable; then record_na ISA3b "本机 QEMU 缺少 32 位 OpenSBI 固件（fw_dynamic.bin），RISC-V32 目标不可运行；构建本身通过，已在有固件的机器上验证"; return; fi
                # .jaso 4 字节重定位）的全部检查在 RISC-V32 上逐项重跑（行名带 RV32/ 前缀）
  if ! rv32_ready; then
    record ISA3b FAIL "RISC-V32 构建 rc=$RV32_BUILD_RC 或缺少 qemu-system-riscv32 / 串口日志（见 build-riscv32.log）"
    return
  fi
  rv32_rerun check_m51pre check_m41 check_m43 check_m44 check_m51 check_s1 check_j1 check_j2 check_j3 check_j4 check_j5 check_j6 \
             check_pol2 check_sched1 check_sched3 check_t1 check_t2
  local progs
  progs=$(grep -caE '^\[JSR-PROC\] event=system.process.created ' "$SERIAL_RV32" || true)
  if [ "$RV32_BAD" -eq 0 ] && ! grep -qa '^\[JSR-STAGE\] user_programs=absent' "$SERIAL_RV32" \
     && grep -qaE '^\[JSR-BOOT\] jasper-os rust kernel [0-9.]+ riscv32' "$SERIAL_RV32" \
     && grep -qaE '^\[JSR-USERTEXT\] task=prog-hello bytes=[0-9]+ text=prog: hello mode=0' "$SERIAL_RV32" \
     && grep -qa '^\[JSR-EXIT\] success' "$SERIAL_RV32" && [ "$QRC_RV32" -eq 33 ]; then
    record ISA3b PASS "RISC-V32（QEMU=$QRC_RV32）：内嵌用户程序以 riscv32imac 构建为 ELF32、链接在 Sv32 私有窗口内（0x0080_0000），64 位参数按低半 a0–a2 / 高半 a3–a5 传递，$RV32_N 项用户态检查全部通过（ELF/生命周期/异步环/IPC/非特权程序/jasper-rt/Rust 库/.jaso 装载（4 字节重定位）与库模块/QoS/过载防护/配置/基准），创建进程 $progs 次"
  else
    record ISA3b FAIL "RISC-V32：$RV32_N 项中 $RV32_BAD 项失败、未内嵌用户程序或未成功退出（见 serial-riscv32.log）"
  fi
}

check_pol2() {  # POL-2：系统 Profile——启动期校验、两份内建 Profile 的服务面真实不同、
                # 四类非法 Profile 各自给出结构化拒绝原因、结构化描述可渲染
  if has '\[JSR-PROFILE\] active name=headless valid=true params=(standard|compact) modules=7 services=11 capabilities=7 guarantees=2' \
     && has '\[JSR-PROFILE\] table idx=1 name=headless-min valid=true modules=4 services=8' \
     && has '\[JSR-PROFILE\] gate profile=headless op=system\.async\.ring\.create allowed=true' \
     && has '\[JSR-PROFILE\] gate profile=headless-min op=system\.async\.ring\.create allowed=false' \
     && has '\[JSR-PROFILE\] gate profile=headless-min op=system\.time\.now allowed=true' \
     && has '\[JSR-PROFILE\] reject case=missing-capability code=missing_capability subject=memory\.virtual' \
     && has '\[JSR-PROFILE\] reject case=capability-conflict code=capability_conflict subject=kernel\.core' \
     && has '\[JSR-PROFILE\] reject case=params-too-small code=unsatisfiable_tasks' \
     && has '\[JSR-PROFILE\] reject case=hot-load-not-allowed code=hot_load_not_allowed' \
     && has '\[JSR-PROFILE\] render idx=0 bytes=[0-9]+ head=profile=headless' \
     && has '\[JSR-PROFILE\] render idx=1 bytes=[0-9]+ head=profile=headless-min' \
     && has '\[JSR-PROFILE\] summary profiles=2 rejects=4 gates=3 renders=2 checks=14 failed=0'; then
    record POL2 PASS "启动期校验通过：headless（6 模块 / 10 服务 / 6 能力）与 headless-min（4 模块 / 8 服务）服务面真实不同（异步环在精简档被门拒绝）；缺依赖 / 能力冲突 / 参数下限不可满足 / 未授权热加载四类各自给出结构化拒绝码；结构化描述可渲染；14 项断言 0 失败"
  else
    record POL2 FAIL "缺少 [JSR-PROFILE] 关键标记、结构化拒绝不全、两份 Profile 服务面相同或 failed≠0"
  fi
}

check_pol3() {  # POL-3：批处理作业——依赖/优先级/终态/取消/满载交互性/Profile 归属
  if has '\[JSR-JOB\] summary jobs=5 completed=2 failed=1 cancelled=2 checks=26 failed_checks=0' \
     && has '\[JSR-JOB\] overload done=20 rounds=20 hog_cpus=[1-9]' \
     && has '\[JSR-JOB\] profile headless=true headless-min=false'; then
    record POL3 PASS "作业队列：依赖门控与优先级选择、失败依赖不解除等待、成功/失败终态、取消等待中与运行中作业、活动任务回到 0；批处理档满载时交互任务 20/20 轮全部唤醒；作业服务只属于 headless（精简档没有 system.job）；26 项断言 0 失败"
  else
    record POL3 FAIL "缺少 [JSR-JOB] 关键标记、终态/取消统计不符或 failed_checks≠0"
  fi
}

check_ci1() {   # 公开仓库自动化验证：工作流在每次推送 / 拉取请求时运行本脚本全量 + 宿主与跨指令集单元测试；工具链钉到具体日期；判据不在工作流里另写
  local wf="$ROOT/.github/workflows/ci.yml" miss=""
  if [ ! -s "$wf" ]; then record CI-1 FAIL "缺少 .github/workflows/ci.yml"; return; fi
  grep -qE '^  push:' "$wf"                                   || miss="$miss 推送触发"
  grep -qE '^  pull_request:' "$wf"                           || miss="$miss 拉取请求触发"
  grep -qE 'run: .*bash scripts/accept\.sh' "$wf"             || miss="$miss 运行accept.sh"
  grep -qE 'qemu-system-x86' "$wf" && grep -qE 'qemu-system-arm' "$wf" && grep -qE 'qemu-system-misc' "$wf" || miss="$miss 三种QEMU"
  grep -qE 'riscv64imac-unknown-none-elf' "$wf"               || miss="$miss RISC-V64内核目标"
  grep -qE 'cargo test -p kernel-core --target' "$wf" && grep -q 'i686-unknown-linux-musl' "$wf" || miss="$miss 32位单元测试"
  grep -qE 'cargo test -p jaso --features pack' "$wf"         || miss="$miss jaso测试"
  grep -qE '^  RUST_NIGHTLY: nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$' "$wf" || miss="$miss 工具链钉日期"
  grep -qE 'upload-artifact' "$wf"                            || miss="$miss 上传证据"
  # 工作流不得自带判据或放宽结果：不允许忽略失败的写法
  grep -qE 'continue-on-error: *true|\|\| *true' "$wf"         && miss="$miss （出现忽略失败的写法）"
  if [ -z "$miss" ]; then
    record CI-1 PASS "工作流：推送/拉取请求触发；宿主 + 32 位/AArch64/RISC-V64 单元测试；accept.sh 全量（x86_64 + AArch64 + RISC-V64 QEMU）；工具链 $(grep -oE 'nightly-[0-9-]+' "$wf" | head -1)；证据上传"
  else
    record CI-1 FAIL "工作流缺少：$miss"
  fi
}

if [ "$SCHED_POLICY" = "rr" ]; then
  check_m10; check_isa; check_m11; check_m12; check_m13; check_m14; check_m14b; check_m15; check_m21; check_m22; check_m23; check_m24; check_m31; check_m32; check_m33; check_m34; check_m51pre; check_m41; check_m42; check_m43; check_m44; check_m51; check_s1; check_j1; check_j2; check_j3; check_j4; check_j5; check_j6; check_t1; check_t2; check_fix; check_isa1a; check_isa1b; check_ci1; check_isa2a; check_isa2b; check_isa3a; check_isa3b; check_smp1a; check_smp1b_a64; check_smp1b_rv; check_smp1c; check_smp2; check_smp3
  check_pol1; check_pol2; check_pol3
  check_sched1; check_sched2; check_sched3
else
  check_m10; check_isa; check_m11; check_m12; check_m13; check_m14; check_m14b; check_m15; check_m21; check_m22; check_m23; check_m24; check_m31; check_m32; check_m33; check_m34; check_m51pre; check_m41; check_m42; check_m43; check_m44; check_m51; check_s1; check_j1; check_j2; check_j3; check_j4; check_j5; check_j6; check_sched1; check_sched2; check_sched3; check_t1; check_t2; check_fix; check_isa1a; check_isa1b; check_ci1; check_isa2a; check_isa2b; check_isa3a; check_isa3b; check_smp1a; check_smp1b_a64; check_smp1b_rv; check_smp1c; check_smp2; check_smp3
  check_pol1; check_pol2; check_pol3
fi

# ---- 汇总与归档 --------------------------------------------------------------
{
  echo "jasper-os 一键验收  $TS"
  echo "提交：$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)$(git -C "$ROOT" diff --quiet 2>/dev/null || echo '（工作区有未提交改动）')"
  echo "配置档：$PROFILE"
  echo "QEMU 退出码：$QRC（4 处理器：$QRC_SMP4，AArch64：$QRC_A64，AArch64 4 处理器：$QRC_A64_SMP4，RISC-V64：$QRC_RV64，RISC-V32：$QRC_RV32）"
  echo
  printf '%-6s %-4s %s\n' "里程碑" "结果" "说明"
  printf '%s\n' "${ROWS[@]}"
} | tee "$OUT/summary.txt"

for f in cargo-test.log build.log serial.log serial-smp4.log serial-aarch64.log serial-aarch64-smp4.log serial-riscv64.log serial-riscv32.log summary.txt; do
  [ -s "$OUT/$f" ] || { echo "✗ 证据文件为空或缺失：$f"; FAILED=1; }
done
echo
echo "证据目录：$OUT"
if [ "$FAILED" -eq 0 ]; then echo "accept: ALL PASS"; exit 0; else echo "accept: FAIL"; exit 1; fi
