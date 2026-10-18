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
# 用法：  bash scripts/accept.sh            （默认：机器最后 4 个逻辑核，最低 CPU 与 I/O 优先级）
#         JASPER_CORES=8-11 bash scripts/accept.sh
# 为什么默认用最后几个核：前几个核（尤其 CPU 0）通常承担显卡、硬盘等设备中断与按核的内核后台工作；
# 把它们压满会让桌面失去响应。构建与 QEMU 一律以 nice 19 / ionice 空闲级运行，桌面需要时随时让出。
# 退出码：0 = 全部 PASS；1 = 至少一项 FAIL；2 = 环境缺失（无 cargo / qemu）
# =============================================================================
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NCPU="$(nproc --all 2>/dev/null || echo 4)"
if [ "$NCPU" -ge 8 ]; then DEFAULT_CORES="$((NCPU - 4))-$((NCPU - 1))"; else DEFAULT_CORES="0-$((NCPU > 1 ? NCPU - 2 : 0))"; fi
CORES="${JASPER_CORES:-$DEFAULT_CORES}"
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
run cargo test -p jaso --features pack > "$OUT/jaso-test.log" 2>&1;                           JASO_RC=$?
run cargo build --release --target x86_64-unknown-none -p kernel-core > "$OUT/build.log" 2>&1; CORE_RC=$?
run cargo build --release --target x86_64-unknown-none -p jasper-kernel >> "$OUT/build.log" 2>&1 \
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
     && has 'quota rings=8 ninth=Some\(-4111\) in_flight=256 over=Some\(-4111\) unchanged_on_reject=true returned=true' \
     && has '^\[JSR-RING\] objects_live=([0-9]+)/\1 pending=0 reclaimed=true checks=[0-9]+ failed=0'; then
    record M4.3 PASS "用户态 ring 提交→完成；cq_full 原子失败；信用耗尽可同步取消；信用消费时归还；取消结果表与窗口；closing 各类收尾；配额；回到基线"
  else
    record M4.3 FAIL "缺少 JSR-RING / user-ring 关键标记或 failed≠0"
  fi
}

check_m44() {   # IPC Channel：用户程序（单进程语义 + 跨进程往返）+ 内核侧（取消映射 / 共享缓冲区 / 延迟后端 / 叶子回收 / 句柄表满）
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
     && has 'byte_quota accepted=64 rejected=16 charged=Some\(4194304\) returned=true' \
     && has '^\[JSR-IPC\] objects_live=([0-9]+)/\1 pending=0 pinned=\(0, 0\) reclaimed=true checks=[0-9]+ failed=0'; then
    record M4.4 PASS "send/recv 经 ring；两阶段 send；原子交付（缓冲区/句柄表不足消息保留）；取消竞争；关闭语义；跨进程句柄往返；页帧固定；回到基线"
  else
    record M4.4 FAIL "缺少 JSR-IPC / user-ipc 关键标记或 failed≠0"
  fi
}

check_m51() {   # 最小非特权程序：特权级 3；读内核内存只杀该进程；特权/无效指令；坏指针被拒；多线程终止 + 父进程等待；内核内阻塞时终止；回到基线
  if has '^\[JSR-USERTEXT\] task=prog-hello bytes=[0-9]+ text=prog: hello cpl=3' \
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
     && has 'text=jasodemo: rejected tamper=Some\(Format\(DigestMismatch\)\) truncated=Some\(Format\(LengthMismatch\)\) arch=Some\(WrongArch\(Aarch64\)\) stage=Some\(WrongStage\(Boot\)\) caps=Some\(MissingCapability\("system\.console\.write"\)\) host=Some\(HostRequired\) init=Some\(MissingInit\)' \
     && has 'text=jasodemo: ok checks=[0-9]+' \
     && has 'case=jasodemo exit=Some\(0\) expect=0 reclaimed=true'; then
    record J-3 PASS "格式宿主测试 $(grep -oE '[0-9]+ passed' "$OUT/jaso-test.log" | head -1)；W^X 改权限；.jaso 装入/重定位/设权限/初始化/调用导出、两实例数据独立、卸载后映射消失；篡改/截断/指令集/阶段/能力/宿主表/初始化入口均被拒；回到基线"
  else
    record J-3 FAIL "jaso 宿主测试 rc=${JASO_RC:-?}，或缺少 jasodemo / protect 关键标记"
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

check_sched1() { # 调度策略 + QoS：档位规则（拒绝且不变、继承、上限）；动态任务数；过载下用户发起档唤醒延迟有上界、后台有进展；压力撤销后立即恢复；回到基线
  if has 'policy=qos preemption=default_on' \
     && has '\[JSR-QOS\] case=rules boot_refused=true steps=7/7 raise_refused_unchanged=true inherit=true ceiling=true reclaimed=true' \
     && has '\[JSR-QOS\] case=many capacity=64 spawned=40 done=40 peak_live=40 full_refused=true fillers=63 reclaimed=true' \
     && has 'text=schedtest: mode=qos qos_rules invalid_refused=true raise_refused=true same_ok=true' \
     && has 'text=schedtest: mode=qos busy_ticks=[0-9]+ background_progressed=true' \
     && has 'text=schedtest: mode=qos joined=4 all_progressed=true' \
     && has 'text=schedtest: mode=same_class joined=4 all_progressed=true' \
     && has '\[JSR-QOS\] case=overload mode=qos exit=Some\(0\) samples=[1-9][0-9]* p50=0 p99=[01] max=[01] bound=1 bounded=true .*reclaimed=true' \
     && has '\[JSR-QOS\] case=overload mode=same_class exit=Some\(0\) samples=[1-9][0-9]* .* bounded=true .*reclaimed=true' \
     && has '\[JSR-QOS\] case=recovery rounds=20 samples=20 max=0 immediate=true reclaimed=true' \
     && has '^\[JSR-QOS\] summary free_frames=([0-9]+)/\1 objects=([0-9]+)/\2 reclaimed=true checks=[0-9]+ failed=0'; then
    record SCHED1 PASS "QoS 四档：降档/不变允许、升档被拒且档位不变、继承与上限；64 槽位、40 任务并发；4 个吃满 CPU 线程下用户发起档唤醒延迟有上界、后台有进展；压力撤销后延迟 0；回到基线"
  else
    record SCHED1 FAIL "缺少 JSR-QOS 关键标记、延迟超界或 failed≠0"
  fi
}

check_sched2() { # 优先级继承：三任务反转（锁 / 等退出）有界、关闭继承对照可见反转、传递继承、拒绝路径无残留、持有者退出可接管、压力撤销后恢复、回到基线
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

check_fix() {   # 基础设施修复回归：失败路径与回滚（已退出接收方、堆扩容、内核空间预分配、只读翻译、ID 用尽、线程创建）
  if has 'exited_receiver grant=Some\(Exited\) grant_new=Some\(Exited\) transfer=Some\(Exited\) objects_unchanged=true sender_kept=true reaped_receiver=Some\(NoSuchProcess\)' \
     && has 'heap fail_alloc=Some\(OutOfFrames\) rolled_back=true fail_map=Some\(MapFailed\) rolled_back=true overflow=Some\(LimitReached\) regrow=true reclaimed=true' \
     && has 'kernel_space ready=true used=256 fail=Some\(OutOfFrames\) untouched=true frames_returned=true ok=Some\(256\) reclaimed=true refuse_when_unready=true' \
     && has 'translate same_as_mapper=true unmapped_none=true kernel_not_user=true reclaimed=true' \
     && has 'ids last=Some\(18446744073709551615\) after_exhausted=None again=None no_wrap=true' \
     && has 'spawn zero_stack=Some\(Map\(InvalidAddress\)\) objects_full=Some\(NoTaskSlot\) restored=true sched_full=Some\(NoTaskSlot\) \(fillers [1-9][0-9]*\) restored=true retry_exit=Some\(Exited \{ code: 42 \}\)' \
     && has '^\[JSR-FIX\] objects_live=([0-9]+)/\1 pending=0 checks=[0-9]+ failed=0' \
     && ! has 'warning residual_handles'; then
    record FIX PASS "失败路径全部回滚到基线；回滚后可再次成功；无残余句柄告警"
  else
    record FIX FAIL "缺少 JSR-FIX 关键标记、failed≠0 或出现残余句柄告警"
  fi
}

check_m10; check_isa; check_m11; check_m12; check_m13; check_m14; check_m14b; check_m15; check_m21; check_m22; check_m23; check_m24; check_m31; check_m32; check_m33; check_m34; check_m51pre; check_m41; check_m42; check_m43; check_m44; check_m51; check_j1; check_j2; check_j3; check_j4; check_sched1; check_sched2; check_fix

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
