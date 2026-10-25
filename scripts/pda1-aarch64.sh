#!/bin/bash
# =============================================================================
# pda1-aarch64.sh —— PDA-1：arm64 Image 头 + DTB 摘要的 QEMU 真实启动验收
#
# 做什么（全部在构建虚拟机内执行）：
#   1. 以 aarch64-unknown-none-softfloat 构建现有内核（不内嵌用户程序）；
#   2. 用 scripts/aarch64-image.sh 生成 Linux arm64 `Image`；
#   3. qemu-system-aarch64 -M virt -kernel <Image> 真实启动，检查
#      `[JSR-IMG] header=ok` 与结构化的 `[JSR-DTB]` 字段；
#   4. 把 flags 改成大端、把 image_size 改大，各启动一次，要求内核以
#      结构化原因拒绝（退出码 35），而不是继续跳转；
#   5. 原始串口日志与汇总表归档到 evidence/pda1-<时间戳>/。
#
# 退出码：0 = 全部 PASS；1 = 至少一项 FAIL；2 = 环境缺失。
#
# 关于退出码 35：当前 main 上的 AArch64 单核启动仍会运行 x86_64 专用的
# PCI / MSI / KRN-0 演练并计入失败（Q66 的修复尚未合入 main）。本脚本只
# 允许这一组**已登记**的基线失败，任何新的失败项或基线项数值变化都判 FAIL，
# 因而能真实检测“AArch64 功能行回归”。
# =============================================================================
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || { echo "✗ 无法进入仓库根目录"; exit 2; }

TARGET="aarch64-unknown-none-softfloat"
ELF="target/$TARGET/release/jasper-kernel"
IMG="images/pda1-aarch64-Image"
BAD_FLAGS="images/pda1-aarch64-Image-bad-flags"
BAD_SIZE="images/pda1-aarch64-Image-bad-size"
TS="$(date '+%Y%m%d-%H%M%S')"
OUT="evidence/pda1-$TS"
QEMU_TIMEOUT="${JASPER_QEMU_TIMEOUT:-180}"
export PATH="$HOME/.cargo/bin:$PATH"

mkdir -p "$OUT" images
command -v cargo >/dev/null || { echo "✗ 找不到 cargo"; exit 2; }
QEMU="$(command -v qemu-system-aarch64 || true)"
[ -n "$QEMU" ] || { echo "✗ 找不到 qemu-system-aarch64"; exit 2; }

PASS=0
FAIL=0
ROWS=()
record() {
  local status="$1" name="$2" detail="$3"
  if [ "$status" = PASS ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi
  ROWS+=("$(printf '%-4s %-28s %s' "$status" "$name" "$detail")")
}

echo "== 构建 AArch64 内核 =="
if cargo build --release --target "$TARGET" -p jasper-kernel --no-default-features > "$OUT/build.log" 2>&1; then
  record PASS build-aarch64 "target=$TARGET"
else
  record FAIL build-aarch64 "见 build.log"
  printf '%s\n' "${ROWS[@]}"
  echo "✗ 构建失败"
  exit 1
fi

echo "== 生成 arm64 Image =="
if bash scripts/aarch64-image.sh "$ELF" "$IMG" > "$OUT/image.log" 2>&1; then
  record PASS image-layout "$(cat "$OUT/image.log")"
else
  record FAIL image-layout "见 image.log"
  cat "$OUT/image.log"
  printf '%s\n' "${ROWS[@]}"
  exit 1
fi

boot() {
  local label="$1" image="$2"
  local log="$OUT/serial-$label.log"
  timeout "$QEMU_TIMEOUT" "$QEMU" -M virt -cpu cortex-a72 -m 256M -kernel "$image" \
    -append "console=ttyAMA0 pda1=1" -semihosting -serial stdio \
    -display none -monitor none -no-reboot > "$log" 2>&1
  echo "$?"
}

check_contains() {
  local label="$1" log="$2" text="$3"
  if grep -aFq -- "$text" "$log"; then
    record PASS "$label" "$text"
  else
    record FAIL "$label" "缺少：$text"
  fi
}

echo "== QEMU 真实启动（arm64 Image） =="
RC="$(boot single "$IMG")"
LOG="$OUT/serial-single.log"

check_contains img-magic "$LOG" "[JSR-IMG] header=ok"
check_contains dtb-fdt "$LOG" "[JSR-DTB] fdt=ok"
check_contains dtb-memory "$LOG" "[JSR-DTB] memory=0x40000000+0x10000000"
check_contains dtb-bootargs "$LOG" '[JSR-DTB] bootargs="console=ttyAMA0 pda1=1"'
check_contains dtb-psci "$LOG" "[JSR-DTB] psci=compatible=arm,psci-1.0 method=hvc cpu_on=0xc4000003"
check_contains dtb-gic "$LOG" "[JSR-DTB] gic=compatible=arm,cortex-a15-gic kind=v2 dist=0x8000000 cpu=0x8010000"
check_contains dtb-timer "$LOG" "[JSR-DTB] timer=arm,armv8-timer ppi=27"
check_contains dtb-serial "$LOG" "[JSR-DTB] serial=compatible=arm,pl011 base=0x9000000 size=0x1000 irq=33"
check_contains dtb-framebuffer "$LOG" "[JSR-DTB] framebuffer=none"
check_contains dtb-missing "$LOG" "[JSR-DTB] missing=framebuffer"
check_contains kernel-main "$LOG" "[JSR-BOOT] jasper-os rust kernel"

if python3 - "$LOG" "$RC" <<'PY'
import re
import sys
from pathlib import Path

log_path, rc = sys.argv[1], int(sys.argv[2])
text = Path(log_path).read_text(errors="replace")
line = next((l for l in text.splitlines() if "[JSR-EXIT]" in l), None)
# 已登记的基线：main 上尚未合入 Q66 的 AArch64 x86 专用演练。
baseline = {"pci_failed": 4, "msi_failed": 2, "krn0_failed": 1}
if rc in (33, 37):
    if line is not None:
        print(f"✗ 退出码 {rc} 但出现失败行：{line}")
        sys.exit(1)
    sys.exit(0)
if rc != 35:
    print(f"✗ 退出码 {rc} 既不是成功（33/37）也不是功能失败（35）")
    sys.exit(1)
if line is None:
    print("✗ 退出码 35 但没有 [JSR-EXIT] 失败行")
    sys.exit(1)
values = {k: int(v) for k, v in re.findall(r"([a-z0-9_]+_failed)=(\d+)", line)}
if not values:
    print(f"✗ 无法解析失败行：{line}")
    sys.exit(1)
unexpected = {k: v for k, v in values.items() if v and k not in baseline}
mismatch = {k: v for k, v in values.items() if k in baseline and v != baseline[k]}
if unexpected or mismatch:
    print(f"✗ AArch64 功能行回归：新失败={unexpected} 基线变化={mismatch}")
    sys.exit(1)
print("基线失败：" + " ".join(f"{k}={v}" for k, v in sorted(values.items()) if v))
PY
then
  record PASS boot-exit "rc=$RC（仅已登记基线失败）"
else
  record FAIL boot-exit "rc=$RC"
fi

# ---- 拒绝路径 1：flags 声明大端 ------------------------------------------------
echo "== QEMU 拒绝路径（flags 大端） =="
python3 - "$IMG" "$BAD_FLAGS" <<'PY'
import struct
import sys
src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, "rb").read())
flags = struct.unpack_from("<Q", data, 0x18)[0]
struct.pack_into("<Q", data, 0x18, flags | 1)
open(dst, "wb").write(data)
PY
RC_BAD="$(boot bad-flags "$BAD_FLAGS")"
LOG_BAD="$OUT/serial-bad-flags.log"
if [ "$RC_BAD" -eq 35 ] && grep -aFq "[JSR-IMG] reject=system.boot.error.image_big_endian" "$LOG_BAD"; then
  record PASS reject-big-endian "rc=$RC_BAD"
else
  record FAIL reject-big-endian "rc=$RC_BAD（期望 35 + image_big_endian）"
fi

# ---- 拒绝路径 2：image_size 与真实跨度不符 -------------------------------------
echo "== QEMU 拒绝路径（image_size 不符） =="
python3 - "$IMG" "$BAD_SIZE" <<'PY'
import struct
import sys
src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, "rb").read())
size = struct.unpack_from("<Q", data, 0x10)[0]
struct.pack_into("<Q", data, 0x10, size + 0x1000)
open(dst, "wb").write(data)
PY
RC_SIZE="$(boot bad-size "$BAD_SIZE")"
LOG_SIZE="$OUT/serial-bad-size.log"
if [ "$RC_SIZE" -eq 35 ] && grep -aFq "[JSR-IMG] reject=system.boot.error.image_size_mismatch" "$LOG_SIZE"; then
  record PASS reject-image-size "rc=$RC_SIZE"
else
  record FAIL reject-image-size "rc=$RC_SIZE（期望 35 + image_size_mismatch）"
fi

# ---- 汇总 ---------------------------------------------------------------------
{
  echo "# PDA-1 AArch64 Image / DTB acceptance ($TS)"
  echo
  printf '%s\n' "${ROWS[@]}"
  echo
  echo "PASS=$PASS FAIL=$FAIL"
  echo "证据：$OUT（原始串口日志 serial-*.log）"
} | tee "$OUT/summary.txt"

if [ "$FAIL" -ne 0 ]; then
  echo "accept: PDA-1 FAIL"
  exit 1
fi
echo "accept: PDA-1 PASS"
