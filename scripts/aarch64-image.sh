#!/bin/bash
# =============================================================================
# aarch64-image.sh —— 把 AArch64 内核 ELF 转成 Linux arm64 `Image`（PDA-1）
#
# 用法：bash scripts/aarch64-image.sh <内核 ELF> <输出 Image>
#
# 做什么：
#   1. 用 Rust 工具链自带的 rust-objcopy 把 ELF 的已装载段压成平坦二进制；
#   2. 从偏移 0x10 读出链接脚本写入的 image_size；
#   3. 用 0 补齐到 image_size（BSS 是 NOBITS，不在 ELF 文件里，但必须占住
#      QEMU / 引导器计算的映像范围）；
#   4. 校验魔数 `ARM\x64`、image_size 边界与 code0 跳转指令，任何一项不符即失败。
#
# 只使用仓库内相对路径；rust-objcopy 由 rust-toolchain.toml 的 llvm-tools-preview
# 组件提供，不依赖 PATH 上的交叉工具链。
# =============================================================================
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "用法：bash scripts/aarch64-image.sh <内核 ELF> <输出 Image>" >&2
  exit 2
fi
ELF="$1"
OUT="$2"
[ -f "$ELF" ] || { echo "✗ 找不到 ELF：$ELF" >&2; exit 2; }

SYSROOT="$(rustc --print sysroot)"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
OBJCOPY="$SYSROOT/lib/rustlib/$HOST/bin/rust-objcopy"
if [ ! -x "$OBJCOPY" ]; then
  OBJCOPY="$(command -v rust-objcopy || true)"
fi
[ -n "$OBJCOPY" ] && [ -x "$OBJCOPY" ] || {
  echo "✗ 找不到 rust-objcopy（需要 rust-toolchain.toml 里的 llvm-tools-preview 组件）" >&2
  exit 2
}

TMP="${OUT}.flat.tmp"
"$OBJCOPY" -O binary "$ELF" "$TMP"

python3 - "$TMP" "$OUT" <<'PY'
import struct
import sys

flat_path, out_path = sys.argv[1], sys.argv[2]
data = open(flat_path, "rb").read()
if len(data) < 64:
    sys.exit(f"✗ 平坦二进制只有 {len(data)} 字节，放不下 64 字节 Image 头")
if data[0x38:0x3C] != b"ARM\x64":
    sys.exit(f"✗ 偏移 0x38 的魔数不是 ARM\\x64：{data[0x38:0x3C]!r}")
code0 = struct.unpack_from("<I", data, 0)[0]
if (code0 & 0xFC000000) != 0x14000000:
    sys.exit(f"✗ code0 不是 B 指令：0x{code0:08x}")
text_offset = struct.unpack_from("<Q", data, 0x08)[0]
image_size = struct.unpack_from("<Q", data, 0x10)[0]
flags = struct.unpack_from("<Q", data, 0x18)[0]
if image_size < 64 or image_size > (1 << 30):
    sys.exit(f"✗ image_size 不合理：0x{image_size:x}")
if text_offset % (2 * 1024 * 1024):
    sys.exit(f"✗ text_offset 未按 2 MiB 对齐：0x{text_offset:x}")
if len(data) > image_size:
    sys.exit(f"✗ 平坦二进制 {len(data)} 字节超过头部声明的 image_size 0x{image_size:x}")
data += b"\0" * (image_size - len(data))
open(out_path, "wb").write(data)
print(f"aarch64-image: {out_path} size=0x{image_size:x} text_offset=0x{text_offset:x} flags=0x{flags:x}")
PY
rm -f "$TMP"
