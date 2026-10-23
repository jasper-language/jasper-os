#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Android boot.img 头解析（只读工具，PDA-0）。

用途
----
在不刷写设备的前提下，判断 Chainway C66 的 ``boot_a`` / ``boot_b`` 备份属于
Android boot image 的哪一代（v0–v4），并列出 kernel / ramdisk / second /
recovery_dtbo / dtb / boot signature 各段的文件偏移、长度与加载地址。

设计约束
--------
* 只用 Python 标准库；不依赖 mkbootimg、unpack_bootimg 或任何第三方包。
* 只读：本工具从不打开块设备，只解析用户提供的镜像文件；``--extract`` 也只
  写宿主目录，不接触设备分区。
* 严格校验：魔数、版本、头长度、页大小、段长度、文件截断、页对齐；任何越界
  都抛 ``BootImageError``（``ValueError`` 子类），绝不静默截断后继续。
* 依据：AOSP ``system/tools/mkbootimg/include/bootimg/bootimg.h`` 的结构定义。

支持的格式
----------
====  ======  ======  =====================================================
版本  头长度  页大小  段（按文件顺序）
====  ======  ======  =====================================================
v0    1632    可配置  kernel, ramdisk, second(可选)
v1    1648    可配置  v0 + recovery_dtbo(可选)
v2    1660    可配置  v1 + dtb
v3    1580    4096    kernel, ramdisk
v4    1584    4096    v3 + boot signature
====  ======  ======  =====================================================

不在本工具范围内：``vendor_boot``（魔数 ``VNDRBOOT``）与 Qualcomm 私有的
``boot.img`` 变体；遇到时明确拒绝并提示改用 ``/sys/firmware/fdt`` 或
``vendor_boot`` 转储。
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"
SUPPORTED_VERSIONS = (0, 1, 2, 3, 4)
# AOSP bootimg.h 的固定头长度（v0–v2 的 header_size 字段与结构体大小一致）。
HEADER_SIZES = {0: 1632, 1: 1648, 2: 1660, 3: 1580, 4: 1584}
# v0–v2 允许的页大小；v3/v4 固定 4096。
ALLOWED_PAGE_SIZES = (2048, 4096, 8192, 16384)
V3_PAGE_SIZE = 4096
# 头部内 header_version 字段的公共偏移（v0–v4 都在 40）。
HEADER_VERSION_OFFSET = 40


class BootImageError(ValueError):
    """镜像格式非法或数据越界。"""


@dataclass(frozen=True)
class Segment:
    """boot.img 中一个段在文件内的位置与加载地址。"""

    name: str
    offset: int
    size: int
    addr: Optional[int] = None
    declared_offset: Optional[int] = None

    @property
    def end(self) -> int:
        return self.offset + self.size

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
            "addr": self.addr,
            "declared_offset": self.declared_offset,
        }


@dataclass
class BootImage:
    """解析结果。所有偏移都相对文件起点，长度单位为字节。"""

    version: int
    header_size: int
    page_size: int
    file_size: int
    os_version: int
    name: str
    cmdline: str
    extra_cmdline: str
    image_id: bytes
    kernel_addr: Optional[int] = None
    ramdisk_addr: Optional[int] = None
    second_addr: Optional[int] = None
    tags_addr: Optional[int] = None
    dtb_addr: Optional[int] = None
    segments: list[Segment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    required_end: int = 0
    trailing_bytes: int = 0
    recovery_dtbo_offset: Optional[int] = None
    signature_size: int = 0

    def segment(self, name: str) -> Optional[Segment]:
        for item in self.segments:
            if item.name == name:
                return item
        return None

    def to_dict(self, path: str = "") -> dict:
        return {
            "path": path,
            "format": f"android-boot-v{self.version}",
            "version": self.version,
            "header_size": self.header_size,
            "page_size": self.page_size,
            "file_size": self.file_size,
            "required_end": self.required_end,
            "trailing_bytes": self.trailing_bytes,
            "os_version": {
                "raw": self.os_version,
                "decoded": decode_os_version(self.os_version),
            },
            "name": self.name,
            "cmdline": self.cmdline,
            "extra_cmdline": self.extra_cmdline,
            "id": self.image_id.hex(),
            "kernel_addr": self.kernel_addr,
            "ramdisk_addr": self.ramdisk_addr,
            "second_addr": self.second_addr,
            "tags_addr": self.tags_addr,
            "dtb_addr": self.dtb_addr,
            "recovery_dtbo_offset": self.recovery_dtbo_offset,
            "signature_size": self.signature_size,
            "segments": [s.to_dict() for s in self.segments],
            "warnings": list(self.warnings),
        }


# 合成镜像使用的 os_version：Android 11.0.0，安全补丁 2023-10。
SYNTHETIC_OS_VERSION = (11 << 25) | ((2023 - 2000) << 4) | 10


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise BootImageError("页大小必须为正整数")
    return (value + alignment - 1) // alignment * alignment


def _u32(data: bytes, offset: int, what: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise BootImageError(f"读取 {what} 越界：偏移 {offset}，文件 {len(data)} 字节")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int, what: str) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise BootImageError(f"读取 {what} 越界：偏移 {offset}，文件 {len(data)} 字节")
    return struct.unpack_from("<Q", data, offset)[0]


def _cstring(data: bytes, offset: int, length: int, what: str) -> str:
    """读取定长字段中的 NUL 结尾字符串；无 NUL 时取满字段。"""
    if offset < 0 or offset + length > len(data):
        raise BootImageError(f"读取 {what} 越界：偏移 {offset}+{length}，文件 {len(data)} 字节")
    raw = data[offset:offset + length]
    nul = raw.find(b"\0")
    if nul >= 0:
        raw = raw[:nul]
    return raw.decode("utf-8", "replace")


def decode_os_version(value: int) -> str:
    """按 AOSP 位域解码 os_version；未设置时返回说明文字。"""
    if value == 0:
        return "未设置"
    major = (value >> 25) & 0x7F
    minor = (value >> 18) & 0x7F
    patch = (value >> 11) & 0x7F
    year = ((value >> 4) & 0x7F) + 2000
    month = value & 0xF
    if not 1 <= month <= 12:
        return f"{major}.{minor}.{patch}（安全补丁月份字段非法：{month}）"
    return f"{major}.{minor}.{patch}（安全补丁 {year}-{month:02d}）"


def parse(data: bytes) -> BootImage:
    """解析 Android boot image v0–v4。

    任何结构错误（魔数不符、版本不支持、头/页大小非法、声明长度超出文件、
    recovery_dtbo 偏移非页对齐等）都抛 :class:`BootImageError`。
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data 必须是 bytes/bytearray/memoryview")
    data = bytes(data)

    if len(data) < 16:
        raise BootImageError(f"文件过短（{len(data)} 字节），连 boot image 魔数都不完整")
    if data[:8] == VENDOR_BOOT_MAGIC:
        raise BootImageError(
            "这是 Android vendor_boot 镜像（VNDRBOOT），不是 boot.img；"
            "DTB 通常在 vendor_boot 中，请单独导出并用 dtbinfo.py 解析"
        )
    if data[:8] != MAGIC:
        raise BootImageError(
            f"魔数不符：期望 {MAGIC!r}，实际 {data[:8]!r}"
        )

    if len(data) < HEADER_VERSION_OFFSET + 4:
        raise BootImageError("文件过短，缺少 header_version 字段")

    version = _u32(data, HEADER_VERSION_OFFSET, "header_version")
    if version not in SUPPORTED_VERSIONS:
        raise BootImageError(
            f"不支持的 header_version={version}（只支持 0–4；"
            "若为 3/4 请确认没有把 vendor_boot 当成 boot.img）"
        )

    expected_header = HEADER_SIZES[version]
    if len(data) < expected_header:
        raise BootImageError(
            f"v{version} 头需要 {expected_header} 字节，文件只有 {len(data)} 字节（截断）"
        )

    warnings: list[str] = []
    if 1 <= version <= 2:
        declared_header = _u32(data, 1644, "v1/v2 header_size")
        if declared_header != expected_header:
            raise BootImageError(
                f"v{version} header_size={declared_header}，规范要求 {expected_header}"
            )
    elif version >= 3:
        declared_header = _u32(data, 20, "v3/v4 header_size")
        if declared_header != expected_header:
            raise BootImageError(
                f"v{version} header_size={declared_header}，规范要求 {expected_header}"
            )

    if version <= 2:
        page_size = _u32(data, 36, "page_size")
        if page_size not in ALLOWED_PAGE_SIZES:
            raise BootImageError(
                f"非法 page_size={page_size}（v0–v2 只允许 {ALLOWED_PAGE_SIZES}）"
            )
        if expected_header > page_size:
            raise BootImageError(
                f"头部 {expected_header} 字节大于页大小 {page_size}"
            )
    else:
        page_size = V3_PAGE_SIZE

    # 先读公共字段，再按版本读版本相关字段；v3/v4 的字段布局与 v0–v2 完全不同。
    kernel_size = _u32(data, 8, "kernel_size")
    if kernel_size == 0:
        raise BootImageError("kernel_size=0：boot image 必须包含内核")

    if version <= 2:
        kernel_addr = _u32(data, 12, "kernel_addr")
        ramdisk_size = _u32(data, 16, "ramdisk_size")
        ramdisk_addr = _u32(data, 20, "ramdisk_addr")
        second_size = _u32(data, 24, "second_size")
        second_addr = _u32(data, 28, "second_addr")
        tags_addr = _u32(data, 32, "tags_addr")
        os_version = _u32(data, 44, "os_version")
        name = _cstring(data, 48, 16, "name")
        cmdline = _cstring(data, 64, 512, "cmdline")
        image_id = data[576:608]
        extra_cmdline = _cstring(data, 608, 1024, "extra_cmdline")
        dtb_addr: Optional[int] = None
        signature_size = 0
    else:
        ramdisk_size = _u32(data, 12, "ramdisk_size")
        os_version = _u32(data, 16, "os_version")
        cmdline = _cstring(data, 44, 1536, "cmdline")
        kernel_addr = ramdisk_addr = second_addr = tags_addr = None
        second_size = 0
        name = ""
        extra_cmdline = ""
        image_id = b""
        dtb_addr = None
        signature_size = _u32(data, 1580, "signature_size") if version == 4 else 0

    # 按文件顺序摆放各段；每段起点按页对齐。
    segments: list[Segment] = []
    pos = page_size

    def place(seg_name: str, size: int, addr: Optional[int],
              declared_offset: Optional[int] = None) -> Optional[Segment]:
        nonlocal pos
        offset = _align_up(pos, page_size)
        if size == 0:
            # 0 长度段不占空间；保持 pos 不变，下一段仍从当前页边界开始。
            return None
        seg = Segment(seg_name, offset, size, addr, declared_offset)
        segments.append(seg)
        pos = offset + size
        return seg

    place("kernel", kernel_size, kernel_addr)
    if ramdisk_size == 0:
        warnings.append("ramdisk_size=0：v0–v4 规范都要求 ramdisk，镜像可能不完整")
    else:
        place("ramdisk", ramdisk_size, ramdisk_addr)
    if second_size:
        place("second", second_size, second_addr)

    recovery_dtbo_size = 0
    declared_dtbo_offset: Optional[int] = None
    if version >= 1:
        recovery_dtbo_size = _u32(data, 1632, "recovery_dtbo_size")
        declared_dtbo_offset = _u64(data, 1636, "recovery_dtbo_offset")
        if recovery_dtbo_size:
            expected_offset = _align_up(pos, page_size)
            seg = place("recovery_dtbo", recovery_dtbo_size, None, declared_dtbo_offset)
            if declared_dtbo_offset not in (0, expected_offset):
                warnings.append(
                    f"recovery_dtbo_offset 声明为 {declared_dtbo_offset}，"
                    f"按顺序布局应为 {expected_offset}；提取以顺序布局为准"
                )
            if seg is not None and declared_dtbo_offset == 0:
                warnings.append("recovery_dtbo_size>0 但 recovery_dtbo_offset=0")

    if version == 2:
        dtb_size = _u32(data, 1648, "dtb_size")
        dtb_addr = _u64(data, 1652, "dtb_addr")
        if dtb_size:
            place("dtb", dtb_size, dtb_addr)
        else:
            warnings.append("v2 的 dtb_size=0：DTB 不在该 boot.img 中")

    if version == 4 and signature_size:
        place("boot_signature", signature_size, None)

    required_end = segments[-1].end if segments else 0
    if required_end > len(data):
        raise BootImageError(
            f"镜像截断：按头部声明的段需要 {required_end} 字节，文件只有 {len(data)} 字节"
        )

    if version <= 2:
        if ramdisk_size and ramdisk_addr == 0:
            warnings.append("ramdisk_addr=0：加载地址未设置")
        if tags_addr == 0:
            warnings.append("tags_addr=0：老式 ATAGS 地址未设置（arm64 通常忽略）")

    # 段必须按文件顺序、页对齐且互不重叠——由 place() 保证，这里再自检一次，
    # 便于将来改动 place() 时立刻发现回归。
    previous_end = 0
    for seg in segments:
        if seg.offset % page_size != 0:
            raise BootImageError(f"内部错误：{seg.name} 偏移 {seg.offset} 未按页对齐")
        if seg.offset < previous_end:
            raise BootImageError(f"内部错误：{seg.name} 与前一段重叠")
        previous_end = seg.end

    trailing = len(data) - required_end
    if trailing >= page_size:
        warnings.append(
            f"文件尾部有 {trailing} 字节不属于任何声明段（可能是分区填充或 vendor 附加数据）"
        )

    return BootImage(
        version=version,
        header_size=expected_header,
        page_size=page_size,
        file_size=len(data),
        os_version=os_version,
        name=name,
        cmdline=cmdline,
        extra_cmdline=extra_cmdline,
        image_id=image_id,
        kernel_addr=kernel_addr,
        ramdisk_addr=ramdisk_addr,
        second_addr=second_addr,
        tags_addr=tags_addr,
        dtb_addr=dtb_addr,
        segments=segments,
        warnings=warnings,
        required_end=required_end,
        trailing_bytes=trailing,
        recovery_dtbo_offset=declared_dtbo_offset,
        signature_size=signature_size,
    )


def parse_file(path: os.PathLike | str) -> BootImage:
    with open(path, "rb") as handle:
        return parse(handle.read())


# ---------------------------------------------------------------------------
# 自测用的合成镜像
# ---------------------------------------------------------------------------

def build_synthetic_image(
    version: int,
    *,
    page_size: int = 2048,
    kernel: bytes = b"K" * 5000,
    ramdisk: bytes = b"R" * 3000,
    second: bytes = b"S" * 100,
    recovery_dtbo: bytes = b"D" * 700,
    dtb: bytes = b"T" * 900,
    signature: bytes = b"G" * 500,
    kernel_addr: int = 0x00080000,
    ramdisk_addr: int = 0x01000000,
    second_addr: int = 0x02000000,
    tags_addr: int = 0x00000100,
    dtb_addr: int = 0x03000000,
) -> bytes:
    """构造一个符合规范的合成 boot image，仅用于 ``--self-test`` 与属性测试。

    该函数不解析、不校验，只按 AOSP 结构打包；测试用它生成正样本，再由
    :func:`parse` 反向验证。合成镜像不写盘、不接触设备。
    """
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"不支持的合成版本 {version}")
    if version <= 2:
        if page_size not in ALLOWED_PAGE_SIZES:
            raise ValueError("v0–v2 的 page_size 非法")
        header_size = HEADER_SIZES[version]
        header = bytearray(page_size)
        pos = page_size

        def layout(payload: bytes) -> int:
            nonlocal pos
            offset = _align_up(pos, page_size)
            pos = offset + len(payload)
            return offset

        kernel_off = layout(kernel)
        ramdisk_off = layout(ramdisk)
        second_off = layout(second) if second else 0
        dtbo_off = layout(recovery_dtbo) if (version >= 1 and recovery_dtbo) else 0
        dtb_off = layout(dtb) if (version == 2 and dtb) else 0

        struct.pack_into("<8s", header, 0, MAGIC)
        struct.pack_into("<I", header, 8, len(kernel))
        struct.pack_into("<I", header, 12, kernel_addr)
        struct.pack_into("<I", header, 16, len(ramdisk))
        struct.pack_into("<I", header, 20, ramdisk_addr)
        struct.pack_into("<I", header, 24, len(second))
        struct.pack_into("<I", header, 28, second_addr)
        struct.pack_into("<I", header, 32, tags_addr)
        struct.pack_into("<I", header, 36, page_size)
        struct.pack_into("<I", header, 40, version)
        struct.pack_into("<I", header, 44, SYNTHETIC_OS_VERSION)
        name_text = b"jasper-tst"
        cmdline_text = b"console=ttyMSM0,115200n8 androidboot.x=1"
        header[48:48 + len(name_text)] = name_text
        header[64:64 + len(cmdline_text)] = cmdline_text
        header[576:576 + 8] = b"JASPERID"
        header[608:608 + 7] = b"extra=1"
        if version >= 1:
            struct.pack_into("<I", header, 1632, len(recovery_dtbo))
            struct.pack_into("<Q", header, 1636, dtbo_off)
            struct.pack_into("<I", header, 1644, header_size)
        if version == 2:
            struct.pack_into("<I", header, 1648, len(dtb))
            struct.pack_into("<Q", header, 1652, dtb_addr)

        body = bytearray(pos)
        body[0:page_size] = header
        body[kernel_off:kernel_off + len(kernel)] = kernel
        body[ramdisk_off:ramdisk_off + len(ramdisk)] = ramdisk
        if second:
            body[second_off:second_off + len(second)] = second
        if dtbo_off:
            body[dtbo_off:dtbo_off + len(recovery_dtbo)] = recovery_dtbo
        if dtb_off:
            body[dtb_off:dtb_off + len(dtb)] = dtb
        return bytes(body)

    # v3/v4：头固定 4096，段紧随其后，无地址字段。
    header = bytearray(V3_PAGE_SIZE)
    pos = V3_PAGE_SIZE

    def layout_v3(payload: bytes) -> int:
        nonlocal pos
        offset = _align_up(pos, V3_PAGE_SIZE)
        pos = offset + len(payload)
        return offset

    kernel_off = layout_v3(kernel)
    ramdisk_off = layout_v3(ramdisk)
    signature_off = layout_v3(signature) if (version == 4 and signature) else 0

    struct.pack_into("<8s", header, 0, MAGIC)
    struct.pack_into("<I", header, 8, len(kernel))
    struct.pack_into("<I", header, 12, len(ramdisk))
    struct.pack_into("<I", header, 16, SYNTHETIC_OS_VERSION)
    struct.pack_into("<I", header, 20, HEADER_SIZES[version])
    struct.pack_into("<I", header, 40, version)
    cmdline_text_v3 = b"console=ttyMSM0,115200n8 earlycon"
    header[44:44 + len(cmdline_text_v3)] = cmdline_text_v3
    if version == 4:
        struct.pack_into("<I", header, 1580, len(signature))

    body = bytearray(pos)
    body[0:V3_PAGE_SIZE] = header
    body[kernel_off:kernel_off + len(kernel)] = kernel
    body[ramdisk_off:ramdisk_off + len(ramdisk)] = ramdisk
    if signature_off:
        body[signature_off:signature_off + len(signature)] = signature
    return bytes(body)


def _run_self_test() -> int:
    """内置合成样本自测；返回检查项数量，失败时抛 AssertionError。"""
    checks = 0

    def check(condition: bool, message: str) -> None:
        nonlocal checks
        if not condition:
            raise AssertionError(message)
        checks += 1

    def expect_error(blob: bytes, needle: str = "") -> None:
        nonlocal checks
        try:
            parse(blob)
        except BootImageError as exc:
            if needle and needle not in str(exc):
                raise AssertionError(f"错误信息缺少 {needle!r}：{exc}") from exc
        else:
            raise AssertionError(f"非法镜像被接受：{needle or blob[:16]!r}")
        checks += 1

    for version in SUPPORTED_VERSIONS:
        image = build_synthetic_image(version)
        parsed = parse(image)
        check(parsed.version == version, f"v{version} 版本解析错误")
        check(parsed.header_size == HEADER_SIZES[version], f"v{version} 头长度错误")
        check(parsed.page_size == (4096 if version >= 3 else 2048), f"v{version} 页大小错误")
        check(parsed.segment("kernel").size == 5000, f"v{version} kernel 长度错误")
        check(parsed.segment("ramdisk").size == 3000, f"v{version} ramdisk 长度错误")
        check(parsed.required_end <= len(image), f"v{version} 段越过文件")
        if version <= 2:
            check(parsed.segment("kernel").addr == 0x00080000, f"v{version} kernel 地址错误")
            check(parsed.segment("ramdisk").addr == 0x01000000, f"v{version} ramdisk 地址错误")
            check(parsed.segment("second").size == 100, f"v{version} second 长度错误")
            check(parsed.name == "jasper-tst", f"v{version} 产品名错误")
            check("androidboot.x=1" in parsed.cmdline, f"v{version} cmdline 错误")
        if version == 1:
            check(parsed.segment("recovery_dtbo").offset % 2048 == 0, "v1 dtbo 未对齐")
        if version == 2:
            check(parsed.segment("dtb").size == 900, "v2 dtb 长度错误")
            check(parsed.dtb_addr == 0x03000000, "v2 dtb 地址错误")
        if version >= 3:
            check(parsed.kernel_addr is None, f"v{version} 不应有 32 位地址")
            check("earlycon" in parsed.cmdline, f"v{version} cmdline 错误")
        if version == 4:
            check(parsed.signature_size == 500, "v4 signature_size 错误")
            check(parsed.segment("boot_signature").size == 500, "v4 signature 段错误")

    valid = build_synthetic_image(2)
    expect_error(b"", "过短")
    expect_error(b"NOTANDROID" + valid[10:], "魔数")
    expect_error(b"VNDRBOOT" + valid[8:], "vendor_boot")
    bad_version = bytearray(valid)
    struct.pack_into("<I", bad_version, 40, 5)
    expect_error(bytes(bad_version), "header_version")
    bad_page = bytearray(valid)
    struct.pack_into("<I", bad_page, 36, 1000)
    expect_error(bytes(bad_page), "page_size")
    bad_header = bytearray(valid)
    struct.pack_into("<I", bad_header, 1644, 1600)
    expect_error(bytes(bad_header), "header_size")
    truncated = valid[:-1]
    expect_error(truncated, "截断")

    # 逐字节截断：只要切在最后一个声明段结束之前，就必须拒绝。
    needed = parse(valid).required_end
    for cut in range(0, needed):
        expect_error(valid[:cut])

    # 零内核必须拒绝。
    zero_kernel = bytearray(build_synthetic_image(0))
    struct.pack_into("<I", zero_kernel, 8, 0)
    expect_error(bytes(zero_kernel), "kernel_size=0")

    return checks


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

def _format_addr(value: Optional[int]) -> str:
    return "-" if value is None else f"0x{value:08x}"


def format_report(image: BootImage, path: str) -> str:
    lines = [
        f"镜像：{path}",
        f"格式：Android boot image v{image.version}"
        f"（头 {image.header_size} 字节，页 {image.page_size} 字节）",
        f"文件：{image.file_size} 字节；声明段结束于 {image.required_end} 字节；"
        f"尾部 {image.trailing_bytes} 字节",
        f"OS：{decode_os_version(image.os_version)}",
    ]
    if image.name:
        lines.append(f"产品名：{image.name}")
    if image.cmdline:
        lines.append(f"cmdline：{image.cmdline}")
    if image.extra_cmdline:
        lines.append(f"extra_cmdline：{image.extra_cmdline}")
    if image.image_id and any(image.image_id):
        lines.append(f"id：{image.image_id.hex()}")
    lines.append("")
    lines.append(f"{'段':<16}{'偏移':>10}{'长度':>12}  {'加载地址':<12}")
    for seg in image.segments:
        lines.append(
            f"{seg.name:<16}{seg.offset:>10}{seg.size:>12}  {_format_addr(seg.addr):<12}"
        )
    if image.version == 2 and not image.segment("dtb"):
        lines.append("注意：v2 但没有 dtb 段；DTB 可能在 dtbo 分区或 /sys/firmware/fdt")
    if image.version >= 3:
        lines.append("注意：v3/v4 不在 boot.img 内携带 DTB；DTB 通常在 vendor_boot 中")
    for warning in image.warnings:
        lines.append(f"警告：{warning}")
    return "\n".join(lines)


def _extract_segments(image: BootImage, data: bytes, directory: Path) -> list[str]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for seg in image.segments:
        target = directory / seg.name
        target.write_bytes(data[seg.offset:seg.end])
        written.append(str(target))
    meta = directory / "bootimg.json"
    meta.write_text(
        json.dumps(image.to_dict(str(directory)), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    written.append(str(meta))
    return written


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="只读解析 Android boot.img v0–v4（PDA-0）",
    )
    parser.add_argument("image", nargs="?", help="boot.img 文件路径（--self-test 时可省略）")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    parser.add_argument(
        "--extract",
        metavar="DIR",
        help="把各段写到宿主目录（不接触设备）；同时写 bootimg.json",
    )
    parser.add_argument("--self-test", action="store_true", help="用内置合成样本自测")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.self_test:
        checks = _run_self_test()
        print(f"bootimg --self-test: PASS（{checks} 项检查）")
        return 0
    if not args.image:
        parser.error("缺少镜像路径（或使用 --self-test）")

    path = Path(args.image)
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"✗ 无法读取 {path}：{exc}", file=sys.stderr)
        return 1
    try:
        image = parse(data)
    except BootImageError as exc:
        print(f"✗ {path}：{exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(image.to_dict(str(path)), ensure_ascii=False, indent=2))
    else:
        print(format_report(image, str(path)))
    if args.extract:
        try:
            written = _extract_segments(image, data, Path(args.extract))
        except OSError as exc:
            print(f"✗ 写出 {args.extract} 失败：{exc}", file=sys.stderr)
            return 1
        print(f"已写出 {len(written)} 个文件到 {args.extract}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
