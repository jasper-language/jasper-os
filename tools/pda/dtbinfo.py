#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flattened Device Tree（FDT/DTB）只读解析与启动节点摘要（PDA-0）。

用途
----
解析 ABL 传给内核的 DTB（或从 ``/sys/firmware/fdt`` 导出的同一份数据），列出
PDA-1/PDA-2 启动所需的节点：``memory``、``chosen``（含 cont-splash 帧缓冲）、
``interrupt-controller``（GICv3）、架构定时器、``psci``、串口，以及辅助的
``cpus`` / ``reserved-memory`` / ``aliases``。

设计约束
--------
* 只用 Python 标准库；不依赖 libfdt、dtc 或任何第三方包。
* 只读：只解析文件，不写设备、不修改 DTB。
* 严格边界检查：魔数、版本、totalsize、结构块/字符串块/保留内存块偏移、
  属性长度、字符串 NUL 结尾、节点嵌套深度、重复属性/兄弟节点全部校验；
  任何越界都抛 :class:`FdtError`（``ValueError`` 子类）。
* 只支持 FDT 版本 16/17（Linux/ABL 实际使用的版本）；其他版本明确拒绝，
  避免用猜测的布局误读。

重要边界
--------
* 本工具做的是**结构与常见 binding 的摘要**，不是完整 DTS 语义验证；
  厂商私有属性（尤其 Qualcomm cont-splash）只按名称/标签提示，真值必须用
  设备 dump 核对，文档中相应结论标为「待设备数据验证」。
* 不解析 phandle 交叉引用（除 ``stdout-path`` 的 alias 解析外），不展开
  ``interrupt-map``，不校验 ``reg`` 是否落在合法物理地址区间。
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional

FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9
HEADER_SIZE = 40
SUPPORTED_VERSIONS = (16, 17)
MAX_DEPTH = 64
MAX_NAME_LEN = 1024
MAX_PROP_LEN = 1 << 20  # 1 MiB；超过视为恶意/损坏，避免无界内存复制

# 常见串口 compatible；用于在缺少 stdout-path 时给出候选。
SERIAL_COMPATIBLES = (
    "qcom,geni-debug-uart",
    "qcom,geni-uart",
    "qcom,msm-uartdm",
    "arm,pl011",
    "arm,sbsa-uart",
    "ns16550a",
    "snps,dw-apb-uart",
)

# 输出脱敏：这些属性名/引导参数可能包含设备唯一标识。
SENSITIVE_KEYS = {
    "serial-number",
    "mac-address",
    "local-mac-address",
    "qcom,board-id",
    "qcom,msm-id",
    "androidboot.serialno",
    "androidboot.imei",
    "androidboot.meid",
    "androidboot.mac",
    "androidboot.wifimac",
    "androidboot.btmac",
}
_SENSITIVE_RE = re.compile(
    r"(?i)\b((?:androidboot\.)?(?:serialno|serial|imei|meid|mac|wifimac|btmac|android_id|cid))=([^\s,;]+)"
)


class FdtError(ValueError):
    """DTB 结构非法或数据越界。"""


@dataclass
class Node:
    """FDT 节点。``props`` 保持文件中的属性顺序。"""

    name: str
    props: dict[str, bytes] = field(default_factory=dict)
    children: list["Node"] = field(default_factory=list)
    parent: Optional["Node"] = None

    @property
    def path(self) -> str:
        if self.parent is None:
            return "/"
        prefix = self.parent.path
        if prefix == "/":
            return "/" + self.name
        return prefix + "/" + self.name

    def walk(self) -> Iterator["Node"]:
        yield self
        for child in self.children:
            yield from child.walk()

    def find(self, path: str) -> Optional["Node"]:
        if path == "/":
            return self
        for node in self.walk():
            if node.path == path:
                return node
        return None

    @property
    def enabled(self) -> bool:
        status = prop_str(self, "status")
        return status not in ("disabled", "fail", "fail-sss")


@dataclass
class Fdt:
    """解析后的设备树。"""

    data: bytes
    totalsize: int
    version: int
    last_comp_version: int
    boot_cpuid_phys: int
    root: Node
    reservations: list[tuple[int, int]]
    trailing_bytes: int

    def walk(self) -> Iterator[Node]:
        return self.root.walk()

    def find(self, path: str) -> Optional[Node]:
        return self.root.find(path)


def _u32(data: bytes, offset: int, what: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise FdtError(f"读取 {what} 越界：偏移 {offset}，数据 {len(data)} 字节")
    return struct.unpack_from(">I", data, offset)[0]


def _cstring(data: bytes, start: int, limit: int, what: str) -> tuple[str, int]:
    """读取 NUL 结尾字符串，返回（字符串, NUL 之后的位置）。"""
    if start < 0 or start >= limit or limit > len(data):
        raise FdtError(f"读取 {what} 起点越界：{start}（上限 {limit}）")
    end = data.find(b"\0", start, limit)
    if end < 0:
        raise FdtError(f"{what} 没有 NUL 结尾（偏移 {start}，上限 {limit}）")
    if end - start > MAX_NAME_LEN:
        raise FdtError(f"{what} 过长（{end - start} 字节）")
    try:
        text = data[start:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise FdtError(f"{what} 不是 ASCII：{exc}") from exc
    return text, end + 1


def parse(data: bytes) -> Fdt:
    """解析 FDT。任何结构错误都抛 :class:`FdtError`。"""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data 必须是 bytes/bytearray/memoryview")
    data = bytes(data)
    if len(data) < HEADER_SIZE:
        raise FdtError(f"文件过短（{len(data)} 字节），不足 FDT 头 40 字节")

    (magic, totalsize, off_struct, off_strings, off_rsvmap,
     version, last_comp, boot_cpuid, size_strings, size_struct) = struct.unpack_from(
        ">10I", data, 0
    )
    if magic != FDT_MAGIC:
        raise FdtError(f"FDT 魔数不符：期望 0x{FDT_MAGIC:08x}，实际 0x{magic:08x}")
    if version not in SUPPORTED_VERSIONS:
        raise FdtError(
            f"不支持的 FDT 版本 {version}（只支持 16/17，last_comp_version={last_comp}）"
        )
    if last_comp > version:
        raise FdtError(f"last_comp_version={last_comp} 大于 version={version}")
    if totalsize < HEADER_SIZE:
        raise FdtError(f"totalsize={totalsize} 小于头长度")
    if totalsize > len(data):
        raise FdtError(f"DTB 截断：totalsize={totalsize}，文件只有 {len(data)} 字节")
    if off_struct < HEADER_SIZE or off_struct % 4:
        raise FdtError(f"off_dt_struct={off_struct} 非法（须 ≥40 且 4 字节对齐）")
    if size_struct < 4 or off_struct + size_struct > totalsize:
        raise FdtError(
            f"结构块越界：off={off_struct} size={size_struct} totalsize={totalsize}"
        )
    if off_strings < HEADER_SIZE or off_strings % 4:
        raise FdtError(f"off_dt_strings={off_strings} 非法（须 ≥40 且 4 字节对齐）")
    if off_strings + size_strings > totalsize:
        raise FdtError(
            f"字符串块越界：off={off_strings} size={size_strings} totalsize={totalsize}"
        )
    if off_rsvmap < HEADER_SIZE or off_rsvmap % 8:
        raise FdtError(f"off_mem_rsvmap={off_rsvmap} 非法（须 ≥40 且 8 字节对齐）")
    if off_rsvmap + 16 > totalsize:
        raise FdtError(f"保留内存块越界：off={off_rsvmap} totalsize={totalsize}")

    # 保留内存：连续 (地址, 长度) 对，以 (0, 0) 结束。
    reservations: list[tuple[int, int]] = []
    pos = off_rsvmap
    while True:
        if pos + 16 > totalsize:
            raise FdtError("保留内存块缺少 (0,0) 终止项")
        addr, size = struct.unpack_from(">QQ", data, pos)
        pos += 16
        if addr == 0 and size == 0:
            break
        if addr + size < addr:
            raise FdtError("保留内存项地址+长度溢出")
        reservations.append((addr, size))

    str_end = off_strings + size_strings
    struct_end = off_struct + size_struct

    def prop_name(nameoff: int) -> str:
        if nameoff >= size_strings:
            raise FdtError(f"属性名偏移 {nameoff} 超出字符串块（{size_strings}）")
        text, next_pos = _cstring(data, off_strings + nameoff, str_end, "属性名")
        if not text:
            raise FdtError("属性名为空")
        if next_pos > str_end:
            raise FdtError("属性名越过字符串块边界")
        return text

    root: Optional[Node] = None
    stack: list[Node] = []
    root_closed = False
    saw_end = False
    pos = off_struct
    while pos < struct_end:
        token = _u32(data, pos, "结构块 token")
        pos += 4
        if token == FDT_BEGIN_NODE:
            if root_closed:
                raise FdtError("根节点已结束后又出现 BEGIN_NODE")
            name, pos = _cstring(data, pos, struct_end, "节点名")
            pos = (pos + 3) & ~3  # FDT 节点名按 4 字节对齐（含 NUL）
            if pos > struct_end:
                raise FdtError("节点名补齐后越过结构块边界")
            if "/" in name:
                raise FdtError(f"节点名包含非法字符 '/': {name!r}")
            if stack:
                parent = stack[-1]
                if any(child.name == name for child in parent.children):
                    raise FdtError(f"兄弟节点重名：{parent.path}/{name}")
                node = Node(name, parent=parent)
                parent.children.append(node)
            else:
                if root is not None:
                    raise FdtError("存在多个根节点")
                if name != "":
                    raise FdtError(f"根节点名必须为空，实际 {name!r}")
                node = Node("")
                root = node
            stack.append(node)
            if len(stack) > MAX_DEPTH:
                raise FdtError(f"节点嵌套超过 {MAX_DEPTH} 层")
        elif token == FDT_END_NODE:
            if not stack:
                raise FdtError("多余的 FDT_END_NODE")
            stack.pop()
            if not stack:
                root_closed = True
        elif token == FDT_PROP:
            if not stack:
                raise FdtError("属性出现在根节点之外")
            length = _u32(data, pos, "属性长度")
            nameoff = _u32(data, pos + 4, "属性名偏移")
            pos += 8
            if length > MAX_PROP_LEN:
                raise FdtError(f"属性长度 {length} 超过上限 {MAX_PROP_LEN}")
            if length > struct_end - pos:
                raise FdtError(f"属性数据越界：长度 {length}，剩余 {struct_end - pos}")
            name = prop_name(nameoff)
            node = stack[-1]
            if name in node.props:
                raise FdtError(f"节点 {node.path} 属性重名：{name}")
            node.props[name] = data[pos:pos + length]
            pos += length
            pos = (pos + 3) & ~3  # 属性值按 4 字节对齐
            if pos > struct_end:
                raise FdtError("属性值补齐后越过结构块边界")
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            if stack:
                raise FdtError(f"FDT_END 时仍有 {len(stack)} 个节点未闭合")
            if root is None:
                raise FdtError("FDT_END 前没有根节点")
            saw_end = True
            break
        else:
            raise FdtError(f"未知结构 token 0x{token:x}（偏移 {pos - 4}）")

    if not saw_end:
        raise FdtError("结构块缺少 FDT_END")
    if root is None:
        raise FdtError("没有根节点")
    if stack:
        raise FdtError("结构块结束时节点未闭合")
    if not root_closed and root.children:
        raise FdtError("根节点未闭合（但含子节点）")

    return Fdt(
        data=data,
        totalsize=totalsize,
        version=version,
        last_comp_version=last_comp,
        boot_cpuid_phys=boot_cpuid,
        root=root,
        reservations=reservations,
        trailing_bytes=len(data) - totalsize,
    )


def parse_file(path: str | Path) -> Fdt:
    with open(path, "rb") as handle:
        return parse(handle.read())


# ---------------------------------------------------------------------------
# 属性读取辅助
# ---------------------------------------------------------------------------

def prop_str(node: Node, name: str, default: str = "") -> str:
    raw = node.props.get(name)
    if raw is None:
        return default
    return _decode_string(raw)


def _decode_string(raw: bytes) -> str:
    raw = raw.split(b"\0", 1)[0]
    return raw.decode("utf-8", "replace")


def prop_u32(node: Node, name: str, default: int = 0) -> int:
    raw = node.props.get(name)
    if raw is None:
        return default
    if len(raw) != 4:
        raise FdtError(f"{node.path}/{name} 长度为 {len(raw)}，期望 4")
    return struct.unpack(">I", raw)[0]


def u32_list(raw: bytes, what: str) -> list[int]:
    if len(raw) % 4:
        raise FdtError(f"{what} 长度 {len(raw)} 不是 4 的倍数")
    return list(struct.unpack(f">{len(raw) // 4}I", raw))


def compatible(node: Node) -> list[str]:
    raw = node.props.get("compatible")
    if raw is None:
        return []
    parts = raw.split(b"\0")
    return [part.decode("utf-8", "replace") for part in parts if part]


def _has_compatible(node: Node, needles: Iterable[str]) -> bool:
    needles = tuple(needles)
    return any(
        needle == item or needle in item
        for item in compatible(node)
        for needle in needles
    )


def find_compatible(fdt: Fdt, *needles: str) -> Optional[Node]:
    for node in fdt.walk():
        if _has_compatible(node, needles):
            return node
    return None


def find_all_compatible(fdt: Fdt, *needles: str) -> list[Node]:
    return [node for node in fdt.walk() if _has_compatible(node, needles)]


def _cells_from_parent(node: Node, prop: str, default: int) -> int:
    parent = node.parent
    while parent is not None:
        if prop in parent.props:
            return prop_u32(parent, prop, default)
        parent = parent.parent
    return default


def reg_ranges(node: Node) -> list[tuple[int, int]]:
    """按父节点 #address-cells/#size-cells 解码 ``reg``。"""
    raw = node.props.get("reg")
    if raw is None:
        return []
    address_cells = _cells_from_parent(node, "#address-cells", 2)
    size_cells = _cells_from_parent(node, "#size-cells", 2)
    if address_cells not in (1, 2) or size_cells not in (1, 2):
        raise FdtError(
            f"{node.path}: 不支持的 #address-cells/#size-cells="
            f"{address_cells}/{size_cells}"
        )
    stride = 4 * (address_cells + size_cells)
    if len(raw) % stride:
        raise FdtError(
            f"{node.path}/reg 长度 {len(raw)} 不是 {stride} 的倍数"
        )
    ranges: list[tuple[int, int]] = []
    for offset in range(0, len(raw), stride):
        address = int.from_bytes(raw[offset:offset + 4 * address_cells], "big")
        size = int.from_bytes(
            raw[offset + 4 * address_cells:offset + stride], "big"
        )
        ranges.append((address, size))
    return ranges


def _reg_summary(node: Node) -> tuple[list[list[int]], Optional[str]]:
    try:
        return [[base, size] for base, size in reg_ranges(node)], None
    except FdtError as exc:
        return [], str(exc)


# ---------------------------------------------------------------------------
# 摘要
# ---------------------------------------------------------------------------

def _add_warning(bucket: dict, message: str) -> None:
    bucket.setdefault("warnings", []).append(message)


def analyze(fdt: Fdt, redact: bool = False) -> dict:
    """把启动相关节点整理成稳定、可 JSON 化的结构。"""
    warnings: list[str] = []
    missing: list[str] = []
    root = fdt.root

    result: dict = {
        "file": {
            "totalsize": fdt.totalsize,
            "trailing_bytes": fdt.trailing_bytes,
            "version": fdt.version,
            "last_comp_version": fdt.last_comp_version,
            "boot_cpuid_phys": fdt.boot_cpuid_phys,
            "model": prop_str(root, "model") or None,
            "compatible": compatible(root),
            "reservations": [[a, s] for a, s in fdt.reservations],
        },
        "memory": None,
        "chosen": None,
        "framebuffer": None,
        "cont_splash": [],
        "interrupt_controller": None,
        "timer": None,
        "psci": None,
        "serial": None,
        "cpus": None,
        "reserved_memory": [],
        "missing": missing,
        "warnings": warnings,
    }

    # --- memory ------------------------------------------------------------
    memory_nodes = [
        node for node in fdt.walk()
        if prop_str(node, "device_type") == "memory"
        or re.match(r"^memory(@|$)", node.name)
    ]
    memory_entries: list[dict] = []
    total_memory = 0
    for node in memory_nodes:
        ranges, error = _reg_summary(node)
        if error:
            _add_warning(result, f"memory 节点 {node.path} 的 reg 无法解码：{error}")
        for base, size in ranges:
            memory_entries.append({"base": base, "size": size, "node": node.path})
            total_memory += size
            if size == 0:
                _add_warning(result, f"memory 区间 {node.path} 长度为 0")
        if not ranges and not error:
            _add_warning(result, f"memory 节点 {node.path} 没有 reg")
    if not memory_nodes:
        missing.append("memory")
        _add_warning(result, "缺少 /memory@*（device_type=\"memory\"）：无法建立物理帧分配器")
    else:
        for index, first in enumerate(memory_entries):
            for second in memory_entries[index + 1:]:
                first_end = first["base"] + first["size"]
                second_end = second["base"] + second["size"]
                if first["base"] < second_end and second["base"] < first_end:
                    _add_warning(
                        result,
                        f"memory 区间重叠：{first['node']} 与 {second['node']}",
                    )
        result["memory"] = {
            "nodes": memory_entries,
            "total_bytes": total_memory,
            "total_mib": round(total_memory / (1024 * 1024), 2),
        }

    # --- chosen / 帧缓冲 ---------------------------------------------------
    chosen = fdt.find("/chosen") or next(
        (node for node in fdt.walk() if node.name == "chosen"), None
    )
    if chosen is None:
        _add_warning(result, "缺少 /chosen：bootargs / stdout-path / 帧缓冲都不可用")
    else:
        chosen_info: dict = {
            "path": chosen.path,
            "bootargs": prop_str(chosen, "bootargs") or None,
            "stdout_path": prop_str(chosen, "stdout-path") or None,
            "linux_initrd_start": None,
            "linux_initrd_end": None,
            "framebuffer": None,
        }
        for key in ("linux,initrd-start", "linux,initrd-end"):
            raw = chosen.props.get(key)
            if raw and len(raw) in (4, 8):
                chosen_info[key.replace("-", "_").replace(",", "_")] = int.from_bytes(
                    raw, "big"
                )
        if redact:
            chosen_info["bootargs"] = _redact_text(chosen_info["bootargs"])
        result["chosen"] = chosen_info

    fb_candidates = find_all_compatible(fdt, "simple-framebuffer")
    chosen_fb = next(
        (node for node in fb_candidates if node.parent is not None
         and node.parent.path == "/chosen"),
        None,
    )
    fb = chosen_fb or (fb_candidates[0] if fb_candidates else None)
    if fb is not None:
        fb_info: dict = {
            "path": fb.path,
            "compatible": compatible(fb),
            "under_chosen": bool(fb.parent is not None and fb.parent.path == "/chosen"),
            "reg": [],
            "width": None,
            "height": None,
            "stride": None,
            "format": None,
            "expected_bytes": None,
            "warnings": [],
        }
        ranges, error = _reg_summary(fb)
        if error:
            fb_info["warnings"].append(f"reg 无法解码：{error}")
        fb_info["reg"] = [[base, size] for base, size in ranges]
        for key in ("width", "height", "stride"):
            raw = fb.props.get(key)
            if raw and len(raw) == 4:
                fb_info[key] = struct.unpack(">I", raw)[0]
            else:
                fb_info["warnings"].append(f"缺少或非法的 {key} 属性")
        fb_info["format"] = prop_str(fb, "format") or None
        bpp = {"r5g6b5": 2, "a8b8g8r8": 4, "x8r8g8b8": 4, "a8r8g8b8": 4}.get(
            fb_info["format"] or ""
        )
        if bpp is None:
            fb_info["warnings"].append(f"未知像素格式 {fb_info['format']!r}")
        if fb_info["stride"] and fb_info["height"]:
            expected = fb_info["stride"] * fb_info["height"]
            fb_info["expected_bytes"] = expected
            if ranges and ranges[0][1] < expected:
                fb_info["warnings"].append(
                    f"reg 长度 {ranges[0][1]} 小于 stride*height={expected}"
                )
            if bpp and fb_info["width"] and fb_info["stride"] < fb_info["width"] * bpp:
                fb_info["warnings"].append(
                    f"stride={fb_info['stride']} 小于 width*{bpp}="
                    f"{fb_info['width'] * bpp}"
                )
        result["framebuffer"] = fb_info
        for message in fb_info["warnings"]:
            _add_warning(result, f"帧缓冲 {fb.path}: {message}")
        if chosen is not None:
            result["chosen"]["framebuffer"] = fb_info["path"]
    else:
        missing.append("framebuffer")
        _add_warning(result, "缺少 simple-framebuffer：屏幕回传不可用，只能依赖串口/pstore")

    # cont-splash：Qualcomm 常见做法是 reserved-memory 里的独立区域；节点名与
    # 标签随 BSP 版本变化，本工具只做提示，不把猜测写成已验证事实。
    for node in fdt.walk():
        haystack = " ".join([
            node.name.lower(),
            prop_str(node, "label").lower(),
            " ".join(item.lower() for item in compatible(node)),
        ])
        if "cont-splash" in haystack or "cont_splash" in haystack:
            ranges, error = _reg_summary(node)
            entry = {
                "path": node.path,
                "reg": [[base, size] for base, size in ranges],
                "no_map": "no-map" in node.props,
                "reusable": "reusable" in node.props,
                "verified": False,
                "note": "节点命名/属性随厂商 BSP 变化，待设备数据验证",
            }
            if error:
                entry["error"] = error
            result["cont_splash"].append(entry)
    if chosen is not None:
        for name, raw in chosen.props.items():
            if "cont-splash" in name.lower():
                result["cont_splash"].append({
                    "path": f"/chosen:{name}",
                    "raw_hex": raw.hex(),
                    "verified": False,
                    "note": "chosen 下的厂商私有属性，语义待设备数据验证",
                })

    # --- reserved-memory ---------------------------------------------------
    reserved = fdt.find("/reserved-memory")
    if reserved is not None:
        for child in reserved.children:
            ranges, error = _reg_summary(child)
            entry = {
                "path": child.path,
                "reg": [[base, size] for base, size in ranges],
                "no_map": "no-map" in child.props,
                "reusable": "reusable" in child.props,
                "label": prop_str(child, "label") or None,
            }
            if error:
                entry["error"] = error
            result["reserved_memory"].append(entry)

    # --- GIC ---------------------------------------------------------------
    gic = find_compatible(fdt, "arm,gic-v3")
    gic_kind = "GICv3"
    if gic is None:
        gic = find_compatible(fdt, "arm,gic-400", "arm,cortex-a15-gic", "arm,gic")
        gic_kind = "GICv2/兼容" if gic is not None else ""
    if gic is None:
        missing.append("interrupt-controller(gic-v3)")
        _add_warning(result, "缺少 arm,gic-v3：PDA-2 的中断/SMP 不可用，只能轮询单核")
    else:
        ranges, error = _reg_summary(gic)
        cells_raw = gic.props.get("#interrupt-cells")
        cells = struct.unpack(">I", cells_raw)[0] if cells_raw and len(cells_raw) == 4 else None
        info = {
            "path": gic.path,
            "kind": gic_kind,
            "compatible": compatible(gic),
            "reg": [[base, size] for base, size in ranges],
            "interrupt_cells": cells,
            "interrupt_controller": "interrupt-controller" in gic.props,
            "msi_controller": "msi-controller" in gic.props,
            "redistributor_stride": None,
            "redistributor_regions": None,
            "its": [],
        }
        if error:
            _add_warning(result, f"GIC reg 无法解码：{error}")
        for key, target in (
            ("redistributor-stride", "redistributor_stride"),
            ("#redistributor-regions", "redistributor_regions"),
        ):
            raw = gic.props.get(key)
            if raw and len(raw) in (4, 8):
                info[target] = int.from_bytes(raw, "big")
        for node in gic.walk():
            if node is gic:
                continue
            if _has_compatible(node, ("arm,gic-v3-its",)):
                its_ranges, its_error = _reg_summary(node)
                info["its"].append({
                    "path": node.path,
                    "reg": [[base, size] for base, size in its_ranges],
                    "error": its_error,
                })
        if gic_kind != "GICv3":
            _add_warning(result, "找到的是 GICv2/兼容控制器，不是 GICv3；PDA-2 计划按 GICv3 实现")
        if cells != 3:
            _add_warning(result, f"#interrupt-cells={cells}，PDA-1 的 SPI 解析按 3 实现")
        if not ranges:
            _add_warning(result, "GIC 没有 reg：无法定位 GICD/GICR")
        result["interrupt_controller"] = info

    # --- 架构定时器 --------------------------------------------------------
    timer = find_compatible(fdt, "arm,armv8-timer")
    if timer is None:
        missing.append("timer(arm,armv8-timer)")
        _add_warning(result, "缺少 arm,armv8-timer：不能产生时钟中断，无法抢占/看门狗")
    else:
        cfg_cells = 3
        if result["interrupt_controller"]:
            cfg_cells = result["interrupt_controller"].get("interrupt_cells") or 3
        raw = timer.props.get("interrupts")
        entries: list[dict] = []
        error = None
        if raw is None:
            if "interrupts-extended" in timer.props:
                error = "只解析 interrupts；本 DTB 使用 interrupts-extended，未展开"
            else:
                error = "缺少 interrupts"
        else:
            try:
                values = u32_list(raw, f"{timer.path}/interrupts")
                if len(values) % cfg_cells:
                    raise FdtError(
                        f"interrupts 长度 {len(values)} 不是 {cfg_cells} 的倍数"
                    )
                names = {
                    13: "secure-phys（EL1 安全物理定时器）",
                    14: "non-secure-phys（EL1 非安全物理定时器）",
                    11: "virtual（EL1 虚拟定时器）",
                    10: "hyp-phys（EL2 物理定时器）",
                }
                for offset in range(0, len(values), cfg_cells):
                    group = values[offset:offset + cfg_cells]
                    irq_type, number, flags = group[0], group[1], group[2]
                    entries.append({
                        "type": "PPI" if irq_type == 1 else f"type{irq_type}",
                        "number": number,
                        "flags": flags,
                        "name": names.get(number, "未知 PPI"),
                    })
                if len(entries) != 4:
                    _add_warning(
                        result,
                        f"定时器 interrupts 有 {len(entries)} 项，期望 4 项（13/14/11/10）",
                    )
                required = {10, 11, 13, 14}
                seen = {entry["number"] for entry in entries}
                if not required.issubset(seen):
                    _add_warning(
                        result,
                        f"定时器 PPI 集合 {sorted(seen)} 缺少 {sorted(required - seen)}",
                    )
                for entry in entries:
                    if entry["type"] != "PPI":
                        _add_warning(result, f"定时器项不是 PPI：{entry}")
                    if entry["flags"] & 0xF not in (4, 8):
                        _add_warning(
                            result,
                            f"定时器 PPI {entry['number']} 触发方式 flags=0x{entry['flags']:x}"
                            "（期望电平触发 4 或 8）",
                        )
            except FdtError as exc:
                error = str(exc)
        result["timer"] = {
            "path": timer.path,
            "compatible": compatible(timer),
            "always_on": "always-on" in timer.props,
            "entries": entries,
            "error": error,
        }
        if error:
            _add_warning(result, f"定时器 {timer.path}: {error}")

    # --- PSCI --------------------------------------------------------------
    psci = find_compatible(fdt, "arm,psci")
    if psci is None:
        missing.append("psci")
        _add_warning(result, "缺少 /psci：不能 CPU_ON、SYSTEM_OFF/RESET，SMP 与自动复位不可用")
    else:
        method = prop_str(psci, "method")
        psci_compat = compatible(psci)
        modern = any(
            item.startswith("arm,psci-0.2") or item.startswith("arm,psci-1.0")
            for item in psci_compat
        )
        standard = {
            "cpu_suspend": 0x84000001,
            "cpu_off": 0x84000002,
            "cpu_on": 0x84000003,
            "migrate": 0x84000005,
            "system_off": 0x84000008,
            "system_reset": 0x84000009,
        }
        info = {
            "path": psci.path,
            "compatible": psci_compat,
            "method": method or None,
            "function_ids": {},
        }
        for key, default in standard.items():
            raw = psci.props.get(key)
            if raw is not None and len(raw) == 4:
                info["function_ids"][key] = struct.unpack(">I", raw)[0]
            elif modern:
                info["function_ids"][key] = default
            else:
                # PSCI 0.1 的函数 ID 必须由 DT 提供；缺失时不能猜标准 ID。
                info["function_ids"][key] = None
        result["psci"] = info
        if method not in ("smc", "hvc"):
            _add_warning(result, f"PSCI method={method!r}，期望 smc 或 hvc")
        if not modern:
            _add_warning(result, "PSCI 版本低于 0.2：函数 ID 必须来自 DTB，缺失项不猜")
            for key in ("cpu_off", "cpu_on"):
                if info["function_ids"][key] is None:
                    _add_warning(result, f"PSCI 0.1 缺少 {key}，SMP/关机不可用")

    # --- 串口 --------------------------------------------------------------
    stdout_node = None
    stdout_options = ""
    stdout_raw = prop_str(chosen, "stdout-path") if chosen is not None else ""
    if stdout_raw:
        target, _, stdout_options = stdout_raw.partition(":")
        if target.startswith("/"):
            stdout_node = fdt.find(target)
        else:
            aliases = fdt.find("/aliases")
            if aliases is not None:
                alias_path = prop_str(aliases, target)
                if alias_path:
                    stdout_node = fdt.find(alias_path)
    serial = stdout_node
    if serial is None or not _has_compatible(serial, SERIAL_COMPATIBLES):
        candidates = [
            node for node in fdt.walk()
            if node.enabled and _has_compatible(node, SERIAL_COMPATIBLES)
        ]
        serial = candidates[0] if candidates else None
        if stdout_node is not None and serial is not None and stdout_node is not serial:
            _add_warning(
                result,
                f"stdout-path 指向 {stdout_node.path}，但其 compatible 不在已知串口列表；"
                f"改用 {serial.path}",
            )
    if serial is None:
        missing.append("serial")
        _add_warning(result, "未找到串口节点：屏幕与 pstore 之外没有日志通道")
    else:
        ranges, error = _reg_summary(serial)
        info = {
            "path": serial.path,
            "compatible": compatible(serial),
            "reg": [[base, size] for base, size in ranges],
            "clock_frequency": None,
            "current_speed": None,
            "interrupts": [],
            "stdout_path": stdout_raw or None,
            "stdout_options": stdout_options or None,
            "error": error,
        }
        for key in ("clock-frequency", "current-speed"):
            raw = serial.props.get(key)
            if raw and len(raw) == 4:
                info[key.replace("-", "_")] = struct.unpack(">I", raw)[0]
        irq_raw = serial.props.get("interrupts")
        if irq_raw:
            try:
                info["interrupts"] = u32_list(irq_raw, f"{serial.path}/interrupts")
            except FdtError as exc:
                info["error"] = str(exc)
        result["serial"] = info
        if error:
            _add_warning(result, f"串口 {serial.path}: {error}")
        if not info["clock_frequency"]:
            _add_warning(
                result,
                f"串口 {serial.path} 未声明 clock-frequency（GENI 可能由 clocks 提供）；"
                "earlycon 波特率需用设备数据确认",
            )
        if not ranges:
            _add_warning(result, f"串口 {serial.path} 没有 reg")

    # --- CPUs（PDA-2 用） --------------------------------------------------
    cpus = fdt.find("/cpus")
    if cpus is not None:
        cpu_nodes = [
            node for node in cpus.children
            if prop_str(node, "device_type") == "cpu" or node.name.startswith("cpu@")
        ]
        methods = sorted({
            prop_str(node, "enable-method") for node in cpu_nodes
            if prop_str(node, "enable-method")
        })
        result["cpus"] = {
            "path": cpus.path,
            "count": len(cpu_nodes),
            "enable_methods": methods,
            "cpus": [
                {
                    "path": node.path,
                    "reg": (prop_u32(node, "reg") if node.props.get("reg") and
                            len(node.props["reg"]) == 4 else None),
                    "compatible": compatible(node),
                }
                for node in cpu_nodes
            ],
        }
        if len(cpu_nodes) == 0:
            _add_warning(result, "/cpus 下没有 cpu@ 节点")
        elif "psci" not in methods:
            _add_warning(result, f"CPU enable-method={methods}，PDA-2 依赖 psci")
    else:
        _add_warning(result, "缺少 /cpus：PDA-2 无法登记大小核")

    if redact:
        result = _redact_obj(result)
    return result


# ---------------------------------------------------------------------------
# 脱敏
# ---------------------------------------------------------------------------

def _redact_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    return _SENSITIVE_RE.sub(lambda match: f"{match.group(1)}=<已脱敏>", text)


def _redact_obj(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key.lower() in SENSITIVE_KEYS:
                result[key] = "<已脱敏>"
            else:
                result[key] = _redact_obj(item)
        return result
    if isinstance(value, list):
        return [_redact_obj(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

def _format_prop(raw: bytes, redact: bool = False) -> str:
    if raw == b"":
        return "(布尔/空)"
    # NUL 分隔字符串（compatible、stdout-path 等）
    if raw.endswith(b"\0") and all(32 <= byte < 127 or byte == 0 for byte in raw[:-1]):
        parts = [part.decode("ascii") for part in raw[:-1].split(b"\0")]
        text = " / ".join(f'"{part}"' for part in parts)
        return _redact_text(text) if redact else text
    if len(raw) % 4 == 0:
        values = struct.unpack(f">{len(raw) // 4}I", raw)
        return "[" + ", ".join(f"0x{value:x}" for value in values) + "]"
    text = raw.hex()
    return text


def format_tree(fdt: Fdt, redact: bool = False) -> str:
    lines = [
        f"FDT totalsize={fdt.totalsize} version={fdt.version} "
        f"last_comp={fdt.last_comp_version} boot_cpuid={fdt.boot_cpuid_phys}"
    ]
    for node in fdt.walk():
        lines.append(f"{node.path}  compatible={compatible(node) or '-'}")
        for name, raw in node.props.items():
            masked = redact and name.lower() in SENSITIVE_KEYS
            value = "<已脱敏>" if masked else _format_prop(raw, redact)
            lines.append(f"    {name} = {value}")
    return "\n".join(lines)


def _format_ranges(ranges: list[list[int]]) -> str:
    if not ranges:
        return "-"
    return ", ".join(f"0x{base:x}+0x{size:x}" for base, size in ranges)


def format_report(info: dict) -> str:
    lines: list[str] = []
    file_info = info["file"]
    lines.append(
        f"DTB：{file_info['totalsize']} 字节，version {file_info['version']}，"
        f"尾部 {file_info['trailing_bytes']} 字节"
    )
    if file_info["model"]:
        lines.append(f"model：{file_info['model']}")
    if file_info["compatible"]:
        lines.append(f"compatible：{', '.join(file_info['compatible'])}")
    if file_info["reservations"]:
        lines.append(
            "保留内存（头表）："
            + ", ".join(f"0x{a:x}+0x{s:x}" for a, s in file_info["reservations"])
        )

    memory = info.get("memory")
    if memory:
        lines.append(
            f"[memory] {len(memory['nodes'])} 个区间，共 {memory['total_mib']} MiB"
        )
        for entry in memory["nodes"]:
            lines.append(
                f"    0x{entry['base']:x} + 0x{entry['size']:x}  ({entry['node']})"
            )
    else:
        lines.append("[memory] 缺失")

    chosen = info.get("chosen")
    if chosen:
        lines.append(f"[chosen] {chosen['path']}")
        if chosen["bootargs"]:
            lines.append(f"    bootargs = {chosen['bootargs']}")
        if chosen["stdout_path"]:
            lines.append(f"    stdout-path = {chosen['stdout_path']}")
    else:
        lines.append("[chosen] 缺失")

    fb = info.get("framebuffer")
    if fb:
        lines.append(f"[framebuffer] {fb['path']}（under chosen={fb['under_chosen']}）")
        lines.append(
            f"    reg={_format_ranges(fb['reg'])}  "
            f"{fb['width']}x{fb['height']} stride={fb['stride']} "
            f"format={fb['format']} 需要 {fb['expected_bytes']} 字节"
        )
    else:
        lines.append("[framebuffer] 缺失")

    if info.get("cont_splash"):
        lines.append("[cont-splash]（待设备数据验证）")
        for entry in info["cont_splash"]:
            lines.append(
                f"    {entry['path']} reg={_format_ranges(entry.get('reg', []))}"
            )
    else:
        lines.append("[cont-splash] 未在 DTB 中发现（不代表 ABL 没启用，命名需设备数据核对）")

    gic = info.get("interrupt_controller")
    if gic:
        lines.append(
            f"[interrupt-controller] {gic['kind']} {gic['path']} "
            f"cells={gic['interrupt_cells']} msi={gic['msi_controller']}"
        )
        lines.append(f"    reg={_format_ranges(gic['reg'])}")
        for its in gic["its"]:
            lines.append(f"    ITS {its['path']} reg={_format_ranges(its['reg'])}")
    else:
        lines.append("[interrupt-controller] 缺失")

    timer = info.get("timer")
    if timer:
        entries = ", ".join(
            f"{entry['number']}({entry['name']})" for entry in timer["entries"]
        )
        lines.append(
            f"[timer] {timer['path']} always-on={timer['always_on']} PPI=[{entries}]"
        )
        if timer["error"]:
            lines.append(f"    错误：{timer['error']}")
    else:
        lines.append("[timer] 缺失")

    psci = info.get("psci")
    if psci:
        ids = psci["function_ids"]

        def fmt_id(value: Optional[int]) -> str:
            return "缺失" if value is None else f"0x{value:x}"

        lines.append(
            f"[psci] {psci['path']} compat={psci['compatible']} method={psci['method']}"
        )
        lines.append(
            f"    cpu_on={fmt_id(ids['cpu_on'])} cpu_off={fmt_id(ids['cpu_off'])} "
            f"system_reset={fmt_id(ids['system_reset'])} "
            f"system_off={fmt_id(ids['system_off'])}"
        )
    else:
        lines.append("[psci] 缺失")

    serial = info.get("serial")
    if serial:
        lines.append(
            f"[serial] {serial['path']} compat={serial['compatible']} "
            f"reg={_format_ranges(serial['reg'])} "
            f"clock={serial['clock_frequency']}"
        )
        if serial["stdout_path"]:
            lines.append(
                f"    stdout-path={serial['stdout_path']} -> {serial['path']}"
            )
    else:
        lines.append("[serial] 缺失")

    cpus = info.get("cpus")
    if cpus:
        lines.append(
            f"[cpus] {cpus['count']} 个 CPU，enable-method={cpus['enable_methods']}"
        )

    if info.get("reserved_memory"):
        lines.append(f"[reserved-memory] {len(info['reserved_memory'])} 个区域")
        for entry in info["reserved_memory"]:
            flags = " ".join(
                flag for flag in ("no-map" if entry["no_map"] else "",
                                  "reusable" if entry["reusable"] else "") if flag
            )
            lines.append(
                f"    {entry['path']} reg={_format_ranges(entry['reg'])} {flags}".rstrip()
            )

    if info["missing"]:
        lines.append("缺失（启动必需）：" + "、".join(info["missing"]))
    else:
        lines.append("启动必需节点：齐全")
    if info["warnings"]:
        lines.append("警告：")
        for warning in info["warnings"]:
            lines.append(f"    - {warning}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 自测
# ---------------------------------------------------------------------------

def _n(name: str, props: Optional[list[tuple[str, bytes]]] = None,
       children: Optional[list[tuple]] = None) -> tuple:
    return (name, props or [], children or [])


def _s(text: str) -> bytes:
    return text.encode("ascii") + b"\0"


def _u32s(*values: int) -> bytes:
    return b"".join(struct.pack(">I", value) for value in values)


def build_synthetic_fdt(root: tuple, *, version: int = 17, magic: int = FDT_MAGIC,
                        omit_end: bool = False) -> bytes:
    """把嵌套元组 ``(name, props, children)`` 打包成 FDT（仅自测/属性测试）。"""
    strings = bytearray()
    string_offsets: dict[str, int] = {}

    def string_offset(name: str) -> int:
        if name not in string_offsets:
            string_offsets[name] = len(strings)
            strings.extend(name.encode("ascii") + b"\0")
        return string_offsets[name]

    def emit(node: tuple) -> bytes:
        name, props, children = node
        out = bytearray(struct.pack(">I", FDT_BEGIN_NODE))
        out.extend(name.encode("ascii") + b"\0")
        out.extend(b"\0" * ((-len(out)) % 4))
        for prop_name, value in props:
            out.extend(struct.pack(">III", FDT_PROP, len(value), string_offset(prop_name)))
            out.extend(value)
            out.extend(b"\0" * ((-len(value)) % 4))
        for child in children:
            out.extend(emit(child))
        out.extend(struct.pack(">I", FDT_END_NODE))
        return bytes(out)

    struct_block = emit(root)
    if not omit_end:
        struct_block += struct.pack(">I", FDT_END)
    off_rsvmap = HEADER_SIZE
    off_struct = off_rsvmap + 16
    pad = (-(off_struct + len(struct_block))) % 4
    off_strings = off_struct + len(struct_block) + pad
    totalsize = off_strings + len(strings)
    header = struct.pack(
        ">10I",
        magic,
        totalsize,
        off_struct,
        off_strings,
        off_rsvmap,
        version,
        16,
        0,
        len(strings),
        len(struct_block),
    )
    return (
        header
        + b"\0" * 16
        + struct_block
        + b"\0" * pad
        + bytes(strings)
    )


def synthetic_tree() -> tuple:
    """覆盖 6 个启动必需节点 + cpus/reserved-memory 的合成设备树。"""
    return _n(
        "",
        [
            ("#address-cells", _u32s(2)),
            ("#size-cells", _u32s(2)),
            ("compatible", _s("chainway,c66")),
            ("model", _s("Chainway C66 (synthetic)")),
        ],
        [
            _n("memory@80000000", [
                ("device_type", _s("memory")),
                ("reg", _u32s(0, 0x80000000, 0, 0x40000000)),
            ]),
            _n("reserved-memory", [
                ("#address-cells", _u32s(2)),
                ("#size-cells", _u32s(2)),
                ("ranges", b""),
            ], [
                _n("cont_splash_region@9c000000", [
                    ("reg", _u32s(0, 0x9C000000, 0, 0x02300000)),
                    ("label", _s("cont_splash_region")),
                    ("no-map", b""),
                ]),
            ]),
            _n("chosen", [
                ("bootargs", _s(
                    "console=ttyMSM0,115200n8 androidboot.slot_suffix=_b "
                    "androidboot.serialno=1234567890"
                )),
                ("stdout-path", _s("serial0:115200n8")),
            ], [
                _n("framebuffer@9c000000", [
                    ("compatible", _s("simple-framebuffer")),
                    ("reg", _u32s(0, 0x9C000000, 0, 0x02300000)),
                    ("width", _u32s(1080)),
                    ("height", _u32s(2400)),
                    ("stride", _u32s(4320)),
                    ("format", _s("a8b8g8r8")),
                ]),
            ]),
            _n("aliases", [("serial0", _s("/soc@0/serial@4a90000"))]),
            _n("psci", [
                ("compatible", _s("arm,psci-1.0")),
                ("method", _s("smc")),
            ]),
            _n("interrupt-controller@17a00000", [
                ("compatible", _s("arm,gic-v3")),
                ("reg", _u32s(
                    0, 0x17A00000, 0, 0x10000,
                    0, 0x17A60000, 0, 0x100000,
                )),
                ("#interrupt-cells", _u32s(3)),
                ("interrupt-controller", b""),
            ]),
            _n("timer", [
                ("compatible", _s("arm,armv8-timer")),
                ("interrupts", _u32s(
                    1, 13, 0xF08,
                    1, 14, 0xF08,
                    1, 11, 0xF08,
                    1, 10, 0xF08,
                )),
                ("always-on", b""),
            ]),
            _n("soc@0", [
                ("#address-cells", _u32s(2)),
                ("#size-cells", _u32s(2)),
            ], [
                _n("serial@4a90000", [
                    ("compatible", _s("qcom,geni-debug-uart")),
                    ("reg", _u32s(0, 0x4A90000, 0, 0x1000)),
                    ("clock-frequency", _u32s(19200000)),
                    ("status", _s("okay")),
                ]),
            ]),
            _n("cpus", [
                ("#address-cells", _u32s(1)),
                ("#size-cells", _u32s(0)),
            ], [
                _n("cpu@0", [
                    ("device_type", _s("cpu")),
                    ("reg", _u32s(0)),
                    ("compatible", _s("arm,cortex-a73")),
                    ("enable-method", _s("psci")),
                ]),
                _n("cpu@1", [
                    ("device_type", _s("cpu")),
                    ("reg", _u32s(1)),
                    ("compatible", _s("arm,cortex-a53")),
                    ("enable-method", _s("psci")),
                ]),
            ]),
        ],
    )


def _run_self_test() -> int:
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
        except FdtError as exc:
            if needle and needle not in str(exc):
                raise AssertionError(f"错误信息缺少 {needle!r}：{exc}") from exc
        else:
            raise AssertionError(f"非法 DTB 被接受：{needle or blob[:16]!r}")
        checks += 1

    root = synthetic_tree()
    blob = build_synthetic_fdt(root)
    fdt = parse(blob)
    info = analyze(fdt)
    check(info["memory"]["total_bytes"] == 0x40000000, "memory 总量错误")
    check(info["framebuffer"]["width"] == 1080, "帧缓冲宽度错误")
    check(info["framebuffer"]["height"] == 2400, "帧缓冲高度错误")
    check(info["framebuffer"]["stride"] == 4320, "帧缓冲 stride 错误")
    check(info["framebuffer"]["format"] == "a8b8g8r8", "帧缓冲格式错误")
    check(info["interrupt_controller"]["kind"] == "GICv3", "GIC 类型错误")
    check(info["interrupt_controller"]["interrupt_cells"] == 3, "GIC cells 错误")
    check(info["timer"]["entries"][0]["number"] == 13, "定时器首项错误")
    check({entry["number"] for entry in info["timer"]["entries"]} == {13, 14, 11, 10},
          "定时器 PPI 集合错误")
    check(info["psci"]["method"] == "smc", "PSCI method 错误")
    check(info["psci"]["function_ids"]["cpu_on"] == 0x84000003, "PSCI CPU_ON 错误")
    check(info["serial"]["path"] == "/soc@0/serial@4a90000", "串口路径错误")
    check(info["serial"]["clock_frequency"] == 19200000, "串口时钟错误")
    check(info["cpus"]["count"] == 2, "CPU 数量错误")
    check(info["missing"] == [], "合成 DTB 不应缺必需节点")
    check(info["cont_splash"][0]["verified"] is False, "cont-splash 不应标已验")

    redacted = analyze(fdt, redact=True)
    check("1234567890" not in json.dumps(redacted, ensure_ascii=False), "序列号未脱敏")
    check("已脱敏" in json.dumps(redacted, ensure_ascii=False), "脱敏标记缺失")

    expect_error(b"", "过短")
    expect_error(blob[:-1], "截断")
    expect_error(build_synthetic_fdt(root, magic=0xDEADBEEF), "魔数")
    expect_error(build_synthetic_fdt(root, version=15), "版本")
    expect_error(build_synthetic_fdt(root, version=18), "版本")
    expect_error(build_synthetic_fdt(root, omit_end=True), "FDT_END")

    corrupted = bytearray(blob)
    struct.pack_into(">I", corrupted, 4, len(blob) + 100)
    expect_error(bytes(corrupted), "截断")

    corrupted = bytearray(blob)
    struct.pack_into(">I", corrupted, 8, (len(blob) - 4) & ~3)  # off_dt_struct
    expect_error(bytes(corrupted), "结构块越界")

    corrupted = bytearray(blob)
    struct.pack_into(">I", corrupted, 12, (len(blob) - 4) & ~3)  # off_dt_strings
    expect_error(bytes(corrupted), "字符串块越界")

    # 第一个属性在根 BEGIN_NODE（4+1，补齐到 8）之后：token/len/nameoff。
    first_prop = 40 + 16 + 8
    corrupted = bytearray(blob)
    struct.pack_into(">I", corrupted, first_prop + 8, 0xFFFFFF)
    expect_error(bytes(corrupted), "属性名偏移")

    corrupted = bytearray(blob)
    struct.pack_into(">I", corrupted, first_prop + 4, 0xFFFFFF)
    expect_error(bytes(corrupted), "属性长度")

    duplicate_prop = _n("", [("#address-cells", _u32s(2)),
                             ("#address-cells", _u32s(2))], [])
    expect_error(build_synthetic_fdt(duplicate_prop), "属性重名")

    duplicate_child = _n("", [], [_n("x", [], []), _n("x", [], [])])
    expect_error(build_synthetic_fdt(duplicate_child), "兄弟节点重名")

    deep = _n("x", [], [])
    for _ in range(MAX_DEPTH + 1):
        deep = _n("x", [], [deep])
    deep = _n("", [], [deep])
    expect_error(build_synthetic_fdt(deep), "嵌套")

    # 保留内存块必须能读到 (0,0) 终止项。
    corrupted = bytearray(blob)
    struct.pack_into(">I", corrupted, 16, len(blob) - 8)
    expect_error(bytes(corrupted))

    return checks


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="只读解析 DTB 并列出 Android/PDA 启动节点（PDA-0）",
    )
    parser.add_argument("fdt", nargs="?", help=".dtb 文件路径（--self-test 时可省略）")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出摘要")
    parser.add_argument("--dump", action="store_true", help="打印完整节点树")
    parser.add_argument("--redact", action="store_true", help="脱敏序列号/MAC/IMEI 等")
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="缺少 memory/framebuffer/gic-v3/timer/psci/serial 时以退出码 2 结束",
    )
    parser.add_argument("--self-test", action="store_true", help="用内置合成 DTB 自测")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.self_test:
        checks = _run_self_test()
        print(f"dtbinfo --self-test: PASS（{checks} 项检查）")
        return 0
    if not args.fdt:
        parser.error("缺少 DTB 路径（或使用 --self-test）")

    path = Path(args.fdt)
    try:
        blob = path.read_bytes()
    except OSError as exc:
        print(f"✗ 无法读取 {path}：{exc}", file=sys.stderr)
        return 1
    try:
        fdt = parse(blob)
    except FdtError as exc:
        print(f"✗ {path}：{exc}", file=sys.stderr)
        return 1

    info = analyze(fdt, redact=args.redact)
    if args.dump:
        print(format_tree(fdt, redact=args.redact))
    elif args.json:
        payload = {"path": str(path), **info}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(format_report(info))
    if args.require_all and info["missing"]:
        print("✗ 启动必需节点缺失：" + "、".join(info["missing"]), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
