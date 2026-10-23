#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PDA-0 解析器的不变量属性测试（固定种子 + 收缩）。

覆盖性质
--------
* ``PDA-BOOTIMG-01``：boot.img 解析器只接受 v0–v4 且所有声明段都在文件内、
  页对齐、按序不重叠；截断、非法魔数/版本/页大小/头长度必须拒绝。
* ``PDA-DTB-01``：FDT 解析器只接受版本 16/17 且所有结构块、字符串块、保留
  内存块、属性长度、字符串 NUL 均在 totalsize 内；截断、越界、缺失 END、
  重复属性/兄弟节点、过深嵌套必须拒绝。

方法说明
--------
随机用例由固定种子驱动，失败时用 :func:`shrink` 收缩到仍能复现问题的最小
输入并打印十六进制前缀。这里的 ``tested`` 只表示这些输入上真实通过，不是
代码级证明，也不替代真实设备数据核对。
"""

from __future__ import annotations

import contextlib
import io
import json
import random
import struct
import tempfile
import unittest
from pathlib import Path

import bootimg
import dtbinfo

SEED_BOOTIMG = 0xB007
SEED_DTB = 0xD7B0
BOOT_MUTATIONS = 400
DTB_MUTATIONS = 800


# ---------------------------------------------------------------------------
# 收缩器：只在属性测试失败时使用，保证报告能给出最小反例
# ---------------------------------------------------------------------------

def shrink(data: bytes, fails, limit: int = 20000) -> bytes:
    """确定性地删除/清零字节，直到仍满足 ``fails`` 且无法再缩小。"""
    best = bytes(data)
    operations = 0

    def attempt(candidate: bytes) -> bool:
        nonlocal operations
        if operations >= limit:
            return False
        operations += 1
        return fails(candidate)

    chunk = max(1, len(best) // 2)
    while chunk >= 1 and operations < limit:
        index = len(best)
        while index >= chunk and operations < limit:
            candidate = best[:index - chunk]
            if attempt(candidate):
                best = candidate
                index = len(best)
            else:
                index -= chunk
        chunk //= 2

    chunk = max(4, len(best) // 2)
    while chunk >= 4 and operations < limit:
        offset = 0
        while offset + chunk <= len(best) and operations < limit:
            candidate = best[:offset] + b"\0" * chunk + best[offset + chunk:]
            if attempt(candidate):
                best = candidate
                offset += chunk
            else:
                offset += max(1, chunk // 2)
        chunk //= 2
    return best


def _repr_failure(data: bytes) -> str:
    head = data[:96].hex()
    return f"最小反例 {len(data)} 字节，前 96 字节：{head}"


# ---------------------------------------------------------------------------
# boot.img
# ---------------------------------------------------------------------------

def _boot_invariant_problems(data: bytes, image) -> list[str]:
    problems: list[str] = []
    if image.version not in bootimg.SUPPORTED_VERSIONS:
        problems.append(f"version={image.version}")
    if image.page_size not in ((4096,) if image.version >= 3 else bootimg.ALLOWED_PAGE_SIZES):
        problems.append(f"page_size={image.page_size}")
    if image.file_size != len(data):
        problems.append("file_size 与输入不一致")
    if image.required_end > len(data):
        problems.append("required_end 超出文件")
    kernel = image.segment("kernel")
    if kernel is None:
        problems.append("缺少 kernel 段")
    else:
        if kernel.offset != image.page_size:
            problems.append("kernel 偏移不是首页边界")
        if kernel.size == 0:
            problems.append("kernel 长度为 0")
    previous_end = 0
    for segment in image.segments:
        if segment.offset % image.page_size:
            problems.append(f"{segment.name} 偏移未对齐")
        if segment.size <= 0:
            problems.append(f"{segment.name} 长度非正")
        if segment.offset < previous_end:
            problems.append(f"{segment.name} 与前段重叠")
        if segment.end > len(data):
            problems.append(f"{segment.name} 越过文件末尾")
        previous_end = segment.end
    if image.segments and image.required_end != image.segments[-1].end:
        problems.append("required_end 不等于最后一段末尾")
    if image.version >= 3 and image.kernel_addr is not None:
        problems.append("v3/v4 不应有 32 位加载地址")
    return problems


class BootImageProperties(unittest.TestCase):
    def test_all_versions_layout_and_addresses(self):
        for version in bootimg.SUPPORTED_VERSIONS:
            for page_size in ((2048, 4096) if version <= 2 else (4096,)):
                with self.subTest(version=version, page_size=page_size):
                    blob = bootimg.build_synthetic_image(
                        version,
                        page_size=page_size,
                        kernel=b"K" * 5000,
                        ramdisk=b"R" * 3000,
                        second=b"S" * 100,
                        recovery_dtbo=b"D" * 700,
                        dtb=b"T" * 900,
                        signature=b"G" * 500,
                    )
                    image = bootimg.parse(blob)
                    self.assertEqual(image.version, version)
                    self.assertEqual(image.page_size, page_size)
                    self.assertEqual(image.header_size, bootimg.HEADER_SIZES[version])
                    self.assertEqual(image.segment("kernel").offset, page_size)
                    self.assertEqual(image.segment("kernel").size, 5000)
                    self.assertEqual(image.segment("ramdisk").size, 3000)
                    self.assertEqual(image.required_end, len(blob))
                    if version <= 2:
                        self.assertEqual(image.segment("second").size, 100)
                        self.assertEqual(image.segment("kernel").addr, 0x00080000)
                        self.assertEqual(image.segment("ramdisk").addr, 0x01000000)
                    else:
                        self.assertIsNone(image.segment("second"))
                    if version == 1:
                        self.assertEqual(image.segment("recovery_dtbo").size, 700)
                    if version == 2:
                        self.assertEqual(image.segment("dtb").size, 900)
                        self.assertEqual(image.dtb_addr, 0x03000000)
                    if version < 2:
                        self.assertIsNone(image.segment("dtb"))
                    if version == 4:
                        self.assertEqual(image.signature_size, 500)
                        self.assertEqual(image.segment("boot_signature").size, 500)
                    self.assertEqual(_boot_invariant_problems(blob, image), [])

    def test_every_truncation_below_required_end_is_rejected(self):
        for version in bootimg.SUPPORTED_VERSIONS:
            with self.subTest(version=version):
                blob = bootimg.build_synthetic_image(version)
                required = bootimg.parse(blob).required_end
                for cut in range(required):
                    with self.assertRaises(bootimg.BootImageError):
                        bootimg.parse(blob[:cut])

    def test_invalid_headers_are_rejected(self):
        blob = bootimg.build_synthetic_image(2)

        def mutated(offset, value, fmt="<I"):
            copy = bytearray(blob)
            struct.pack_into(fmt, copy, offset, value)
            return bytes(copy)

        cases = {
            "bad magic": b"NOTANDROID" + blob[10:],
            "vendor_boot": b"VNDRBOOT" + blob[8:],
            "version 5": mutated(40, 5),
            "version huge": mutated(40, 0xFFFFFFFF),
            "page 1024": mutated(36, 1024),
            "page 65536": mutated(36, 65536),
            "header_size v2": mutated(1644, 1648),
            "kernel zero": mutated(8, 0),
            "kernel too big": mutated(8, 0xFFFFFFF0),
            "ramdisk too big": mutated(16, 0xFFFFFFF0),
            "dtb too big": mutated(1648, 0xFFFFFFF0),
            "dtbo too big": mutated(1632, 0xFFFFFFF0),
            "empty": b"",
            "short": blob[:20],
        }
        for label, data in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(bootimg.BootImageError):
                    bootimg.parse(data)

    def test_recovery_dtbo_offset_mismatch_is_reported_not_hidden(self):
        blob = bytearray(bootimg.build_synthetic_image(1))
        offset = struct.unpack_from("<Q", blob, 1636)[0]
        struct.pack_into("<Q", blob, 1636, offset + 2048)
        image = bootimg.parse(bytes(blob))
        self.assertTrue(any("recovery_dtbo_offset" in item for item in image.warnings))
        # 提取仍按顺序布局，不被错误声明带偏。
        self.assertEqual(image.segment("recovery_dtbo").offset, offset)

    def test_random_mutations_never_raise_unexpected_exception(self):
        rng = random.Random(SEED_BOOTIMG)
        for version in bootimg.SUPPORTED_VERSIONS:
            base = bootimg.build_synthetic_image(version)
            limit = bootimg.HEADER_SIZES[version]
            for _ in range(BOOT_MUTATIONS):
                data = bytearray(base)
                for _ in range(rng.randint(1, 4)):
                    position = rng.randrange(0, min(limit, len(data)))
                    data[position] ^= 1 << rng.randrange(8)
                mutated = bytes(data)

                def unexpected(payload: bytes) -> bool:
                    try:
                        bootimg.parse(payload)
                    except ValueError:
                        return False
                    except Exception:  # noqa: BLE001 - 属性测试要捕获所有非 ValueError
                        return True
                    return False

                if unexpected(mutated):
                    try:
                        bootimg.parse(mutated)
                    except Exception as exc:  # noqa: BLE001
                        small = shrink(mutated, unexpected)
                        self.fail(
                            f"v{version} 突变触发未预期异常 {type(exc).__name__}: {exc}；"
                            + _repr_failure(small)
                        )

                def violates(payload: bytes) -> bool:
                    try:
                        image = bootimg.parse(payload)
                    except ValueError:
                        return False
                    return bool(_boot_invariant_problems(payload, image))

                if violates(mutated):
                    small = shrink(mutated, violates)
                    self.fail(f"v{version} 突变被接受但破坏不变量；" + _repr_failure(small))

    def test_random_sizes_roundtrip(self):
        rng = random.Random(SEED_BOOTIMG ^ 0x5A5A)
        for version in bootimg.SUPPORTED_VERSIONS:
            for _ in range(60):
                page = rng.choice((2048, 4096, 8192, 16384)) if version <= 2 else 4096
                kernel = rng.randbytes(rng.randint(1, 6000))
                ramdisk = rng.randbytes(rng.randint(0, 6000))
                with self.subTest(version=version, page=page,
                                  kernel=len(kernel), ramdisk=len(ramdisk)):
                    blob = bootimg.build_synthetic_image(
                        version, page_size=page, kernel=kernel, ramdisk=ramdisk,
                        second=rng.randbytes(rng.randint(0, 100)),
                        recovery_dtbo=rng.randbytes(rng.randint(0, 300)),
                        dtb=rng.randbytes(rng.randint(0, 300)),
                        signature=rng.randbytes(rng.randint(0, 300)),
                        kernel_addr=rng.randrange(2 ** 31),
                        ramdisk_addr=rng.randrange(2 ** 31),
                    )
                    image = bootimg.parse(blob)
                    self.assertEqual(image.segment("kernel").size, len(kernel))
                    if ramdisk:
                        self.assertEqual(image.segment("ramdisk").size, len(ramdisk))
                    else:
                        self.assertIsNone(image.segment("ramdisk"))
                        self.assertTrue(any("ramdisk_size=0" in w for w in image.warnings))
                    self.assertEqual(_boot_invariant_problems(blob, image), [])

    def test_cli_self_test_and_extract(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(bootimg.main(["--self-test"]), 0)
        self.assertIn("PASS", output.getvalue())

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            blob = bootimg.build_synthetic_image(2)
            image_path = directory / "boot_b.img"
            image_path.write_bytes(blob)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(bootimg.main([str(image_path), "--json"]), 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["version"], 2)
            self.assertEqual(payload["segments"][0]["name"], "kernel")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    bootimg.main([str(image_path), "--extract", str(directory / "out")]), 0
                )
            self.assertEqual((directory / "out" / "kernel").stat().st_size, 5000)
            self.assertEqual((directory / "out" / "ramdisk").stat().st_size, 3000)
            self.assertEqual((directory / "out" / "dtb").stat().st_size, 900)
            self.assertTrue((directory / "out" / "bootimg.json").is_file())


# ---------------------------------------------------------------------------
# DTB
# ---------------------------------------------------------------------------

def _fdt_invariant_problems(data: bytes, fdt) -> list[str]:
    problems: list[str] = []
    if fdt.totalsize > len(data):
        problems.append("totalsize 超出文件")
    if fdt.trailing_bytes < 0:
        problems.append("trailing_bytes 为负")
    if fdt.root.path != "/":
        problems.append("根节点路径不是 /")
    paths: list[str] = []
    seen: set[str] = set()
    for node in fdt.walk():
        if node.path in seen:
            problems.append(f"重复路径 {node.path}")
        seen.add(node.path)
        paths.append(node.path)
        if node.parent is not None and node not in node.parent.children:
            problems.append(f"{node.path} 与父节点不一致")
        depth = 0
        cursor = node
        while cursor.parent is not None:
            cursor = cursor.parent
            depth += 1
            if depth > dtbinfo.MAX_DEPTH:
                problems.append(f"{node.path} 深度超过上限")
                break
        for name in node.props:
            if not name:
                problems.append(f"{node.path} 存在空属性名")
    return problems


class FdtProperties(unittest.TestCase):
    def test_synthetic_required_nodes(self):
        fdt = dtbinfo.parse(dtbinfo.build_synthetic_fdt(dtbinfo.synthetic_tree()))
        info = dtbinfo.analyze(fdt)
        self.assertEqual(info["missing"], [])
        self.assertEqual(info["memory"]["total_bytes"], 0x40000000)
        self.assertEqual(info["framebuffer"]["width"], 1080)
        self.assertEqual(info["framebuffer"]["height"], 2400)
        self.assertEqual(info["framebuffer"]["stride"], 4320)
        self.assertEqual(info["framebuffer"]["format"], "a8b8g8r8")
        self.assertEqual(info["interrupt_controller"]["kind"], "GICv3")
        self.assertEqual(info["interrupt_controller"]["interrupt_cells"], 3)
        self.assertEqual(info["timer"]["entries"][0]["number"], 13)
        self.assertEqual(info["psci"]["method"], "smc")
        self.assertEqual(info["serial"]["path"], "/soc@0/serial@4a90000")
        self.assertEqual(info["cpus"]["count"], 2)
        self.assertEqual(info["cont_splash"][0]["verified"], False)

    def test_every_truncation_is_rejected(self):
        blob = dtbinfo.build_synthetic_fdt(dtbinfo.synthetic_tree())
        for cut in range(len(blob)):
            with self.assertRaises(dtbinfo.FdtError):
                dtbinfo.parse(blob[:cut])

    def test_invalid_structures_are_rejected(self):
        root = dtbinfo.synthetic_tree()
        blob = dtbinfo.build_synthetic_fdt(root)

        def mutated(offset: int, value: int, fmt: str = ">I") -> bytes:
            copy = bytearray(blob)
            struct.pack_into(fmt, copy, offset, value)
            return bytes(copy)

        cases = {
            "bad magic": dtbinfo.build_synthetic_fdt(root, magic=0xDEADBEEF),
            "version 15": dtbinfo.build_synthetic_fdt(root, version=15),
            "version 18": dtbinfo.build_synthetic_fdt(root, version=18),
            "missing end": dtbinfo.build_synthetic_fdt(root, omit_end=True),
            "totalsize too big": mutated(4, len(blob) + 1),
            "totalsize too small": mutated(4, 8),
            "off_struct beyond": mutated(8, len(blob) - 4),
            "off_struct misaligned": mutated(8, 41),
            "off_strings beyond": mutated(12, len(blob) - 1),
            "off_strings misaligned": mutated(12, 43),
            "off_rsvmap beyond": mutated(16, len(blob) - 8),
            "off_rsvmap misaligned": mutated(16, 44),
            "size_struct huge": mutated(36, 0xFFFFFFF0),
            "size_strings huge": mutated(32, 0xFFFFFFF0),
            "empty": b"",
            "short": blob[:39],
        }
        first_prop = 40 + 16 + 8
        cases["nameoff beyond"] = mutated(first_prop + 8, 0xFFFFFF)
        cases["prop len beyond"] = mutated(first_prop + 4, 0xFFFFFF)
        cases["last_comp > version"] = mutated(24, 99)

        duplicate_prop = dtbinfo._n(
            "", [("x", b"\0"), ("x", b"\0")], []
        )
        cases["duplicate prop"] = dtbinfo.build_synthetic_fdt(duplicate_prop)
        duplicate_child = dtbinfo._n(
            "", [], [dtbinfo._n("x", [], []), dtbinfo._n("x", [], [])]
        )
        cases["duplicate sibling"] = dtbinfo.build_synthetic_fdt(duplicate_child)
        deep = dtbinfo._n("x", [], [])
        for _ in range(dtbinfo.MAX_DEPTH + 1):
            deep = dtbinfo._n("x", [], [deep])
        deep = dtbinfo._n("", [], [deep])
        cases["too deep"] = dtbinfo.build_synthetic_fdt(deep)

        for label, data in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(dtbinfo.FdtError):
                    dtbinfo.parse(data)

    def test_random_mutations_never_raise_unexpected_exception(self):
        rng = random.Random(SEED_DTB)
        base = dtbinfo.build_synthetic_fdt(dtbinfo.synthetic_tree())

        for _ in range(DTB_MUTATIONS):
            data = bytearray(base)
            for _ in range(rng.randint(1, 4)):
                position = rng.randrange(len(data))
                data[position] ^= 1 << rng.randrange(8)
            mutated = bytes(data)

            def unexpected(payload: bytes) -> bool:
                try:
                    dtbinfo.parse(payload)
                except ValueError:
                    return False
                except Exception:  # noqa: BLE001
                    return True
                return False

            if unexpected(mutated):
                try:
                    dtbinfo.parse(mutated)
                except Exception as exc:  # noqa: BLE001
                    small = shrink(mutated, unexpected)
                    self.fail(
                        f"DTB 突变触发未预期异常 {type(exc).__name__}: {exc}；"
                        + _repr_failure(small)
                    )

            def violates(payload: bytes) -> bool:
                try:
                    fdt = dtbinfo.parse(payload)
                except ValueError:
                    return False
                return bool(_fdt_invariant_problems(payload, fdt))

            if violates(mutated):
                small = shrink(mutated, violates)
                self.fail("DTB 突变被接受但破坏不变量；" + _repr_failure(small))

    def test_random_trees_roundtrip(self):
        rng = random.Random(SEED_DTB ^ 0xA5A5)

        def make_node(depth: int, name: str) -> tuple:
            props: list[tuple[str, bytes]] = []
            for index in range(rng.randrange(0, 5)):
                prop_name = f"prop{index}"
                kind = rng.randrange(4)
                if kind == 0:
                    value = b""
                elif kind == 1:
                    value = bytes(rng.randrange(32, 127) for _ in range(rng.randrange(0, 12))) + b"\0"
                elif kind == 2:
                    value = struct.pack(">I", rng.randrange(2 ** 32))
                else:
                    value = rng.randbytes(rng.randrange(0, 16))
                props.append((prop_name, value))
            children = []
            if depth < 4:
                for index in range(rng.randrange(0, 4)):
                    children.append(make_node(depth + 1, f"n{depth}_{index}"))
            return (name, props, children)

        for _ in range(80):
            tree = make_node(0, "")
            blob = dtbinfo.build_synthetic_fdt(tree)
            fdt = dtbinfo.parse(blob)
            self.assertEqual(_fdt_invariant_problems(blob, fdt), [])
            # 逐节点比较路径与属性原始字节。
            expected: dict[str, dict[str, bytes]] = {}

            def collect(node: tuple, prefix: str) -> None:
                name, props, children = node
                path = "/" if not prefix and not name else (
                    "/" + name if prefix == "/" else prefix + "/" + name
                )
                expected[path] = dict(props)
                for child in children:
                    collect(child, path)

            collect(tree, "/")
            actual = {node.path: dict(node.props) for node in fdt.walk()}
            self.assertEqual(actual, expected)

    def test_redaction_hides_identifiers(self):
        fdt = dtbinfo.parse(dtbinfo.build_synthetic_fdt(dtbinfo.synthetic_tree()))
        info = dtbinfo.analyze(fdt, redact=True)
        text = json.dumps(info, ensure_ascii=False)
        self.assertNotIn("1234567890", text)
        self.assertIn("已脱敏", text)
        tree = dtbinfo.format_tree(fdt, redact=True)
        self.assertNotIn("1234567890", tree)

    def test_analysis_reports_missing_nodes(self):
        root = dtbinfo._n("", [("#address-cells", dtbinfo._u32s(2)),
                               ("#size-cells", dtbinfo._u32s(2))], [])
        info = dtbinfo.analyze(dtbinfo.parse(dtbinfo.build_synthetic_fdt(root)))
        self.assertEqual(
            set(info["missing"]),
            {"memory", "framebuffer", "interrupt-controller(gic-v3)", "timer(arm,armv8-timer)",
             "psci", "serial"},
        )

    def test_psci_v01_ids_come_from_dtb_not_guessed(self):
        tree = dtbinfo._n("", [], [
            dtbinfo._n("psci", [
                ("compatible", dtbinfo._s("arm,psci")),
                ("method", dtbinfo._s("smc")),
                ("cpu_on", dtbinfo._u32s(0x95C10002)),
                ("cpu_off", dtbinfo._u32s(0x95C10001)),
            ], []),
        ])
        info = dtbinfo.analyze(dtbinfo.parse(dtbinfo.build_synthetic_fdt(tree)))
        self.assertEqual(info["psci"]["function_ids"]["cpu_on"], 0x95C10002)
        self.assertEqual(info["psci"]["function_ids"]["cpu_off"], 0x95C10001)
        # 0.1 没有标准 SYSTEM_OFF/RESET ID，不能填 0x84000008/09。
        self.assertIsNone(info["psci"]["function_ids"]["system_reset"])
        self.assertIsNone(info["psci"]["function_ids"]["system_off"])

    def test_cli_self_test_and_require_all(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(dtbinfo.main(["--self-test"]), 0)
        self.assertIn("PASS", output.getvalue())

        root = dtbinfo._n("", [], [])
        blob = dtbinfo.build_synthetic_fdt(root)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fdt.dtb"
            path.write_bytes(blob)
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(dtbinfo.main([str(path), "--require-all"]), 2)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(dtbinfo.main([str(path), "--json"]), 0)
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["missing"])


class SelfTestProperties(unittest.TestCase):
    def test_embedded_self_tests_pass(self):
        self.assertGreater(bootimg._run_self_test(), 0)
        self.assertGreater(dtbinfo._run_self_test(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
