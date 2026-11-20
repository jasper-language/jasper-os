#!/usr/bin/env python3
"""Generate and verify the classified Issue #35 hardcode inventory ledger.

生成并校验 Issue #35 硬编码存量分类账；分类是审计输入，不自动授予豁免。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs" / "hardcode-inventory-baseline.json"
GATE = ROOT / "scripts" / "check-hardcode-gate.py"
CATEGORIES = {
    "protocol-abi",
    "explicit-safety-policy",
    "runtime-resource-capacity",
    "platform-adapter",
    "test-demo-fixture",
    "confirmed-defect",
    "unclassified",
}
IDENTIFIER = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+(?:mut\s+)?"
    r"(?P<name>[A-Z][A-Z0-9_]*)\b"
)
FINDING = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+): (?P<rules>[^:]+): .*: (?P<text>.*)$")


def load_gate():
    spec = importlib.util.spec_from_file_location("hardcode_gate", GATE)
    if spec is None or spec.loader is None:
        raise SystemExit("hardcode-ledger: cannot load hardcode gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules["hardcode_gate"] = module
    spec.loader.exec_module(module)
    return module


def baseline_records(gate) -> tuple[dict[str, object], list[tuple[str, dict[str, str]]]]:
    baseline = gate.load_inventory_snapshot(BASELINE)
    findings = gate.scan_inventory()
    current = Counter(gate.inventory_record(finding)["fingerprint"] for finding in findings)
    previous = {
        entry["fingerprint"]: int(entry["count"])
        for entry in baseline["entries"]
    }
    if current != Counter(previous):
        added = current - Counter(previous)
        removed = Counter(previous) - current
        raise SystemExit(
            "hardcode-ledger: baseline drift "
            f"added={sum(added.values())} removed={sum(removed.values())}; "
            "refresh the baseline before regenerating the ledger"
        )
    parsed: dict[str, dict[str, str]] = {}
    for finding in findings:
        match = FINDING.match(finding)
        if match is None:
            raise SystemExit(f"hardcode-ledger: malformed finding: {finding}")
        record = gate.inventory_record(finding)
        parsed.setdefault(
            record["fingerprint"],
            {
                "line": match.group("line"),
                "text": match.group("text").strip(),
            },
        )
    ordered = sorted(
        (
            (entry["fingerprint"], entry, parsed[entry["fingerprint"]])
            for entry in baseline["entries"]
        ),
        key=lambda item: (item[1]["path"], item[1]["rules"], item[0]),
    )
    records = [
        (
            fingerprint,
            {
                **entry,
                **source,
                "source": source_line(entry["path"], int(source["line"])),
            },
        )
        for fingerprint, entry, source in ordered
    ]
    return baseline, records


def source_line(path: str, line: int) -> str:
    lines = (ROOT / path).read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def identifier(source: str) -> str:
    match = IDENTIFIER.search(source)
    return match.group("name") if match else ""


def classify(path: str, rules: str, source: str) -> tuple[str, str]:
    """Classify one fingerprint, conservatively leaving unknown consumers open.

    保守分类单个指纹；缺少消费者证据时保持 unclassified。
    """
    name = identifier(source)
    lowered = path.lower()
    if path == "kernel-core/src/fdt.rs" and any(
        marker in source
        for marker in (
            "redistributor-stride",
            "strip_suffix(&[0])",
            'unwrap_or("arm,psci")',
            'unwrap_or("arm,pl011")',
            'unwrap_or(if v3 { "arm,gic-v3" }',
        )
    ):
        return (
            "protocol-abi",
            "FDT binding default or diagnostic compatible string, not a discovered hardware value",
        )
    if path == "kernel/build.rs" and "link-pixel6a" in source:
        return (
            "platform-adapter",
            "explicit Pixel verification linker layout selected only by the verification build",
        )
    if path == "kernel-core/src/persistent_install.rs" and name == "BLOB_SLOTS":
        return (
            "protocol-abi",
            "fixed v4 on-disk blob slot map; resize requires a format migration and crash recovery test",
        )
    if path == "kernel-core/src/sandbox_launch_abi.rs" and name in {
        "MAX_DEVICE_GRANTS",
        "MAX_DATA_SCOPES",
    }:
        return (
            "protocol-abi",
            "fixed Sandbox launch v1 record fields; changing either count changes CREATE_BYTES and offsets",
        )
    if path == "kernel/src/kmain.rs" and "pixel6a-smp-probe" in source:
        return (
            "platform-adapter",
            "explicit physical-device verification probe branch",
        )
    if path == "kernel/src/kmain.rs" and "JSR-PIXEL6A" in source:
        return (
            "platform-adapter",
            "explicit physical-device verification status output",
        )
    if path == "kernel-core/src/capacity/tests.rs":
        return (
            "test-demo-fixture",
            "deterministic capacity test fixture; not a production capacity source",
        )
    if path in {"kernel-core/src/bench.rs", "kernel/src/sched/pex4_probe.rs"}:
        return (
            "test-demo-fixture",
            "bounded benchmark or probe fixture, not a production hardware fact",
        )
    if path == "kernel/src/arch/x86_64/bm1.rs":
        return (
            "test-demo-fixture",
            "QEMU-only BM-1 acceptance trace buffer; the module has no effect on the default kernel",
        )
    if path == "kernel/src/s2.rs":
        return (
            "test-demo-fixture",
            "bounded cross-CPU syscall acceptance campaign",
        )
    if path == "kernel-core/src/pci.rs" and "unwrap_or(0)" in source:
        return (
            "test-demo-fixture",
            "PCI configuration-space model default used by tests, not hardware discovery",
        )
    if any(
        marker in source
        for marker in (
            'psci.method.unwrap_or("none")',
            "self.msr_read(index).unwrap_or(0)",
            "chunk.get(1).unwrap_or(&0)",
        )
    ):
        return (
            "protocol-abi",
            "architecture or wire protocol reset/default value, not a runtime inventory fact",
        )
    if any(
        marker in source
        for marker in (
            "uart.unwrap_or(0)",
            "rtc.unwrap_or(0)",
            "uart::interrupt().unwrap_or(0)",
            'NAMES.get(line).copied().unwrap_or("none")',
            'PINS.lock().get(line).map(|pin| pin.name).unwrap_or("none")',
            "MAP.get(make as usize).copied().unwrap_or(b'?')",
        )
    ):
        return (
            "explicit-safety-policy",
            "absent-device sentinel or diagnostic-only display; control paths reject zero/unknown ids",
        )
    if path == "kernel/src/binder.rs" and name == "MAX_BINDER_THREADS":
        return (
            "runtime-resource-capacity",
            "per-process Binder looper registry; the Vec already admits each registration with try_reserve",
        )
    if path == "kernel/src/linux_abi.rs" and name == "MAX_NODES":
        return (
            "explicit-safety-policy",
            "bounded robust-list traversal and cycle detection during faulted process exit; allocation cannot be required on this path",
        )
    if path == "kernel/src/boot.rs" and name == "MAX_REGIONS":
        return (
            "explicit-safety-policy",
            "pre-heap bootloader handoff staging bound; overflow is counted and frame allocation fails closed until the complete memory map is retained",
        )
    if (
        path == "kernel/src/sched/mod.rs" and name == "PI_MAILBOX_CAPACITY"
    ) or (
        path == "kernel/src/sched/scheduler.rs" and name == "WAKE_MAILBOX_CAPACITY"
    ):
        return (
            "explicit-safety-policy",
            "per-CPU interrupt-safe delivery mailbox: full returns to the caller for synchronous completion or retry and never overwrites or drops a wake/PI request",
        )
    if path == "kernel/src/linux_abi.rs" and name in {
        "MAX_REGISTRATIONS",
        "MAX_REQUESTS",
        "MAX_READ",
        "MAX_RANDOM",
        "MAX_FUTEX_WAITERS",
        "MAX_FLOCK_LOCKS",
        "MAX_LINUX_KEYS",
        "MAX_GROUPS",
        "MAX_SYSV_SEM_SETS",
        "MAX_SYSV_SEMS_PER_SET",
        "MAX_SYSV_SEM_WAITERS",
        "MAX_SYSV_SEM_UNDOS",
        "MAX_SYSV_SHARED_ATTACHMENTS",
    }:
        return (
            "runtime-resource-capacity",
            "Linux compatibility collection or operation capacity; migrate the consumer to handle, memory, or Workload admission",
        )
    if path == "kernel/src/linux_abi.rs" and name in {
        "MAX_IOVECS",
        "MAX_WAITV",
        "MAX_SYSV_SEM_OPS",
    }:
        if name == "MAX_IOVECS" and "1024" in source:
            return (
                "protocol-abi",
                "Linux UAPI IOV_MAX=1024 for message vectors; preserve the published compatibility value",
            )
        return (
            "explicit-safety-policy",
            "bounded vector or operation batch; excess work must fail explicitly without silently truncating results",
        )
    if path == "kernel/src/linux_abi.rs" and name == "MAX_RAW_KEY":
        return (
            "protocol-abi",
            "fscrypt UAPI master-key payload width; preserve the documented 64-byte maximum",
        )
    if name in {
        "MAX_BARS",
        "MAX_TEXT_OFFSET",
        "MAX_GPA",
        "MAX_GENERATION",
        "MAX_ARGS",
        "MAX_MSG_HANDLES",
    }:
        return (
            "protocol-abi",
            "PCI configuration limit, architecture address width, wire handle count, or internal bit field",
        )
    if name in {
        "MAX_WAITS",
        "MAX_SPINS",
        "MAX_CHUNK_US",
        "MAX_POLL_STEPS",
        "MAX_SETTLE",
        "MAX_BURST_TICKS",
        "MAX_SCHED_CLASSES",
        "MAX_TAGS",
        "MAX_CAPABILITY_HOPS",
        "MAX_PERMILLE",
        "MAX_MODULE_VERSION",
        "MAX_POLICY_RULES",
        "MAX_SAMPLES",
        "MIN_ALIGN",
        "MIN_BLOCK",
        "MIN_TEXT",
        "MAX_SENDFILE",
        "MAX_RANK",
        "MAX_BOOT_ATTEMPTS",
        "MAX_ROUNDS",
        "MAX_LEN",
    }:
        return (
            "explicit-safety-policy",
            "explicit bounded-work, parser, scheduling, or protocol-conformance policy",
        )
    if name in {
        "MAX_REGIONS",
        "MAX_FILES",
        "MAX_JOURNAL_NODES",
        "MAX_VFS_HANDLES",
        "MAX_DEPS",
        "MAX_NODES",
        "MAX_HANDLES",
        "MAX_KEYS",
        "MAX_WORKERS",
        "MAX_CHILDREN",
        "MAX_GUEST_MAPPINGS",
        "MAX_DEVICE_GRANTS",
        "MAX_MODULE_DEPENDENCIES",
        "MAX_REGIONS",
    }:
        return (
            "runtime-resource-capacity",
            "runtime-owned collection or metadata capacity; callers must enforce budget and expose rejection",
        )
    if name == "DEFAULT" or name.startswith("DEFAULT_"):
        return (
            "explicit-safety-policy",
            "documented scheduling, pressure, or arbitration policy default; not a discovered hardware fact",
        )
    if name == "MAX_IDS":
        return (
            "protocol-abi",
            "versioned SyscallSet bit width; compatibility must reject ids outside the published ABI",
        )
    if any(
        marker in source
        for marker in (
            'uart.unwrap_or(0)',
            'rtc.unwrap_or(0)',
            'NAMES.get(line).copied().unwrap_or("none")',
            'PINS.lock().get(line).map(|pin| pin.name).unwrap_or("none")',
        )
    ):
        return (
            "explicit-safety-policy",
            "absent-device sentinel or diagnostic display; consumers reject unavailable lines",
        )
    if any(
        marker in source
        for marker in (
            "requested.unwrap_or(Rights::NONE)",
            ".unwrap_or(false)",
            ".unwrap_or(1)",
            ".unwrap_or(15)",
            ".unwrap_or(0);",
            ".unwrap_or((SbiError::Failed))",
            ".unwrap_or(SbiError::Failed)",
            "KERNEL_STACK_TOP.get(index).unwrap_or_else",
            "CPU_TSS.get(super::smp::cpu_index())",
            "CPUS.get(index).unwrap_or_else",
            "TABLE.get().unwrap_or(&EMPTY)",
            "let best = cands",
            "choice.as_ref()",
            "from_utf8(&self.buf[..self.len]).unwrap_or",
            "image_base(&arch).unwrap_or_else",
            "system_table_raw()",
            "s.len().min(WRITE_MAX)",
            ".unwrap_or(true)",
        )
    ):
        return (
            "explicit-safety-policy",
            "documented fail-closed, default-deny, diagnostic, or bounded-progress fallback; must not synthesize hardware state",
        )
    if name in {
        "MAX_COUNTER",
        "MIN_ALTSTACK",
        "MAX_PROFILE_NAME",
        "MAX_MODULE_NAME",
        "MAX_MODULE_VERSION",
    }:
        return (
            "protocol-abi",
            "identifier is a Linux UAPI width or semantic boundary; preserve the documented Linux value",
        )
    if path == "kernel-core/src/acpi.rs" and "IsaRoute" in source:
        return (
            "protocol-abi",
            "ISA route fallback is the explicitly documented ACPI bus-default policy",
        )
    if name in {
        "MAX_TABLE_LEN",
        "MAX_DMAR_UNITS",
        "MAX_DMAR_SCOPES",
        "MAX_DMAR_PATH",
        "MAX_CONTEXT",
        "MAX_WRITE",
        "MAX_GETDENTS",
        "MAX_MESSAGES",
        "MAX_SENDFILE",
        "MAX_ENTRIES",
    }:
        return (
            "explicit-safety-policy",
            "identifier bounds parser work or one compatibility-service copy batch; behavior must return bounded partial progress rather than silently lose data",
        )
    if "/arch/" in lowered and re.search(r"pixel|qemu", source, re.IGNORECASE):
        return (
            "platform-adapter",
            "architecture-specific selector or probe; verify it remains behind an explicit platform profile",
        )
    if name in {
        "MAX_CPUS",
        "MAX_TASKS",
        "MAX_OBJECTS",
        "MAX_FDS",
        "MAX_SOCKETS",
        "MAX_JOBS",
        "MAX_LINUX_THREADS",
        "MAX_FUTEX_WORDS",
        "MAX_POSIX_TIMERS",
        "MAX_PENDING_SIGNAL_RECORDS",
    } or re.search(
        r"(?:^|_)(?:CPU|TASK|OBJECT|FD|SOCKET|JOB|IRQ|VECTOR|RING|QUEUE|SHARD|"
        r"FRAME|PAGE|ENDPOINT|PROCESS|TIMER|SUBSCRIPTION|CAPACITY|SLOT)S?(?:_|$)",
        name,
    ):
        return (
            "runtime-resource-capacity",
            "identifier names a runtime-owned collection or capacity; consumer must derive an admission budget",
        )
    if re.search(
        r"(?:DEPTH|FILTER|CAUSE|AUDIT|TRACE|RECORD|EVENT|NAME|PATH|BYTES|LINES|"
        r"LEVEL|CHAIN|BATCH|LIMIT|WINDOW|SECTION|HEADER|SEGMENT|ENTRY|RELOC|"
        r"SYMBOL|AUX|TLS|LIFECYCLE|ADDRESS|IMAGE|PROGRAM|ARCHIVE|UNPACKED)",
        name,
    ) or rules in {"HC-G2,HC-G6", "HC-G6"}:
        return (
            "explicit-safety-policy",
            "identifier or clamp names a parser, batching, address, or security ceiling; retain only with a documented policy",
        )
    if lowered.startswith(
        (
            "jaso/",
            "compat-core/",
            "compat-loader/",
            "compat-packages/",
            "compat-graphics/",
            "lifecycle-model/",
        )
    ):
        return (
            "protocol-abi",
            "path owns a wire, loader, package, graphics, or lifecycle ABI; consumer review remains required",
        )
    if lowered == "kernel-core/src/config.rs":
        return (
            "explicit-safety-policy",
            "declared product validation bound: KernelConfig::validate rejects out-of-range timer, Task, Object, RT, and stack values before publishing capacity",
        )
    return (
        "unclassified",
        "baseline has no consumer-level classification yet; keep open rather than granting an exception",
    )


def build_ledger(gate) -> dict[str, object]:
    baseline, records = baseline_records(gate)
    entries = []
    weighted: Counter[str] = Counter()
    for fingerprint, record in records:
        category, reason = classify(record["path"], record["rules"], record["source"])
        count = int(record["count"])
        weighted[category] += count
        entries.append(
            {
                "fingerprint": fingerprint,
                "path": record["path"],
                "rules": record["rules"],
                "count": count,
                "line": int(record["line"]),
                "source": record["source"],
                "category": category,
                "reason": reason,
            }
        )
    counts = Counter(entry["category"] for entry in entries)
    return {
        "schema": 1,
        "baseline_total": int(baseline["total"]),
        "categories": sorted(CATEGORIES),
        "counts": dict(sorted(counts.items())),
        "weighted_counts": dict(sorted(weighted.items())),
        "entries": entries,
    }


def verify_ledger(gate, ledger: dict[str, object]) -> None:
    baseline, records = baseline_records(gate)
    if ledger.get("schema") != 1:
        raise SystemExit("hardcode-ledger: unsupported ledger schema")
    entries = ledger.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("hardcode-ledger: entries must be a list")
    if int(ledger.get("baseline_total", -1)) != int(baseline["total"]):
        raise SystemExit("hardcode-ledger: baseline_total does not match baseline")
    expected = {fingerprint: record for fingerprint, record in records}
    seen: set[str] = set()
    counts: Counter[str] = Counter()
    weighted: Counter[str] = Counter()
    for entry in entries:
        fingerprint = entry.get("fingerprint")
        if fingerprint in seen:
            raise SystemExit(f"hardcode-ledger: duplicate fingerprint {fingerprint}")
        seen.add(fingerprint)
        record = expected.get(fingerprint)
        if record is None:
            raise SystemExit(f"hardcode-ledger: extra fingerprint {fingerprint}")
        if entry.get("path") != record["path"] or entry.get("rules") != record["rules"]:
            raise SystemExit(f"hardcode-ledger: path/rules mismatch for {fingerprint}")
        if int(entry.get("count", 0)) != int(record["count"]):
            raise SystemExit(f"hardcode-ledger: count mismatch for {fingerprint}")
        category = entry.get("category")
        if category not in CATEGORIES:
            raise SystemExit(f"hardcode-ledger: invalid category {category}")
        if not str(entry.get("reason", "")).strip():
            raise SystemExit(f"hardcode-ledger: missing reason for {fingerprint}")
        counts[category] += 1
        weighted[category] += int(entry["count"])
    missing = set(expected) - seen
    if missing:
        raise SystemExit(f"hardcode-ledger: {len(missing)} baseline fingerprints unclassified")
    declared = ledger.get("counts", {})
    if declared != dict(sorted(counts.items())):
        raise SystemExit("hardcode-ledger: category counts do not match entries")
    declared_weighted = ledger.get("weighted_counts", {})
    if declared_weighted != dict(sorted(weighted.items())):
        raise SystemExit("hardcode-ledger: weighted counts do not match entries")
    if sum(weighted.values()) != int(baseline["total"]):
        raise SystemExit("hardcode-ledger: weighted entries do not cover baseline total")


def self_test(gate) -> None:
    cases = [
        ("kernel-core/src/smp.rs", "HC-G1", "pub const MAX_CPUS: usize = 128;"),
        ("jaso/src/wire.rs", "HC-G1", "pub const MAX_MESSAGE: usize = 65536;"),
        ("kernel/src/arch/aarch64/platform.rs", "HC-G3", "#[cfg(feature = \"pixel6a-smoke\")]"),
        ("kernel-core/src/acpi.rs", "HC-G1", "pub const MAX_DEPTH: usize = 8;"),
        ("kernel-core/src/acpi.rs", "HC-G1", "pub const MAX_DMAR_UNITS: usize = 8;"),
        ("kernel/src/linux_abi.rs", "HC-G1", "const MAX_WRITE: usize = 1024 * 1024;"),
        ("kernel/src/linux_abi.rs", "HC-G1", "const MIN_ALTSTACK: u64 = 2048;"),
    ]
    observed = {classify(path, rules, source)[0] for path, rules, source in cases}
    assert {"runtime-resource-capacity", "protocol-abi", "platform-adapter", "explicit-safety-policy"} <= observed
    ledger = build_ledger(gate)
    verify_ledger(gate, ledger)
    print("hardcode-ledger: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", type=Path, help="write the current classified ledger")
    parser.add_argument("--check", type=Path, help="verify a classified ledger")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    gate = load_gate()
    if args.self_test:
        self_test(gate)
        return 0
    if args.write:
        ledger = build_ledger(gate)
        args.write.write_text(
            json.dumps(ledger, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"hardcode-ledger: wrote {len(ledger['entries'])} entries "
            f"counts={ledger['counts']} weighted={ledger['weighted_counts']}"
        )
        return 0
    if args.check:
        ledger = json.loads(args.check.read_text(encoding="utf-8"))
        verify_ledger(gate, ledger)
        print(
            f"hardcode-ledger: PASS entries={len(ledger['entries'])} "
            f"counts={ledger['counts']} weighted={ledger['weighted_counts']}"
        )
        return 0
    parser.error("select --write, --check, or --self-test")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
