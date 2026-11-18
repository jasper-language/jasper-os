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
            "runtime-resource-capacity",
            "kernel product capacity policy; must remain explicit, budget-derived, and rejection-visible",
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
