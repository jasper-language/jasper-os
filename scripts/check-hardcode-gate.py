#!/usr/bin/env python3
"""Block newly introduced unsourced hardware facts and capacity limits.

The incremental gate inspects production lines added by the current change.
``--inventory`` separately audits the complete current tree. A review exception
must match a registered source, issue and reason in
``docs/hardcode-review-sources.tsv``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_REGISTRY = ROOT / "docs" / "hardcode-review-sources.tsv"
SCOPE = (
    "arch-probes",
    "boot-manager",
    "compat-core",
    "compat-graphics",
    "compat-loader",
    "compat-packages",
    "jaso",
    "kernel",
    "kernel-core",
    "lifecycle-boot",
    "lifecycle-model",
    "lifecycle-staging",
    "modules",
    "netd",
    "tools",
    "user",
    "xtask",
)
SOURCE_SUFFIXES = (".rs",)
ZERO_SHA = re.compile(r"^0+$")
REVIEW = "JASPER-HARDCODE-REVIEW:"
REVIEW_PATTERN = re.compile(
    r"JASPER-HARDCODE-REVIEW:\s+"
    r"issue=(?P<issue>[1-9][0-9]*)\s+"
    r"source=(?P<source>[A-Za-z0-9_.:/-]+)\s+"
    r"reason=(?P<reason>[A-Za-z0-9_.:/-]+)\s*$"
)


@dataclass(frozen=True)
class Rule:
    ident: str
    pattern: re.Pattern[str]
    reason: str


RULES = (
    Rule(
        "HC-G1",
        re.compile(
            r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+(?:mut\s+)?"
            r"(?:MAX|MIN|DEFAULT|QEMU|PIXEL|BOARD|PLATFORM)[A-Z0-9_]*\b"
        ),
        "fixed capacity, default, or platform fact",
    ),
    Rule(
        "HC-G2",
        re.compile(r"\.min\s*\(\s*(?:[A-Z][A-Z0-9_]*MAX[A-Z0-9_]*|MAX_[A-Z0-9_]*)\s*\)"),
        "physical inventory silently truncated by a software maximum",
    ),
    Rule(
        "HC-G3",
        re.compile(r"\b(?:QEMU|Pixel\s*6a|qemu-virt)\b", re.IGNORECASE),
        "platform-specific value in generic production code",
    ),
    Rule(
        "HC-G4",
        re.compile(r"\bverified\s*(?::|=)\s*(?:true|CapabilityState::Verified)"),
        "verified capability state assigned without independent evidence",
    ),
    Rule(
        "HC-G5",
        re.compile(
            r"\b(?:max_tasks|max_objects|max_rt|max_rings_per_process|"
            r"max_in_flight_per_process|max_endpoints_per_process|"
            r"frame_bitmap_words|max_map_pages|max_vm_guest_frames)\s*:\s*\d"
        ),
        "operational capacity chosen from an unqualified numeric literal",
    ),
    Rule(
        "HC-G6",
        re.compile(r"\b(?:max|min|clamp)\s*\([^)]*\b(?:MAX|DEFAULT)_[A-Z0-9_]*"),
        "resource size clamped to a software default or maximum",
    ),
    Rule(
        "HC-G8",
        re.compile(
            r"\bconst\s+[A-Z0-9_]*(?:CAPACITY|SLOTS|LINES|VECTORS|CPUS)"
            r"[A-Z0-9_]*\s*:\s*[^=]+\s*=\s*\d"
        ),
        "fixed production capacity introduced as a numeric constant",
    ),
)

DISCOVERY_PATH = re.compile(
    r"(?:/arch/|boot|memory|paging|acpi|fdt|pci|irq|msi|capability|"
    r"virtio|device|smp|numa|mmio)",
    re.IGNORECASE,
)
UNWRAP_OR = re.compile(r"\.unwrap_or(?:_else)?\s*\(")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _excluded(path: str) -> bool:
    return (
        "/tests/" in f"/{path}"
        or path.endswith("_demo.rs")
        or "/demo" in path
        or path.endswith("/baseline.rs")
        or path.endswith("/net_policy.rs")
        or path.endswith("/hwv5_policy.rs")
    )


def _in_scope(path: str) -> bool:
    return path.endswith(SOURCE_SUFFIXES) and any(
        path.startswith(scope + "/") for scope in SCOPE
    )


def load_source_registry(
    path: Path = SOURCE_REGISTRY,
) -> dict[str, tuple[str, str, str]]:
    """Load exact review sources as source -> (issue, kind, reference)."""
    registry: dict[str, tuple[str, str, str]] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 4 or any(not field for field in fields):
            raise SystemExit(
                f"hardcode-gate: malformed source registry line {line_number}"
            )
        source, issue, kind, reference = fields
        if source in registry:
            raise SystemExit(f"hardcode-gate: duplicate review source {source}")
        if kind not in {"spec", "policy", "runtime", "build", "test"}:
            raise SystemExit(f"hardcode-gate: invalid review kind {kind}")
        registry[source] = (issue, kind, reference)
    return registry


def review_source(
    line: str, registry: dict[str, tuple[str, str, str]]
) -> str | None:
    """Return a registered source id for a complete structured exception."""
    match = REVIEW_PATTERN.search(line)
    if not match:
        return None
    source = match.group("source")
    record = registry.get(source)
    if record is None or record[0] != match.group("issue"):
        return None
    return source


def _scan_line(
    path: str,
    line_number: int,
    text: str,
    registry: dict[str, tuple[str, str, str]],
) -> str | None:
    if not _in_scope(path) or _excluded(path):
        return None
    code = text.split("//", 1)[0]
    reasons = [rule for rule in RULES if rule.pattern.search(code)]
    if DISCOVERY_PATH.search(path) and UNWRAP_OR.search(code):
        reasons.append(
            Rule(
                "HC-G7",
                UNWRAP_OR,
                "hidden fallback in a discovery or hardware path",
            )
        )
    if not reasons or review_source(text, registry) is not None:
        return None
    ids = ",".join(rule.ident for rule in reasons)
    why = "; ".join(rule.reason for rule in reasons)
    return f"{path}:{line_number}: {ids}: {why}: {text.strip()}"


def scan_patch(
    patch: str, registry: dict[str, tuple[str, str, str]] | None = None
) -> list[str]:
    """Return one diagnostic per unsourced production line."""
    registry = registry or load_source_registry()
    findings: list[str] = []
    path = ""
    line_number = 0
    for raw in patch.splitlines():
        if raw.startswith("+++ b/"):
            path = raw[6:]
            continue
        match = HUNK.match(raw)
        if match:
            line_number = int(match.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            text = raw[1:]
            finding = _scan_line(path, line_number, text, registry)
            if finding:
                findings.append(finding)
            line_number += 1
        elif raw.startswith(" "):
            line_number += 1
    return findings


def scan_inventory(
    registry: dict[str, tuple[str, str, str]] | None = None,
) -> list[str]:
    """Audit the complete current production tree without using a diff base."""
    registry = registry or load_source_registry()
    findings: list[str] = []
    for scope in SCOPE:
        root = ROOT / scope
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.rs")):
            relative = path.relative_to(ROOT).as_posix()
            if _excluded(relative):
                continue
            for line_number, raw in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(),
                1,
            ):
                finding = _scan_line(relative, line_number, raw, registry)
                if finding:
                    findings.append(finding)
    return findings


def inventory_record(finding: str) -> dict[str, str]:
    """Convert a diagnostic into a stable baseline record."""
    parts = finding.split(": ", 3)
    if len(parts) != 4:
        raise SystemExit(f"hardcode-gate: malformed inventory finding: {finding}")
    location, rules, _, text = parts
    path = location.rsplit(":", 1)[0]
    identity = "\0".join(
        (path, rules, text.strip())
    )
    return {
        "fingerprint": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "path": path,
        "rules": rules,
    }


def inventory_snapshot(findings: list[str]) -> dict[str, object]:
    """Build a deterministic multiset snapshot of inventory findings."""
    records = Counter(inventory_record(finding)["fingerprint"] for finding in findings)
    details: dict[str, dict[str, str]] = {}
    for finding in findings:
        record = inventory_record(finding)
        details.setdefault(record["fingerprint"], record)
    return {
        "schema": 1,
        "scope": list(SCOPE),
        "total": len(findings),
        "entries": [
            {
                **details[fingerprint],
                "count": count,
            }
            for fingerprint, count in sorted(records.items())
        ],
    }


def load_inventory_snapshot(path: Path) -> dict[str, object]:
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"hardcode-gate: invalid inventory baseline {path}: {exc}") from exc
    if snapshot.get("schema") != 1 or not isinstance(snapshot.get("entries"), list):
        raise SystemExit(f"hardcode-gate: unsupported inventory baseline {path}")
    return snapshot


def compare_inventory(
    findings: list[str], baseline: dict[str, object]
) -> tuple[list[dict[str, str]], int]:
    """Return newly introduced records and the number of cleared baseline records."""
    current_records = list(map(inventory_record, findings))
    current = Counter(record["fingerprint"] for record in current_records)
    current_details = {
        record["fingerprint"]: record for record in current_records
    }
    previous: Counter[str] = Counter()
    for entry in baseline["entries"]:
        fingerprint = entry["fingerprint"]
        previous[fingerprint] = int(entry["count"])
    added = current - previous
    removed = previous - current
    new_records = [current_details[fingerprint] for fingerprint in added]
    return new_records, sum(removed.values())


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def resolve_base(requested: str) -> str:
    if requested and not ZERO_SHA.match(requested):
        return requested
    try:
        return _git("rev-parse", "HEAD^").strip()
    except subprocess.CalledProcessError as exc:
        raise SystemExit("hardcode-gate: cannot resolve a comparison base") from exc


def self_test() -> None:
    patch = """diff --git a/kernel/src/arch/boot.rs b/kernel/src/arch/boot.rs
--- a/kernel/src/arch/boot.rs
+++ b/kernel/src/arch/boot.rs
@@ -1,0 +1,8 @@
+const MAX_CPUS: usize = 32;
+let line = count.min(MAX_LINES);
+let verified = true;
+let name = entries.get(index).unwrap_or("none");
+const INPUT_CAPACITY: usize = 4096;
+const MAX_PROTOCOL: usize = 64; // JASPER-HARDCODE-REVIEW: issue=33 source=PCI-SIG-MSI-X reason=11-bit-table-size-field
+const BAD_CAPACITY_SOURCE: usize = 16; // JASPER-HARDCODE-REVIEW: issue=33 source=unregistered reason=missing
+const BAD_CAPACITY_SHAPE: usize = 16; // JASPER-HARDCODE-REVIEW: issue=33 source=PCI-SIG-MSI-X
diff --git a/boot-manager/src/lib.rs b/boot-manager/src/lib.rs
--- a/boot-manager/src/lib.rs
+++ b/boot-manager/src/lib.rs
@@ -1,0 +1,1 @@
+const MAX_LOADERS: usize = 8;
"""
    found = scan_patch(patch)
    assert len(found) == 8, found
    assert any("HC-G1" in item for item in found)
    assert any("HC-G2" in item for item in found)
    assert any("HC-G7" in item for item in found)
    assert any("HC-G8" in item for item in found)
    assert any("BAD_CAPACITY_SOURCE" in item for item in found)
    assert any("BAD_CAPACITY_SHAPE" in item for item in found)
    assert any("boot-manager/src/lib.rs" in item for item in found)
    assert not any(item.endswith("MAX_PROTOCOL: usize = 64;") for item in found)
    first = inventory_record(
        "kernel/src/example.rs:1: HC-G1: fixed capacity: const MAX_FIRST: usize = 4;"
    )
    second = inventory_record(
        "kernel/src/example.rs:2: HC-G1: fixed capacity: const MAX_SECOND: usize = 4;"
    )
    assert first["fingerprint"] != second["fingerprint"]
    snapshot = inventory_snapshot(found)
    assert snapshot["total"] == len(found)
    assert "entries" in snapshot
    print("hardcode-gate: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="audit the complete current tree separately from the incremental gate",
    )
    parser.add_argument(
        "--inventory-verbose",
        action="store_true",
        help="print every finding produced by --inventory",
    )
    parser.add_argument(
        "--inventory-baseline",
        default="",
        help="fail when inventory contains fingerprints absent from this baseline",
    )
    parser.add_argument(
        "--write-inventory-baseline",
        default="",
        help="write the current deterministic inventory snapshot and exit",
    )
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.inventory:
        findings = scan_inventory()
        if args.write_inventory_baseline:
            path = Path(args.write_inventory_baseline)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(inventory_snapshot(findings), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"hardcode-inventory: wrote {len(findings)} findings to {path}")
            return 0
        counts: dict[str, int] = {}
        for finding in findings:
            match = re.match(r"^[^:]+:\d+: ([^:]+):", finding)
            ident = match.group(1) if match else "unknown"
            counts[ident] = counts.get(ident, 0) + 1
        summary = " ".join(f"{key}={counts[key]}" for key in sorted(counts))
        print(
            f"hardcode-inventory: audited scope={'+'.join(SCOPE)} "
            f"findings={len(findings)} {summary}".rstrip()
        )
        if args.inventory_verbose:
            for finding in findings:
                print(f"  {finding}")
        if args.inventory_baseline:
            baseline = load_inventory_snapshot(Path(args.inventory_baseline))
            added, removed = compare_inventory(findings, baseline)
            print(
                f"hardcode-inventory-baseline: added={len(added)} "
                f"cleared={removed} baseline={baseline.get('total', 'unknown')}"
            )
            if added:
                for record in sorted(
                    added, key=lambda item: (item["path"], item["rules"], item["fingerprint"])
                ):
                    print(
                        f"  NEW {record['path']} {record['rules']} "
                        f"fingerprint={record['fingerprint'][:16]}",
                        file=sys.stderr,
                    )
                return 1
        return 0

    base = resolve_base(args.base)
    patch = _git(
        "diff",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        f"{base}...HEAD",
        "--",
        *SCOPE,
    )
    findings = scan_patch(patch)
    if findings:
        print("hardcode-gate: FAIL", file=sys.stderr)
        for item in findings:
            print(f"  {item}", file=sys.stderr)
        print(
            f"Add `{REVIEW} issue=<n> source=<registered-id> reason=<why>` "
            "on the exact production line, or replace the hardcoded value with "
            "runtime discovery and admission.",
            file=sys.stderr,
        )
        return 1
    print(f"hardcode-gate: PASS base={base[:12]} scope={'+'.join(SCOPE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
