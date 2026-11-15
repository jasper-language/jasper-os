#!/usr/bin/env python3
"""Block newly introduced unsourced hardware facts and capacity limits.

This is a review gate, not a claim that the existing Issue #33 inventory is
complete. It inspects production lines added by the current change and requires
an explicit ``JASPER-HARDCODE-REVIEW`` annotation for high-risk patterns.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ("kernel", "kernel-core")
ZERO_SHA = re.compile(r"^0+$")
REVIEW = "JASPER-HARDCODE-REVIEW:"


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


def _reviewed(line: str) -> bool:
    return REVIEW in line


def scan_patch(patch: str) -> list[str]:
    """Return one diagnostic per unsourced production line."""
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
            if path and not _excluded(path) and any(path.startswith(s + "/") for s in SCOPE):
                code = text.split("//", 1)[0]
                reasons = [rule for rule in RULES if rule.pattern.search(code)]
                if path and DISCOVERY_PATH.search(path) and UNWRAP_OR.search(code):
                    reasons.append(
                        Rule(
                            "HC-G7",
                            UNWRAP_OR,
                            "hidden fallback in a discovery or hardware path",
                        )
                    )
                if reasons and not _reviewed(text):
                    ids = ",".join(rule.ident for rule in reasons)
                    why = "; ".join(rule.reason for rule in reasons)
                    findings.append(f"{path}:{line_number}: {ids}: {why}: {text.strip()}")
            line_number += 1
        elif raw.startswith(" "):
            line_number += 1
    return findings


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
@@ -1,0 +1,6 @@
+const MAX_CPUS: usize = 32;
+let line = count.min(MAX_LINES);
+let verified = true;
+let name = entries.get(index).unwrap_or("none");
+const INPUT_CAPACITY: usize = 4096;
+const MAX_PROTOCOL: usize = 64; // JASPER-HARDCODE-REVIEW: issue=33 source=SPEC
"""
    found = scan_patch(patch)
    assert len(found) == 5, found
    assert any("HC-G1" in item for item in found)
    assert any("HC-G2" in item for item in found)
    assert any("HC-G7" in item for item in found)
    assert any("HC-G8" in item for item in found)
    assert not any(item.endswith("MAX_PROTOCOL: usize = 64;") for item in found)
    print("hardcode-gate: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
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
            f"Add `{REVIEW} issue=<n> source=<spec-or-runtime-fact> reason=<why>` "
            "on the exact production line, or replace the hardcoded value with "
            "runtime discovery and admission.",
            file=sys.stderr,
        )
        return 1
    print(f"hardcode-gate: PASS base={base[:12]} scope={'+'.join(SCOPE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
