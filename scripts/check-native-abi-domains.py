#!/usr/bin/env python3
"""Audit legacy system.* operations against the approved ABI domain policy.

This check is deliberately an inventory and consistency gate. It does not
rename an operation, allocate an ID, or claim that a migration is complete.
"""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "abi/system-ids.txt"
POLICY = ROOT / "verification/native-abi-domain-policy.toml"
MATRIX = ROOT / "verification/native-abi-operation-matrix.tsv"
SOURCE_ROOTS = (
    "kernel",
    "kernel-core",
    "user",
    "compat-core",
    "compat-loader",
    "netd",
    "trust-service",
    "modules",
    "scripts",
)
SOURCE_SUFFIXES = {".c", ".h", ".md", ".py", ".rs", ".sh", ".toml"}
MATRIX_FIELDS = (
    "id",
    "legacy_name",
    "version",
    "side_effect",
    "decision",
    "proposed_domain",
    "target_name",
    "dispatch_symbol",
    "consumer_count",
    "consumer_paths",
    "error_candidates",
    "wire_review",
    "authorization_review",
    "evidence",
    "migration_status",
    "remaining_gate",
)


def starts(name: str, prefixes: list[str]) -> bool:
    return any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)


def classify(row: dict[str, object], policy: dict[str, object]) -> dict[str, object]:
    name = str(row["old_name"])
    op_id = int(row["id"])
    if op_id in set(policy["reserved_review_ids"]["ids"]):
        return {
            **row,
            "proposed_domain": "review",
            "target_name": "unresolved",
            "decision": "reserved-review",
        }
    if starts(name, policy["split_review_prefixes"]["names"]):
        return {
            **row,
            "proposed_domain": "kernel+service",
            "target_name": name.replace("system.", "kernel.", 1),
            "decision": "split-review",
        }
    if name in policy["service_exact"]["names"] or starts(
        name, policy["service_prefixes"]["names"]
    ):
        return {
            **row,
            "proposed_domain": "service",
            "target_name": name.replace("system.", "service.", 1),
            "decision": "migrate-service",
        }
    if starts(name, policy["kernel_prefixes"]["names"]):
        return {
            **row,
            "proposed_domain": "kernel",
            "target_name": name.replace("system.", "kernel.", 1),
            "decision": "retain-kernel",
        }
    raise ValueError(f"{name}: no domain classification")


def load_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(REGISTRY.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 6:
            raise ValueError(f"system-ids.txt:{line_number}: invalid record")
        if fields[1] != "op":
            continue
        rows.append(
            {
                "id": int(fields[0]),
                "old_name": fields[2],
                "version": int(fields[3]),
                "side_effect": fields[4],
                "registry_line": line_number,
            }
        )
    return rows


def load_errors() -> list[str]:
    errors: list[str] = []
    for line in REGISTRY.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) >= 6 and fields[1] == "error":
            errors.append(fields[2])
    return errors


def registry_symbol(name: str) -> str:
    return name.upper().replace(".", "_")


def source_texts() -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    for root_name in SOURCE_ROOTS:
        root = ROOT / root_name
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
                continue
            if path.name == "ids.rs" or path == MATRIX:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            texts.append((path.relative_to(ROOT).as_posix(), text))
    return texts


def operation_matrix(
    policy: dict[str, object],
    rows: list[dict[str, object]],
    errors: list[str],
) -> list[dict[str, str]]:
    texts = source_texts()
    dispatch_path = "kernel/src/syscall/mod.rs"
    dispatch_text = next((text for path, text in texts if path == dispatch_path), "")
    matrix: list[dict[str, str]] = []
    for row in rows:
        classified = classify(row, policy)
        name = str(row["old_name"])
        symbol = registry_symbol(name)
        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        consumers = [path for path, text in texts if pattern.search(text)]
        family = ".".join(name.split(".")[:2])
        candidates = sorted(
            {
                error
                for error in errors
                if error.startswith(family + ".") or error.startswith("system.error.")
            }
        )
        decision = str(classified["decision"])
        if name == "system.info.get":
            migration_status = "service-runtime-deployed;legacy-retained"
            evidence = (
                "kernel-core/src/service_info.rs;user/infod/src/main.rs;"
                "user/infoprobe/src/main.rs;evidence/issue60-service-info-20261124-r8"
            )
        else:
            migration_status = "classification-only"
            evidence = ";".join(consumers)
        remaining = {
            "migrate-service": (
                "deployed service replacement, every caller migration, wire snapshot, "
                "authorization and failure/recovery evidence"
            ),
            "split-review": (
                "explicit kernel enforcement versus service-management split, caller "
                "migration, wire snapshot and security-boundary evidence"
            ),
            "reserved-review": (
                "retain the reservation until a concrete consumer and enforcing "
                "primitive exist"
            ),
            "retain-kernel": (
                "confirm every consumer uses the kernel enforcement boundary and record "
                "authorization/error/wire evidence"
            ),
        }[decision]
        matrix.append(
            {
                "id": str(row["id"]),
                "legacy_name": name,
                "version": str(row["version"]),
                "side_effect": str(row["side_effect"]),
                "decision": decision,
                "proposed_domain": str(classified["proposed_domain"]),
                "target_name": str(classified["target_name"]),
                "dispatch_symbol": "yes" if pattern.search(dispatch_text) else "no",
                "consumer_count": str(len(consumers)),
                "consumer_paths": ";".join(consumers),
                "error_candidates": ";".join(candidates),
                "wire_review": "legacy-register-layout;op-specific-review-required",
                "authorization_review": "PEP-and-consumer-authorization-review-required",
                "evidence": evidence,
                "migration_status": migration_status,
                "remaining_gate": remaining,
            }
        )
    return matrix


def render_matrix(matrix: list[dict[str, str]]) -> str:
    lines = ["\t".join(MATRIX_FIELDS)]
    for row in matrix:
        lines.append("\t".join(row[field] for field in MATRIX_FIELDS))
    return "\n".join(lines) + "\n"


def check_matrix(expected: str) -> None:
    try:
        actual = MATRIX.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ValueError(f"operation matrix is missing: {error}") from error
    if actual != expected:
        raise ValueError(
            "operation matrix is stale; run "
            "`python3 scripts/check-native-abi-domains.py --write-matrix`"
        )


def audit(
    policy: dict[str, object], rows: list[dict[str, object]], *, quiet: bool = False
) -> None:
    ids = [int(row["id"]) for row in rows]
    names = [str(row["old_name"]) for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate operation ID")
    if len(names) != len(set(names)):
        raise ValueError("duplicate operation name")
    if len(rows) != 109:
        raise ValueError(f"expected 109 legacy operations, found {len(rows)}")
    reserved = set(policy["reserved_review_ids"]["ids"])
    if reserved != {37, 38, 39, 40, 42}:
        raise ValueError("reserved review set changed without an explicit policy update")
    classified = [classify(row, policy) for row in rows]
    for row in classified:
        target = str(row["target_name"])
        if target != "unresolved" and target.startswith(("system.", "extension.")):
            raise ValueError(f"{row['old_name']}: retired target namespace")
    counts = Counter(str(row["decision"]) for row in classified)
    if not quiet:
        print(
            "native-abi-domains: PASS "
            f"ops={len(classified)} "
            + " ".join(f"{key}={counts[key]}" for key in sorted(counts))
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="print the audit rows")
    parser.add_argument(
        "--write-matrix",
        action="store_true",
        help="regenerate the per-operation audit matrix",
    )
    parser.add_argument(
        "--check-matrix",
        action="store_true",
        help="verify the checked-in per-operation matrix is current",
    )
    args = parser.parse_args()
    try:
        policy = tomllib.loads(POLICY.read_text(encoding="utf-8"))
        rows = load_rows()
        matrix = operation_matrix(policy, rows, load_errors())
        rendered = render_matrix(matrix)
        if args.write_matrix:
            MATRIX.write_text(rendered, encoding="utf-8")
        elif not args.json:
            check_matrix(rendered)
        audit(policy, rows, quiet=args.json)
        if args.json:
            print(json.dumps([classify(row, policy) for row in rows], indent=2))
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as error:
        print(f"native-abi-domains: FAIL {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
