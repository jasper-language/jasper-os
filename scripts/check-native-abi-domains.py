#!/usr/bin/env python3
"""Audit legacy system.* operations against the approved ABI domain policy.

This check is deliberately an inventory and consistency gate. It does not
rename an operation, allocate an ID, or claim that a migration is complete.
"""

from __future__ import annotations

import argparse
import json
import tomllib
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "abi/system-ids.txt"
POLICY = ROOT / "verification/native-abi-domain-policy.toml"


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
    args = parser.parse_args()
    try:
        policy = tomllib.loads(POLICY.read_text(encoding="utf-8"))
        rows = load_rows()
        audit(policy, rows, quiet=args.json)
        if args.json:
            print(json.dumps([classify(row, policy) for row in rows], indent=2))
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as error:
        print(f"native-abi-domains: FAIL {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
