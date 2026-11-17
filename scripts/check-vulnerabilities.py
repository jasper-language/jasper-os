#!/usr/bin/env python3
"""Validate LC-5 vulnerability response and backport evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "release" / "release-policy.toml"
PRODUCTION = ROOT / "release" / "vulnerabilities.toml"
EXAMPLE = ROOT / "release" / "vulnerabilities.example.toml"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    print(f"vulnerabilities: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def date(value: object, field: str) -> dt.date:
    if not isinstance(value, str):
        fail(f"{field} must be an ISO date")
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        fail(f"{field} must be an ISO date")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, default=PRODUCTION)
    args = parser.parse_args()
    try:
        policy = tomllib.loads(POLICY.read_text(encoding="utf-8"))
        ledger = tomllib.loads(args.file.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(str(error))
    if ledger.get("schema") != 1:
        fail("ledger schema must be 1")
    channels = {entry["name"]: entry for entry in policy["channel"]}
    cases = ledger.get("cases", [])
    if not isinstance(cases, list):
        fail("cases must be an array")
    seen: set[str] = set()
    for entry in cases:
        required = {
            "id",
            "severity",
            "discovered_at",
            "acknowledged_at",
            "fixed_at",
            "affected",
            "status",
            "mitigation",
            "backport",
        }
        if not isinstance(entry, dict) or set(entry) != required:
            fail("advisory field set is not recognized")
        case_id = entry["id"]
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            fail("advisory id must be non-empty and unique")
        seen.add(case_id)
        severity = entry["severity"]
        if severity not in {"critical", "high"}:
            fail(f"{case_id}: severity must be critical or high")
        discovered = date(entry["discovered_at"], f"{case_id}.discovered_at")
        acknowledged = date(entry["acknowledged_at"], f"{case_id}.acknowledged_at")
        fixed = date(entry["fixed_at"], f"{case_id}.fixed_at")
        if acknowledged < discovered or fixed < discovered:
            fail(f"{case_id}: response timeline runs backwards")
        if entry["status"] not in {"open", "mitigated", "backported"}:
            fail(f"{case_id}: unknown status")
        backports = entry["backport"]
        if not isinstance(backports, list):
            fail(f"{case_id}: backport must be an array")
        by_channel = {}
        for item in backports:
            if not isinstance(item, dict) or set(item) != {"channel", "release", "commit"}:
                fail(f"{case_id}: backport field set is not recognized")
            channel = item["channel"]
            if channel not in channels or channel in by_channel:
                fail(f"{case_id}: backport channel is unknown or duplicated")
            if not isinstance(item["release"], str) or not item["release"]:
                fail(f"{case_id}: backport release is empty")
            if not isinstance(item["commit"], str) or not COMMIT_RE.fullmatch(item["commit"]):
                fail(f"{case_id}: backport commit is invalid")
            by_channel[channel] = item
        if entry["status"] == "backported":
            if set(by_channel) != set(channels):
                fail(f"{case_id}: every release channel needs a backport")
            for channel, item in by_channel.items():
                channel_policy = channels[channel]
                fix_days = channel_policy["critical_fix_days"]
                if severity == "high":
                    fix_days = channel_policy["high_fix_days"]
                if fixed > discovered + dt.timedelta(days=fix_days):
                    fail(f"{case_id}: {channel} fix deadline exceeded")
                if acknowledged > discovered + dt.timedelta(
                    hours=channel_policy["security_response_hours"]
                ):
                    fail(f"{case_id}: {channel} response deadline exceeded")
    try:
        display = args.file.resolve().relative_to(ROOT)
    except ValueError:
        display = args.file
    print(
        f"vulnerabilities: PASS file={display} "
        f"cases={len(cases)} channels={','.join(sorted(channels))}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as error:
        fail(str(error))
