#!/usr/bin/env python3
"""Guard Issue #15: verify/* pull requests must run both real CI jobs.

GitHub sets ``github.ref`` to ``refs/pull/<number>/merge`` for pull request
events.  A private ``verify/*`` branch gate must also inspect
``github.head_ref``; checking only the ref made both jobs skip and report an
empty success.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
JOBS = ("host", "accept")
REQUIRED = (
    "github.event_name == 'pull_request'",
    "startsWith(github.head_ref, 'verify/')",
    "startsWith(github.ref, 'refs/heads/verify/')",
)


def job_block(text: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
    )
    if match is None:
        raise ValueError(f"CI workflow is missing the {name} job")
    return match.group("body")


def job_condition(text: str, name: str) -> str:
    match = re.search(r"(?ms)^    if: >-\n(?P<condition>(?:      .*\n)+)", job_block(text, name))
    if match is None:
        raise ValueError(f"{name} job must use a folded if expression")
    return " ".join(line.strip() for line in match.group("condition").splitlines())


def audit(text: str) -> None:
    for job in JOBS:
        condition = job_condition(text, job)
        for fragment in REQUIRED:
            if fragment not in condition:
                raise ValueError(f"{job} job condition omits {fragment!r}")


def self_test() -> None:
    condition = "\n".join(f"      {line}" for line in REQUIRED)
    good = (
        "jobs:\n"
        "  host:\n"
        "    if: >-\n"
        f"{condition}\n"
        "    runs-on: ubuntu-24.04\n"
        "  accept:\n"
        "    if: >-\n"
        f"{condition}\n"
        "    runs-on: ubuntu-24.04\n"
    )
    audit(good)

    for job in JOBS:
        broken = good.replace(
            f"  {job}:\n    if: >-\n{condition}",
            f"  {job}:\n    if: >-\n" + condition.replace(
                "startsWith(github.head_ref, 'verify/')", "false"
            ),
            1,
        )
        try:
            audit(broken)
        except ValueError:
            pass
        else:
            raise AssertionError(f"self-test accepted a {job} gate without github.head_ref")


def main() -> int:
    try:
        if "--self-test" in sys.argv[1:]:
            self_test()
            print("ci-private-pr-gate: self-test PASS")
        audit(WORKFLOW.read_text(encoding="utf-8"))
        print("ci-private-pr-gate: PASS host+accept use pull_request head_ref and verify push ref")
    except (OSError, ValueError, AssertionError) as error:
        print(f"ci-private-pr-gate: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
