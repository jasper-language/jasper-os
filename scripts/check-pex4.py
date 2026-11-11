#!/usr/bin/env python3
"""Validate PEX-4 source instrumentation and measured KVM evidence."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "selection-instrumentation",
    "candidate-density",
    "latency-tail",
    "capacity-saturation",
    "kvm-matrix",
}
DENSITIES = {"low": 1, "medium": 4, "high": 8}
VCUS = {1, 2, 4, 8}
DEFAULT_MATRIX = ROOT / "evidence/pex4-main-2548998-20261112-001800/pex4-matrix.json"


def fail(message: str) -> None:
    print(f"pex4: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "matrix", nargs="?", default=str(ROOT / "verification/pex4.toml")
    )
    parser.add_argument("--evidence", type=Path, default=DEFAULT_MATRIX)
    args = parser.parse_args()
    try:
        contract = tomllib.loads(Path(args.matrix).read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(str(exc))
    if contract.get("schema") != 1 or contract.get("stage") != "PEX-4":
        fail("bad schema/stage")
    items = contract.get("acceptance", [])
    seen = {item.get("id"): item for item in items if isinstance(item, dict)}
    if set(seen) != REQUIRED:
        fail(f"acceptance set mismatch: {sorted(set(seen) ^ REQUIRED)}")
    pending = {key for key, item in seen.items() if item.get("state") == "pending"}
    if contract.get("status") == "done" and pending:
        fail("done status with pending acceptance")

    scheduler = (ROOT / "kernel/src/sched/scheduler.rs").read_text()
    probe = (ROOT / "kernel/src/sched/pex4_probe.rs").read_text()
    demo = (ROOT / "kernel/src/pex4_demo.rs").read_text()
    script = (ROOT / "scripts/pex4-matrix.py").read_text()
    for source, anchors in (
        (scheduler, ("pex4_probe::record", "pex4_candidates")),
        (probe, ("pub fn copy_samples", "pub fn snapshot", "SAMPLES_PER_CPU")),
        (demo, ("capacity_workers", "candidate_density_permille", "p999_cycles")),
        (script, ('"capacity"', '"density_permille"', '"p999_ns"', "len(parsed) == len(DENSITIES)")),
    ):
        for anchor in anchors:
            if anchor not in source:
                fail(f"lost source anchor {anchor}")

    try:
        matrix = json.loads(args.evidence.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read evidence {args.evidence}: {exc}")
    coverage = matrix.get("coverage", {})
    if coverage.get("expected_runs") != 12 or coverage.get("completed_runs") != 12:
        fail("evidence does not contain 12 completed runs")
    if not coverage.get("complete") or set(coverage.get("vcpus", [])) != VCUS:
        fail("evidence vCPU coverage is incomplete")
    if coverage.get("host_cpus") != list(range(4, 12)):
        fail("evidence host CPU set is not 4-11")
    rows = matrix.get("rows", [])
    if len(rows) != 12 * len(DENSITIES):
        fail("evidence row count is not 36")
    groups: dict[tuple[int, str], int] = {}
    for row in rows:
        key = (row.get("vcpus"), row.get("density"))
        groups[key] = groups.get(key, 0) + 1
        capacity = row.get("capacity", 0)
        per_cpu = DENSITIES.get(row.get("density"))
        expected_tasks = (
            min(row["vcpus"] * per_cpu, capacity) if per_cpu is not None else -1
        )
        if (
            capacity != 63
            or row.get("tasks") != expected_tasks
            or row.get("per_cpu") != per_cpu
            or not row.get("complete")
            or row.get("dropped") != 0
            or row.get("picks", 0) <= 0
            or row.get("candidates", 0) <= 0
            or row.get("p50_ns", 0) <= 0
            or row.get("p99_ns", 0) < row.get("p50_ns", 0)
            or row.get("p999_ns", 0) < row.get("p99_ns", 0)
            or not 0 < row.get("density_permille", 0) <= 1000
        ):
            fail(f"invalid evidence row {key}")
    if set(groups) != {(vcpus, density) for vcpus in VCUS for density in DENSITIES}:
        fail("evidence group coverage mismatch")
    if any(count != 3 for count in groups.values()):
        fail("evidence does not contain three rounds per group")
    if not any(
        row.get("vcpus") == 8
        and row.get("density") == "high"
        and row.get("tasks") == 63
        for row in rows
    ):
        fail("8-vCPU high density did not saturate 63 workers")

    print(
        f"pex4: PASS [{contract.get('status')}] "
        f"passed={len(REQUIRED) - len(pending)} pending={len(pending)} rows={len(rows)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
