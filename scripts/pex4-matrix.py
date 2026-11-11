#!/usr/bin/env python3
"""Run and summarize the PEX-4 local selection-path matrix."""

from __future__ import annotations

import argparse
import json
import re
import statistics
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOT_TRACE = ROOT / "scripts" / "boot-trace.py"
DENSITIES = {"low": 1, "medium": 4, "high": 8}
ROW = re.compile(
    r"\[JSR-PEX4\] density=(?P<density>low|medium|high) vcpus=(?P<vcpus>\d+) "
    r"tasks=(?P<tasks>\d+) capacity_workers=(?P<capacity>\d+) "
    r"tasks_per_cpu=(?P<per_cpu>\d+) yields=(?P<yields>\d+) "
    r"switches=(?P<switches>\d+) picks=(?P<picks>\d+) visited=(?P<visited>\d+) "
    r"candidates=(?P<candidates>\d+) avg_visited_permille=(?P<avg_visited>\d+) "
    r"candidate_density_permille=(?P<density_permille>\d+) "
    r"max_visited=(?P<max_visited>\d+) max_candidates=(?P<max_candidates>\d+) "
    r"samples=(?P<samples>\d+) dropped=(?P<dropped>\d+) "
    r"p50_cycles=(?P<p50>\d+) p99_cycles=(?P<p99>\d+) "
    r"p999_cycles=(?P<p999>\d+) max_cycles=(?P<max>\d+) "
    r"p50_ns=(?P<p50_ns>\d+) p99_ns=(?P<p99_ns>\d+) p999_ns=(?P<p999_ns>\d+) "
    r"complete=(?P<complete>true|false)"
)


def cpu_set(text: str) -> set[int]:
    result: set[int] = set()
    for part in text.split(","):
        values = part.split("-", 1)
        if len(values) == 1:
            result.add(int(values[0]))
        else:
            start, end = map(int, values)
            if start > end:
                raise ValueError(part)
            result.update(range(start, end + 1))
    return result


def qemu_pids() -> list[int]:
    result = subprocess.run(
        ["pgrep", "-f", "[q]emu-system-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return [int(value) for value in result.stdout.split()]


def environment() -> dict:
    return {
        "commit": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.strip(),
        "uname": subprocess.run(
            ["uname", "-a"],
            stdout=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.strip(),
        "lscpu": subprocess.run(
            ["lscpu"],
            stdout=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.splitlines(),
        "qemu_version": subprocess.run(
            ["qemu-system-x86_64", "--version"],
            stdout=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.splitlines()[:1],
    }


def parse(serial: Path, vcpus: int, round_no: int) -> list[dict]:
    rows = []
    for match in ROW.finditer(serial.read_text(errors="replace")):
        item = match.groupdict()
        rows.append(
            {
                "round": round_no,
                "vcpus": vcpus,
                "density": item["density"],
                **{
                    key: int(item[key])
                    for key in (
                        "tasks",
                        "capacity",
                        "per_cpu",
                        "yields",
                        "switches",
                        "picks",
                        "visited",
                        "candidates",
                        "avg_visited",
                        "density_permille",
                        "max_visited",
                        "max_candidates",
                        "samples",
                        "dropped",
                        "p50",
                        "p99",
                        "p999",
                        "max",
                        "p50_ns",
                        "p99_ns",
                        "p999_ns",
                    )
                },
                "complete": item["complete"] == "true",
            }
        )
    return rows


def aggregate(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[int, str], list[dict]] = {}
    for row in rows:
        groups.setdefault((row["vcpus"], row["density"]), []).append(row)
    result = []
    for (vcpus, density), values in sorted(groups.items()):
        result.append(
            {
                "vcpus": vcpus,
                "density": density,
                "rounds": len(values),
                **{
                    key: statistics.median(row[key] for row in values)
                    for key in (
                        "tasks",
                        "capacity",
                        "picks",
                        "visited",
                        "candidates",
                        "avg_visited",
                        "density_permille",
                        "max_visited",
                        "max_candidates",
                        "p50_ns",
                        "p99_ns",
                        "p999_ns",
                    )
                },
            }
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--cpus", default="4-11")
    parser.add_argument("--smps", default="1,2,4,8")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()

    image = Path(args.image).resolve()
    if not image.is_file() or image.stat().st_size == 0:
        raise SystemExit(f"PEX-4: image is missing or empty: {image}")
    cpus = cpu_set(args.cpus)
    if cpus & {0, 1, 2, 3}:
        raise SystemExit("PEX-4: host CPUs 0-3 are forbidden")
    if qemu_pids():
        raise SystemExit("PEX-4: another QEMU is running")

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = environment()
    (out / "environment.json").write_text(
        json.dumps(env, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    rows = []
    runs = []
    smps = list(map(int, args.smps.split(",")))
    for vcpus in smps:
        for round_no in range(1, args.rounds + 1):
            prefix = out / f"smp{vcpus}-round{round_no}"
            if qemu_pids():
                raise SystemExit("PEX-4: contaminated start")
            command = [
                sys.executable,
                str(BOOT_TRACE),
                "--img",
                str(image),
                "--out",
                str(prefix),
                "--timeout",
                str(args.timeout),
                "--nice",
                "5",
                "--io-class",
                "2",
                "--smp",
                str(vcpus),
                "--accel",
                "kvm",
                "--cpus",
                args.cpus,
            ]
            result = subprocess.run(
                command,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            prefix.with_suffix(".result").write_text(result.stdout, encoding="utf-8")
            parsed = parse(prefix.with_suffix(".serial"), vcpus, round_no)
            rows.extend(parsed)
            rc_match = re.search(r"\brc=(-?\d+)\b", result.stdout)
            qemu_rc = int(rc_match.group(1)) if rc_match else None
            by_density = {row["density"]: row for row in parsed}
            capacities = {row["capacity"] for row in parsed}
            capacity = next(iter(capacities)) if len(capacities) == 1 else 0
            valid = (
                qemu_rc == 33
                and set(by_density) == set(DENSITIES)
                and len(parsed) == len(DENSITIES)
                and capacity > 0
                and not qemu_pids()
                and all(
                    row["complete"]
                    and row["dropped"] == 0
                    and row["tasks"]
                    == min(vcpus * DENSITIES[row["density"]], capacity)
                    and row["per_cpu"] == DENSITIES[row["density"]]
                    and row["picks"] > 0
                    and row["candidates"] > 0
                    for row in parsed
                )
            )
            runs.append(
                {
                    "vcpus": vcpus,
                    "round": round_no,
                    "returncode": result.returncode,
                    "qemu_returncode": qemu_rc,
                    "valid": valid,
                    "trace": result.stdout.strip(),
                }
            )
            print(
                f"PEX-4: vcpus={vcpus} round={round_no} rc={qemu_rc} valid={valid}",
                flush=True,
            )

    coverage = {
        "expected_runs": len(smps) * args.rounds,
        "completed_runs": sum(1 for run in runs if run["valid"]),
        "vcpus": sorted({run["vcpus"] for run in runs if run["valid"]}),
        "complete": all(run["valid"] for run in runs),
        "host_cpus": sorted(cpus),
    }
    matrix = {
        "environment": env,
        "coverage": coverage,
        "runs": runs,
        "rows": rows,
        "summary": aggregate(rows),
    }
    (out / "pex4-matrix.json").write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if coverage["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
