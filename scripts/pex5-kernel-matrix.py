#!/usr/bin/env python3
"""Run and summarize the PEX-5 real-kernel growth matrix."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOT_TRACE = ROOT / "scripts" / "boot-trace.py"
GROWTH = re.compile(
    r"\[JSR-PEX5\] case=growth worker=(?P<worker>\d+) "
    r"request_bytes=(?P<request>\d+) grown_bytes=(?P<grown>\d+) "
    r"mapped_before=(?P<mapped_before>\d+) mapped_after=(?P<mapped_after>\d+) "
    r"duration_cycles=(?P<cycles>\d+) duration_ns=(?P<ns>\d+) "
    r"valid=(?P<valid>true|false)"
)
SUMMARY = re.compile(
    r"\[JSR-PEX5\] summary vcpus=(?P<vcpus>\d+) workers=(?P<workers>\d+) "
    r"cases=(?P<cases>\d+) initial_total=(?P<initial_total>\d+) "
    r"final_total=(?P<final_total>\d+) initial_free=(?P<initial_free>\d+) "
    r"final_free=(?P<final_free>\d+) initial_blocks=(?P<initial_blocks>\d+) "
    r"final_blocks=(?P<final_blocks>\d+) initial_mapped=(?P<initial_mapped>\d+) "
    r"final_mapped=(?P<final_mapped>\d+) mapped_growth=(?P<mapped_growth>\d+) "
    r"expected_growth=(?P<expected_growth>\d+) frames_before=(?P<frames_before>\d+) "
    r"frames_after=(?P<frames_after>\d+) mapped_pages=(?P<mapped_pages>\d+) "
    r"page_table_frames=(?P<page_table_frames>\d+) p50_cycles=(?P<p50>\d+) "
    r"p99_cycles=(?P<p99>\d+) p999_cycles=(?P<p999>\d+) max_cycles=(?P<max>\d+) "
    r"p50_ns=(?P<p50_ns>\d+) p99_ns=(?P<p99_ns>\d+) p999_ns=(?P<p999_ns>\d+) "
    r"complete=(?P<complete>true|false) resources=(?P<resources>true|false) "
    r"checks=(?P<checks>\d+) failed=(?P<failed>\d+)"
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


def parse(serial: Path, vcpus: int, round_no: int) -> tuple[list[dict], dict | None]:
    text = serial.read_text(errors="replace")
    cases = []
    for match in GROWTH.finditer(text):
        item = match.groupdict()
        cases.append(
            {
                "round": round_no,
                "vcpus": vcpus,
                "worker": int(item["worker"]),
                "request_bytes": int(item["request"]),
                "grown_bytes": int(item["grown"]),
                "mapped_before": int(item["mapped_before"]),
                "mapped_after": int(item["mapped_after"]),
                "duration_cycles": int(item["cycles"]),
                "duration_ns": int(item["ns"]),
                "valid": item["valid"] == "true",
            }
        )
    match = SUMMARY.search(text)
    summary = None
    if match:
        item = match.groupdict()
        summary = {
            "round": round_no,
            "vcpus": vcpus,
            **{
                key: int(item[key])
                for key in (
                    "workers",
                    "cases",
                    "initial_total",
                    "final_total",
                    "initial_free",
                    "final_free",
                    "initial_blocks",
                    "final_blocks",
                    "initial_mapped",
                    "final_mapped",
                    "mapped_growth",
                    "expected_growth",
                    "frames_before",
                    "frames_after",
                    "mapped_pages",
                    "page_table_frames",
                    "p50",
                    "p99",
                    "p999",
                    "max",
                    "p50_ns",
                    "p99_ns",
                    "p999_ns",
                    "checks",
                    "failed",
                )
            },
            "complete": item["complete"] == "true",
            "resources": item["resources"] == "true",
        }
    if re.search(r"\[JSR-PEX5-FAIL\]", text):
        cases.append(
            {
                "round": round_no,
                "vcpus": vcpus,
                "failure_marker": True,
                "valid": False,
            }
        )
    return cases, summary


def summarize(cases: list[dict], summaries: list[dict]) -> dict:
    groups: dict[tuple[int, int], list[int]] = {}
    for row in cases:
        if row.get("valid"):
            groups.setdefault((row["vcpus"], row["request_bytes"]), []).append(
                row["duration_ns"]
            )

    def nearest_rank(values: list[int], percentile: int) -> int:
        ordered = sorted(values)
        index = math.ceil(percentile * len(ordered) / 100) - 1
        return ordered[max(0, min(index, len(ordered) - 1))]

    latency = [
        {
            "vcpus": vcpus,
            "request_bytes": request,
            "samples": len(values),
            "p50_ns": statistics.median(values),
            "p99_ns": nearest_rank(values, 99),
            "max_ns": max(values),
        }
        for (vcpus, request), values in sorted(groups.items())
    ]
    overall = []
    for vcpus in sorted({row["vcpus"] for row in summaries}):
        selected = [row for row in summaries if row["vcpus"] == vcpus]
        overall.append(
            {
                "vcpus": vcpus,
                "rounds": len(selected),
                "p50_ns": statistics.median(row["p50_ns"] for row in selected),
                "p99_ns": statistics.median(row["p99_ns"] for row in selected),
                "p999_ns": statistics.median(row["p999_ns"] for row in selected),
                "max_cycles": statistics.median(row["max"] for row in selected),
                "page_table_frames": statistics.median(
                    row["page_table_frames"] for row in selected
                ),
            }
        )
    return {"by_request": latency, "overall": overall}


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
        raise SystemExit(f"PEX-5: image is missing or empty: {image}")
    cpus = cpu_set(args.cpus)
    if cpus & {0, 1, 2, 3}:
        raise SystemExit("PEX-5: host CPUs 0-3 are forbidden")
    if qemu_pids():
        raise SystemExit("PEX-5: another QEMU is running")

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = environment()
    (out / "environment.json").write_text(
        json.dumps(env, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    all_cases: list[dict] = []
    summaries: list[dict] = []
    runs = []
    for vcpus in map(int, args.smps.split(",")):
        for round_no in range(1, args.rounds + 1):
            prefix = out / f"smp{vcpus}-round{round_no}"
            if qemu_pids():
                raise SystemExit("PEX-5: contaminated start")
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
            cases, summary = parse(prefix.with_suffix(".serial"), vcpus, round_no)
            all_cases.extend(cases)
            if summary is not None:
                summaries.append(summary)
            rc_match = re.search(r"\brc=(-?\d+)\b", result.stdout)
            qemu_rc = int(rc_match.group(1)) if rc_match else None
            valid = (
                qemu_rc == 33
                and summary is not None
                and summary["complete"]
                and summary["resources"]
                and summary["workers"] == vcpus
                and summary["cases"] == vcpus * 5
                and not any(not row.get("valid", False) for row in cases)
                and not qemu_pids()
            )
            runs.append(
                {
                    "vcpus": vcpus,
                    "round": round_no,
                    "returncode": result.returncode,
                    "qemu_returncode": qemu_rc,
                    "valid": valid,
                    "cases": len(cases),
                    "trace": result.stdout.strip(),
                }
            )
            print(
                f"PEX-5: vcpus={vcpus} round={round_no} rc={qemu_rc} cases={len(cases)} valid={valid}",
                flush=True,
            )

    coverage = {
        "expected_runs": len(list(map(int, args.smps.split(",")))) * args.rounds,
        "completed_runs": sum(1 for run in runs if run["valid"]),
        "vcpus": sorted({run["vcpus"] for run in runs if run["valid"]}),
        "complete": all(run["valid"] for run in runs),
        "host_cpus": sorted(cpus),
    }
    matrix = {
        "environment": env,
        "coverage": coverage,
        "runs": runs,
        "cases": all_cases,
        "summaries": summaries,
        "latency": summarize(all_cases, summaries),
    }
    (out / "pex5-kernel-matrix.json").write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if coverage["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
