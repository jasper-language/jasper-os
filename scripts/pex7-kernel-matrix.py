#!/usr/bin/env python3
"""Run and summarize the PEX-7 real-kernel frame matrix."""

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
SUMMARY = re.compile(
    r"\[JSR-PEX7\] summary vcpus=(?P<vcpus>\d+) workers=(?P<workers>\d+) "
    r"frames_per_worker=(?P<per_worker>\d+) contiguous_frames=(?P<contiguous>\d+) "
    r"alloc_samples=(?P<alloc_samples>\d+) free_samples=(?P<free_samples>\d+) "
    r"frames_before=(?P<frames_before>\d+) frames_after=(?P<frames_after>\d+) "
    r"alloc_p50_cycles=(?P<ap50>\d+) alloc_p99_cycles=(?P<ap99>\d+) "
    r"alloc_p999_cycles=(?P<ap999>\d+) alloc_max_cycles=(?P<amax>\d+) "
    r"alloc_p50_ns=(?P<ap50ns>\d+) alloc_p99_ns=(?P<ap99ns>\d+) "
    r"alloc_p999_ns=(?P<ap999ns>\d+) free_p50_cycles=(?P<fp50>\d+) "
    r"free_p99_cycles=(?P<fp99>\d+) free_p999_cycles=(?P<fp999>\d+) "
    r"free_max_cycles=(?P<fmax>\d+) free_p50_ns=(?P<fp50ns>\d+) "
    r"free_p99_ns=(?P<fp99ns>\d+) free_p999_ns=(?P<fp999ns>\d+) "
    r"contig_alloc_p99_ns=(?P<cap99ns>\d+) contig_free_p99_ns=(?P<cfp99ns>\d+) "
    r"pressure_admitted=(?P<pressure_admitted>\d+) "
    r"pressure_refused=(?P<pressure_refused>\d+) pressure_ok=(?P<pressure_ok>true|false) "
    r"bitmap_bits_per_frame=(?P<bits>\d+) candidate_cache_bytes=(?P<cache_bytes>\d+) "
    r"complete=(?P<complete>true|false) resources=(?P<resources>true|false) "
    r"failures=(?P<failures>\d+)"
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


def parse(serial: Path, vcpus: int, round_no: int) -> dict | None:
    text = serial.read_text(errors="replace")
    match = SUMMARY.search(text)
    if match is None:
        return None
    item = match.groupdict()
    return {
        "round": round_no,
        "vcpus": vcpus,
        **{
            key: int(item[key])
            for key in (
                "workers",
                "per_worker",
                "contiguous",
                "alloc_samples",
                "free_samples",
                "frames_before",
                "frames_after",
                "ap50",
                "ap99",
                "ap999",
                "amax",
                "ap50ns",
                "ap99ns",
                "ap999ns",
                "fp50",
                "fp99",
                "fp999",
                "fmax",
                "fp50ns",
                "fp99ns",
                "fp999ns",
                "cap99ns",
                "cfp99ns",
                "pressure_admitted",
                "pressure_refused",
                "bits",
                "cache_bytes",
                "failures",
            )
        },
        "pressure_ok": item["pressure_ok"] == "true",
        "complete": item["complete"] == "true",
        "resources": item["resources"] == "true",
    }


def aggregate(rows: list[dict]) -> list[dict]:
    result = []
    for vcpus in sorted({row["vcpus"] for row in rows}):
        selected = [row for row in rows if row["vcpus"] == vcpus]
        result.append(
            {
                "vcpus": vcpus,
                "rounds": len(selected),
                **{
                    key: statistics.median(row[key] for row in selected)
                    for key in (
                        "ap50ns",
                        "ap99ns",
                        "ap999ns",
                        "fp50ns",
                        "fp99ns",
                        "fp999ns",
                        "cap99ns",
                        "cfp99ns",
                        "cache_bytes",
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
        raise SystemExit(f"PEX-7: image is missing or empty: {image}")
    cpus = cpu_set(args.cpus)
    if cpus & {0, 1, 2, 3}:
        raise SystemExit("PEX-7: host CPUs 0-3 are forbidden")
    if qemu_pids():
        raise SystemExit("PEX-7: another QEMU is running")

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
                raise SystemExit("PEX-7: contaminated start")
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
            row = parse(prefix.with_suffix(".serial"), vcpus, round_no)
            if row is not None:
                rows.append(row)
            rc_match = re.search(r"\brc=(-?\d+)\b", result.stdout)
            qemu_rc = int(rc_match.group(1)) if rc_match else None
            valid = (
                qemu_rc == 33
                and row is not None
                and row["complete"]
                and row["resources"]
                and row["pressure_ok"]
                and row["workers"] == vcpus
                and row["alloc_samples"] == vcpus * row["per_worker"]
                and row["free_samples"] == vcpus * row["per_worker"]
                and row["failures"] == 0
                and not qemu_pids()
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
                f"PEX-7: vcpus={vcpus} round={round_no} rc={qemu_rc} valid={valid}",
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
    (out / "pex7-kernel-matrix.json").write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if coverage["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
