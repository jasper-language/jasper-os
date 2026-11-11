#!/usr/bin/env python3
"""Run and summarize the PEX-3 central-versus-sharded KVM matrix."""

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
PEX3 = re.compile(
    r"\[JSR-PEX3\] mode=(?P<mode>central|sharded) vcpus=(?P<vcpus>\d+) "
    r"workers=(?P<workers>\d+) shards=(?P<shards>\d+) ops=(?P<ops>\d+) "
    r"samples=(?P<samples>\d+) throughput_ops_s=(?P<throughput>\d+) "
    r"p50_cycles=(?P<p50>\d+) p99_cycles=(?P<p99>\d+) "
    r"p999_cycles=(?P<p999>\d+) max_cycles=(?P<max>\d+) "
    r"p50_ns=(?P<p50_ns>\d+) p99_ns=(?P<p99_ns>\d+) "
    r"p999_ns=(?P<p999_ns>\d+) lock_acquired=(?P<acquired>\d+) "
    r"lock_contended=(?P<contended>\d+) lock_spins=(?P<spins>\d+) "
    r"lock_max_spins=(?P<max_spins>\d+) live=(?P<live>\d+) "
    r"pending=(?P<pending>\d+) resources=(?P<resources>true|false) "
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
                raise ValueError(f"invalid CPU range: {part}")
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


def parse_rows(serial: Path, smp: int, round_no: int) -> list[dict]:
    text = serial.read_text(errors="replace")
    rows = []
    for match in PEX3.finditer(text):
        item = match.groupdict()
        rows.append(
            {
                "round": round_no,
                "vcpus": smp,
                "mode": item["mode"],
                "workers": int(item["workers"]),
                "shards": int(item["shards"]),
                "samples": int(item["samples"]),
                "ops": int(item["ops"]),
                "throughput_ops_s": int(item["throughput"]),
                **{
                    key: int(item[key])
                    for key in (
                        "p50",
                        "p99",
                        "p999",
                        "max",
                        "p50_ns",
                        "p99_ns",
                        "p999_ns",
                        "acquired",
                        "contended",
                        "spins",
                        "max_spins",
                        "live",
                        "pending",
                    )
                },
                "resources": item["resources"] == "true",
                "complete": item["complete"] == "true",
            }
        )
    if re.search(r"\[JSR-PEX3-FAIL\]", text):
        rows.append(
            {
                "round": round_no,
                "vcpus": smp,
                "mode": "failure",
                "failure_marker": True,
            }
        )
    return rows


def summarize(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[int, str], list[dict]] = {}
    for row in rows:
        if row.get("mode") in {"central", "sharded"}:
            groups.setdefault((row["vcpus"], row["mode"]), []).append(row)
    result = []
    for (vcpus, mode), values in sorted(groups.items()):
        row = {"vcpus": vcpus, "mode": mode, "rounds": len(values)}
        for key in (
            "throughput_ops_s",
            "p50",
            "p99",
            "p999",
            "max",
            "p50_ns",
            "p99_ns",
            "p999_ns",
            "contended",
            "spins",
            "max_spins",
        ):
            row[key] = statistics.median(value[key] for value in values)
        result.append(row)
    comparisons = []
    modes = {(row["vcpus"], row["mode"]): row for row in result}
    for vcpus in sorted({row["vcpus"] for row in result}):
        central = modes.get((vcpus, "central"))
        sharded = modes.get((vcpus, "sharded"))
        if central is None or sharded is None:
            continue
        comparisons.append(
            {
                "vcpus": vcpus,
                "p99_reduction_percent": (
                    100.0 * (central["p99"] - sharded["p99"]) / central["p99"]
                    if central["p99"]
                    else None
                ),
                "p999_reduction_percent": (
                    100.0 * (central["p999"] - sharded["p999"]) / central["p999"]
                    if central["p999"]
                    else None
                ),
                "throughput_ratio": (
                    sharded["throughput_ops_s"] / central["throughput_ops_s"]
                    if central["throughput_ops_s"]
                    else None
                ),
            }
        )
    return result, comparisons


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--cpus", default="4-11")
    parser.add_argument("--smps", default="2,4,8")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()

    image = Path(args.image).resolve()
    if not image.is_file() or image.stat().st_size == 0:
        raise SystemExit(f"PEX-3: image is missing or empty: {image}")
    cpus = cpu_set(args.cpus)
    if cpus & {0, 1, 2, 3}:
        raise SystemExit("PEX-3: host CPUs 0-3 are forbidden")
    if qemu_pids():
        raise SystemExit("PEX-3: another QEMU is running")

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = environment()
    (out / "environment.json").write_text(
        json.dumps(env, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    all_rows: list[dict] = []
    runs: list[dict] = []
    for smp in map(int, args.smps.split(",")):
        for round_no in range(1, args.rounds + 1):
            prefix = out / f"smp{smp}-round{round_no}"
            before = qemu_pids()
            if before:
                raise SystemExit(f"PEX-3: contaminated start, QEMU PIDs {before}")
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
                str(smp),
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
            rows = parse_rows(prefix.with_suffix(".serial"), smp, round_no)
            all_rows.extend(rows)
            rc_match = re.search(r"\brc=(-?\d+)\b", result.stdout)
            qemu_rc = int(rc_match.group(1)) if rc_match else None
            valid = (
                qemu_rc == 33
                and not any(row.get("failure_marker") for row in rows)
                and {
                    row.get("mode")
                    for row in rows
                    if row.get("mode") in {"central", "sharded"}
                }
                == {"central", "sharded"}
                and all(
                    row.get("complete") and row.get("resources")
                    for row in rows
                    if row.get("mode") in {"central", "sharded"}
                )
                and not qemu_pids()
            )
            runs.append(
                {
                    "vcpus": smp,
                    "round": round_no,
                    "returncode": result.returncode,
                    "qemu_returncode": qemu_rc,
                    "valid": valid,
                    "rows": len(rows),
                    "trace": result.stdout.strip(),
                }
            )
            print(
                f"PEX-3: vcpus={smp} round={round_no} rc={qemu_rc} rows={len(rows)} valid={valid}",
                flush=True,
            )

    summary, comparisons = summarize(all_rows)
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
        "rows": all_rows,
        "summary": summary,
        "comparisons": comparisons,
    }
    (out / "pex3-matrix.json").write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if coverage["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
