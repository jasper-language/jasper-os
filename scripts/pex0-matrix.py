#!/usr/bin/env python3
"""Run and summarize the PEX-0 KVM performance matrix."""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOT_TRACE = ROOT / "scripts" / "boot-trace.py"

FAILURE_MARKERS = (
    r"\[JSR-[A-Z0-9-]+-FAIL\]",
    r"\[JSR-BENCH-FAIL\]",
    r"\[JSR-RING-FAIL\]",
    r"\[JSR-SCALE-FAIL\]",
)

LOW_METRICS = {
    "kernel.timer_irq",
    "sched.context_switch",
    "frame.alloc",
    "frame.free",
    "heap.alloc_free_64",
    "heap.alloc_free_4096",
    "syscallset.contains.current",
    "syscallset.contains.u64-reference",
    "syscallset.subset.current",
    "syscallset.subset.u64-reference",
    "syscallset.copy.current",
    "syscallset.copy.u64-reference",
    "spawn.decode.current",
    "spawn.calls.decode.current",
    "spawn.calls.decode.u64-reference",
}
MEDIUM_METRICS = {
    "syscall.roundtrip",
    "ring.submit_complete",
    "ring.wait_complete",
    "ring.wait_cancel",
    "ipc.roundtrip",
}


def parse_cpu_set(text: str) -> set[int]:
    cpus: set[int] = set()
    for part in text.split(","):
        bounds = part.split("-", 1)
        if len(bounds) == 1:
            cpus.add(int(bounds[0]))
        else:
            start, end = map(int, bounds)
            if start > end:
                raise ValueError(f"invalid CPU range {part}")
            cpus.update(range(start, end + 1))
    return cpus


def host_sample(path: Path) -> dict:
    load = Path("/proc/loadavg").read_text().strip().split()
    result = {"loadavg": load[:3]}
    qemu = subprocess.run(
        ["pgrep", "-f", "[q]emu-system-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    result["qemu_pids"] = [int(x) for x in qemu.stdout.split()]
    result["lscpu"] = subprocess.run(
        ["lscpu"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    ).stdout.splitlines()
    result["uname"] = subprocess.run(
        ["uname", "-a"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    ).stdout.strip()
    result["qemu_version"] = subprocess.run(
        ["qemu-system-x86_64", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    ).stdout.splitlines()[:1]
    result["kvm_accessible"] = os.access("/dev/kvm", os.R_OK | os.W_OK)
    frequencies = {}
    for cpu in sorted(
        int(cpu_path.name[3:])
        for cpu_path in Path("/sys/devices/system/cpu").glob("cpu[0-9]*")
        if cpu_path.name[3:].isdigit()
    ):
        base = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
        frequencies[str(cpu)] = {
            "governor": (
                (base / "scaling_governor").read_text().strip()
                if (base / "scaling_governor").exists()
                else None
            ),
            "current_khz": (
                int((base / "scaling_cur_freq").read_text().strip())
                if (base / "scaling_cur_freq").exists()
                else None
            ),
        }
    result["cpu_frequency"] = frequencies
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


def cpu_busy(cpus: set[int]) -> float:
    def snapshot() -> dict[int, tuple[int, int]]:
        values: dict[int, tuple[int, int]] = {}
        for line in Path("/proc/stat").read_text().splitlines():
            if not line.startswith("cpu"):
                continue
            fields = line.split()
            if not fields[0][3:].isdigit():
                continue
            cpu = int(fields[0][3:])
            if cpu not in cpus:
                continue
            numbers = [int(x) for x in fields[1:]]
            idle = numbers[3] + (numbers[4] if len(numbers) > 4 else 0)
            values[cpu] = (sum(numbers), idle)
        return values

    before = snapshot()
    time.sleep(1.0)
    after = snapshot()
    busy = 0.0
    for cpu in cpus:
        total = after[cpu][0] - before[cpu][0]
        idle = after[cpu][1] - before[cpu][1]
        if total:
            busy = max(busy, 100.0 * (total - idle) / total)
    return busy


def wait_for_cpu_idle(
    cpus: set[int], max_busy_percent: float, wait_seconds: int
) -> float:
    deadline = time.monotonic() + wait_seconds
    while True:
        busy = cpu_busy(cpus)
        if busy <= max_busy_percent or time.monotonic() >= deadline:
            return busy
        time.sleep(2)


def parse_number(value: str) -> int | float:
    return float(value) if "." in value else int(value)


def parse_serial(path: Path, smp: int, round_no: int) -> list[dict]:
    text = path.read_text(errors="replace")
    rows: list[dict] = []

    bench = re.compile(
        r"\[JSR-BENCH\] name=(?P<name>\S+) iters=(?P<iters>\d+) "
        r"min=(?P<min>\d+) p50=(?P<p50>\d+) p99=(?P<p99>\d+) "
        r"p999=(?P<p999>\d+) max=(?P<max>\d+) mean=(?P<mean>\d+) "
        r"unit=cycles p50_ns=(?P<p50_ns>\d+) p99_ns=(?P<p99_ns>\d+) "
        r"p999_ns=(?P<p999_ns>\d+)"
    )
    user = re.compile(
        r"bench: name=(?P<name>\S+) iters=(?P<iters>\d+) "
        r"min=(?P<min>\d+) p50=(?P<p50>\d+) p99=(?P<p99>\d+) "
        r"p999=(?P<p999>\d+) max=(?P<max>\d+) mean=(?P<mean>\d+) "
        r"unit=cycles p50_ns=(?P<p50_ns>\d+) p99_ns=(?P<p99_ns>\d+) "
        r"p999_ns=(?P<p999_ns>\d+)"
    )
    for match in bench.finditer(text):
        item = match.groupdict()
        name = item["name"]
        workload = "low" if name in LOW_METRICS else "other"
        rows.append(
            {
                "round": round_no,
                "vcpus": smp,
                "workload": workload,
                "source": "kernel",
                "name": name,
                "samples": int(item["iters"]),
                "unit": "cycles",
                **{k: int(item[k]) for k in ("min", "p50", "p99", "p999", "max", "mean")},
                "p50_ns": int(item["p50_ns"]),
                "p99_ns": int(item["p99_ns"]),
                "p999_ns": int(item["p999_ns"]),
            }
        )
    for match in user.finditer(text):
        item = match.groupdict()
        name = item["name"]
        workload = "medium" if name in MEDIUM_METRICS else "other"
        rows.append(
            {
                "round": round_no,
                "vcpus": smp,
                "workload": workload,
                "source": "user",
                "name": name,
                "samples": int(item["iters"]),
                "unit": "cycles",
                **{k: int(item[k]) for k in ("min", "p50", "p99", "p999", "max", "mean")},
                "p50_ns": int(item["p50_ns"]),
                "p99_ns": int(item["p99_ns"]),
                "p999_ns": int(item["p999_ns"]),
            }
        )

    ring = re.search(
        r"\[JSR-RING-WAIT-SCALE\] rounds=(?P<rounds>\d+) batch=(?P<batch>\d+) "
        r"requests=(?P<requests>\d+) scan_slots=(?P<scan_slots>\d+) "
        r"heap_ops=(?P<heap_ops>\d+) cycle_p50=(?P<p50>\d+) cycle_p99=(?P<p99>\d+) "
        r"cycle_p999=(?P<p999>\d+) cycle_max=(?P<max>\d+) "
        r"sched_contended=(?P<sched_contended>\d+) "
        r"object_contended=(?P<object_contended>\d+) failed_ok=(?P<failed_ok>true|false)",
        text,
    )
    if ring:
        item = ring.groupdict()
        rows.append(
            {
                "round": round_no,
                "vcpus": smp,
                "workload": "medium",
                "source": "kernel",
                "name": "ring.wait_scale",
                "samples": int(item["rounds"]),
                "unit": "cycles",
                "p50": int(item["p50"]),
                "p99": int(item["p99"]),
                "p999": int(item["p999"]),
                "max": int(item["max"]),
                "batch": int(item["batch"]),
                "requests": int(item["requests"]),
                "scan_slots": int(item["scan_slots"]),
                "heap_ops": int(item["heap_ops"]),
                "scheduler_contended": int(item["sched_contended"]),
                "object_contended": int(item["object_contended"]),
                "valid": item["failed_ok"] == "true",
            }
        )

    ring_quota = re.search(
        r"\[JSR-RING\] quota rings=(?P<rings>\d+) ninth=Some\((?P<ninth>-?\d+)\) "
        r"in_flight=(?P<in_flight>\d+) over=Some\((?P<over>-?\d+)\) "
        r"unchanged_on_reject=(?P<unchanged>true|false) "
        r"returned=(?P<returned>true|false)",
        text,
    )
    if ring_quota:
        item = ring_quota.groupdict()
        rows.append(
            {
                "round": round_no,
                "vcpus": smp,
                "workload": "high",
                "source": "kernel",
                "name": "ring.quota_parallel_capacity",
                "samples": int(item["rings"]),
                "unit": "configuration",
                "rings": int(item["rings"]),
                "in_flight": int(item["in_flight"]),
                "unchanged_on_reject": item["unchanged"] == "true",
                "returned": item["returned"] == "true",
                "valid": item["unchanged"] == "true" and item["returned"] == "true",
            }
        )

    if re.search(r"\[JSR-RING\] transfer result=Ok\(Err\(Handle\(RightsDenied\)\)\)", text):
        rows.append(
            {
                "round": round_no,
                "vcpus": smp,
                "workload": "medium",
                "source": "kernel",
                "name": "ring.cross_process_transfer",
                "samples": 1,
                "unit": "contract",
                "valid": True,
            }
        )

    scale = re.search(
        r"\[JSR-SCALE\] case=overload cpus=(?P<cpus>\d+) "
        r"sleepers=(?P<sleepers>\d+) hogs=(?P<hogs>\d+) window=(?P<window>\d+) "
        r"interactive_rounds=(?P<interactive_rounds>\d+) samples=(?P<samples>\d+) "
        r"latency_max=(?P<latency_max>\d+) bound=(?P<bound>\d+) "
        r"bounded=(?P<bounded>true|false)",
        text,
    )
    if scale:
        item = scale.groupdict()
        rows.append(
            {
                "round": round_no,
                "vcpus": smp,
                "workload": "high",
                "source": "kernel",
                "name": "scheduler.overload",
                "samples": int(item["samples"]),
                "unit": "ticks",
                "p999": int(item["latency_max"]),
                "max": int(item["latency_max"]),
                "sleepers": int(item["sleepers"]),
                "hogs": int(item["hogs"]),
                "window": int(item["window"]),
                "bounded": item["bounded"] == "true",
            }
        )

    for marker in FAILURE_MARKERS:
        if re.search(marker, text):
            rows.append(
                {
                    "round": round_no,
                    "vcpus": smp,
                    "workload": "failure",
                    "source": "serial",
                    "name": "failure_marker",
                    "pattern": marker,
                    "valid": False,
                }
            )

    parallel = re.compile(
        r"\[JSR-PEX0-PAR\] density=(?P<density>low|medium|high) "
        r"vcpus=(?P<vcpus>\d+) processes=(?P<processes>\d+) rings=(?P<rings>\d+) "
        r"workers=(?P<workers>\d+) ops=(?P<ops>\d+) "
        r"window_cycles=(?P<window_cycles>\d+) window_ns=(?P<window_ns>\d+) "
        r"throughput_ops_s=(?P<throughput>\d+) per_cpu_ops_s=(?P<per_cpu>\d+) "
        r"p50=(?P<p50>\d+) p99=(?P<p99>\d+) p999=(?P<p999>\d+) max=(?P<max>\d+) "
        r"p50_ns=(?P<p50_ns>\d+) p99_ns=(?P<p99_ns>\d+) p999_ns=(?P<p999_ns>\d+) "
        r"sched_contended=(?P<sched_contended>\d+) sched_spins=(?P<sched_spins>\d+) "
        r"object_contended=(?P<object_contended>\d+) object_spins=(?P<object_spins>\d+) "
        r"complete=(?P<complete>true|false) resources=(?P<resources>true|false)"
    )
    for match in parallel.finditer(text):
        item = match.groupdict()
        row = {
            "round": round_no,
            "vcpus": smp,
            "workload": item["density"],
            "source": "kernel",
            "name": "ring.parallel_throughput",
            "samples": int(item["ops"]),
            "unit": "ops",
            "processes": int(item["processes"]),
            "rings": int(item["rings"]),
            "workers": int(item["workers"]),
            "window_cycles": int(item["window_cycles"]),
            "window_ns": int(item["window_ns"]),
            "throughput_ops_s": int(item["throughput"]),
            "per_cpu_ops_s": int(item["per_cpu"]),
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
                    "sched_contended",
                    "sched_spins",
                    "object_contended",
                    "object_spins",
                )
            },
            "valid": (
                item["complete"] == "true"
                and item["resources"] == "true"
                and int(item["workers"]) == int(item["rings"])
                and int(item["rings"]) == int(item["processes"]) * 2
            ),
        }
        rows.append(row)
    unique = []
    seen = set()
    for row in rows:
        key = json.dumps(row, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def load_resumed_run(
    prefix: Path, smp: int, round_no: int, prior: dict | None
) -> tuple[list[dict], dict] | None:
    """Load one already completed run without rerunning QEMU.

    Only a normal boot-trace exit with parsed workload metrics is reusable.
    This lets long matrices survive an execution session limit without
    discarding samples that already passed the contamination and resource
    gates.
    """
    if prior is None or prior.get("valid") is not True:
        return None
    result_path = prefix.with_suffix(".result")
    serial_path = prefix.with_suffix(".serial")
    if not result_path.is_file() or not serial_path.is_file():
        return None
    result = result_path.read_text(errors="replace")
    if "timed_out=0" not in result or not re.search(r"\brc=33\b", result):
        return None
    rows = parse_serial(serial_path, smp, round_no)
    if not rows or any(row["workload"] == "failure" for row in rows):
        return None
    rc_match = re.search(r"\brc=(-?\d+)\b", result)
    receipt = {
        "vcpus": smp,
        "round": round_no,
        "returncode": 0,
        "qemu_returncode": int(rc_match.group(1)) if rc_match else None,
        "boot_trace": result.strip(),
        "metrics": len(rows),
        "failure_markers": False,
        "busy_before_percent": prior.get("busy_before_percent"),
        "busy_after_percent": prior.get("busy_after_percent"),
        "qemu_after": prior.get("qemu_after", []),
        "resumed": True,
        "valid": True,
    }
    return rows, receipt


def median_summary(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[int, str, str], list[dict]] = {}
    for row in rows:
        if row["workload"] in {"low", "medium", "high"}:
            grouped.setdefault((row["vcpus"], row["workload"], row["name"]), []).append(row)
    summary = []
    for (vcpus, workload, name), values in sorted(grouped.items()):
        entry: dict = {
            "vcpus": vcpus,
            "workload": workload,
            "name": name,
            "rounds": len(values),
        }
        for key in (
            "p50",
            "p99",
            "p999",
            "max",
            "p50_ns",
            "p99_ns",
            "p999_ns",
            "throughput_ops_s",
            "per_cpu_ops_s",
            "sched_contended",
            "sched_spins",
            "object_contended",
            "object_spins",
        ):
            samples = [v[key] for v in values if key in v]
            if samples:
                entry[key] = statistics.median(samples)
        summary.append(entry)
    return summary


def latency_scaling(summary: list[dict]) -> list[dict]:
    baseline = {
        (row["workload"], row["name"]): row["p50"]
        for row in summary
        if row["vcpus"] == 1 and "p50" in row
    }
    scaling = []
    for row in summary:
        key = (row["workload"], row["name"])
        if row["vcpus"] == 1 or key not in baseline or "p50" not in row:
            continue
        base = baseline[key]
        speedup = base / row["p50"] if row["p50"] else None
        scaling.append(
            {
                "name": row["name"],
                "vcpus": row["vcpus"],
                "p50_1v": base,
                "p50_current": row["p50"],
                "relative_latency_speedup": speedup,
                "efficiency": speedup / row["vcpus"] if speedup is not None else None,
                "note": "Latency-derived only; not an independent throughput claim.",
            }
        )
    return scaling


def throughput_scaling(summary: list[dict]) -> list[dict]:
    baseline = {
        row["workload"]: row["throughput_ops_s"]
        for row in summary
        if row["vcpus"] == 1
        and row["name"] == "ring.parallel_throughput"
        and "throughput_ops_s" in row
    }
    scaling = []
    for row in summary:
        if (
            row["vcpus"] == 1
            or row["name"] != "ring.parallel_throughput"
            or row["workload"] not in baseline
            or "throughput_ops_s" not in row
        ):
            continue
        base = baseline[row["workload"]]
        speedup = row["throughput_ops_s"] / base if base else None
        scaling.append(
            {
                "density": row["workload"],
                "vcpus": row["vcpus"],
                "throughput_1v": base,
                "throughput_current": row["throughput_ops_s"],
                "speedup": speedup,
                "parallel_efficiency": speedup / row["vcpus"] if speedup is not None else None,
            }
        )
    return scaling


def write_markdown(path: Path, summary: list[dict], coverage: dict) -> None:
    lines = [
        "# PEX-0 KVM performance matrix",
        "",
        f"- 1/2/4/8 vCPU: `{coverage['vcpus']}`",
        f"- low workload: `{coverage['low']}`",
        f"- medium workload: `{coverage['medium']}`",
        f"- high workload: `{coverage['high']}`",
        f"- multi-ring capacity exercised: `{coverage['multi_ring']}`",
        f"- multi-process contract exercised: `{coverage['multi_process']}`",
        f"- parallel multi-ring throughput: `{coverage['parallel_ring_throughput']}`",
        f"- exclusive CPU set verified: `{coverage['measurement_exclusive']}`",
        f"- complete PEX-0 matrix: `{coverage['complete']}`",
        f"- valid: `{coverage['valid']}`",
        "",
        "| vCPU | workload | metric | rounds | throughput/s | per-CPU/s | p50 | p99 | p99.9 | max |",
        "| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary:
        def value(key: str) -> str:
            if key not in row:
                return "-"
            return f"{row[key]:.1f}" if isinstance(row[key], float) else str(row[key])

        lines.append(
            f"| {row['vcpus']} | {row['workload']} | {row['name']} | "
            f"{row['rounds']} | {value('throughput_ops_s')} | {value('per_cpu_ops_s')} | "
            f"{value('p50_ns')} | {value('p99_ns')} | {value('p999_ns')} | {value('max')} |"
        )
    lines.append("")
    lines.append("Values in `*_ns` columns are nanoseconds; missing rows remain explicit.")
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--smps", default="1,2,4,8")
    parser.add_argument("--cpus", default="4-11")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-busy-percent", type=float, default=5.0)
    parser.add_argument("--idle-wait-seconds", type=int, default=60)
    parser.add_argument("--allow-busy", action="store_true")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="reuse completed round result/serial files in --out",
    )
    args = parser.parse_args()

    image = Path(args.image).resolve()
    if not image.is_file() or image.stat().st_size == 0:
        raise SystemExit(f"PEX-0: image is missing or empty: {image}")
    cpus = parse_cpu_set(args.cpus)
    if cpus & {0, 1, 2, 3}:
        raise SystemExit("PEX-0: CPU 0-3 are forbidden")
    if not cpus:
        raise SystemExit("PEX-0: CPU set is empty")

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    sample = host_sample(out / "environment-before.json")
    if sample["qemu_pids"]:
        raise SystemExit(f"PEX-0: another QEMU is running: {sample['qemu_pids']}")
    observed_busy = (
        0.0
        if args.allow_busy
        else wait_for_cpu_idle(cpus, args.max_busy_percent, args.idle_wait_seconds)
    )
    if observed_busy > args.max_busy_percent:
        raise SystemExit(
            f"PEX-0: CPU set {sorted(cpus)} did not become idle "
            f"({observed_busy:.1f}% > {args.max_busy_percent:.1f}%)"
        )

    committed_rows: list[dict] = []
    run_receipts: list[dict] = []
    prior_receipts: dict[tuple[int, int], dict] = {}
    previous_matrix = out / "matrix.json"
    if args.resume and previous_matrix.is_file():
        try:
            previous = json.loads(previous_matrix.read_text(encoding="utf-8"))
            prior_receipts = {
                (int(run["vcpus"]), int(run["round"])): run
                for run in previous.get("runs", [])
            }
        except (OSError, ValueError, KeyError, TypeError):
            prior_receipts = {}
    resume_manifest = out / "resume-valid.json"
    if args.resume and resume_manifest.is_file():
        try:
            previous = json.loads(resume_manifest.read_text(encoding="utf-8"))
            for run in previous.get("runs", []):
                if run.get("valid") is True:
                    prior_receipts[(int(run["vcpus"]), int(run["round"]))] = run
        except (OSError, ValueError, KeyError, TypeError):
            pass
    smps = [int(x) for x in args.smps.split(",")]
    for smp in smps:
        for round_no in range(1, args.rounds + 1):
            prefix = out / f"smp{smp}-round{round_no}"
            if args.resume:
                resumed = load_resumed_run(
                    prefix,
                    smp,
                    round_no,
                    prior_receipts.get((smp, round_no)),
                )
                if resumed is not None:
                    rows, receipt = resumed
                    committed_rows.extend(rows)
                    run_receipts.append(receipt)
                    print(
                        f"PEX-0: vcpus={smp} round={round_no} resumed "
                        f"rc={receipt['qemu_returncode']} metrics={len(rows)}",
                        flush=True,
                    )
                    continue
            before = host_sample(Path(f"{prefix}.environment-before.json"))
            before_busy = (
                0.0
                if args.allow_busy
                else wait_for_cpu_idle(
                    cpus, args.max_busy_percent, args.idle_wait_seconds
                )
            )
            if before["qemu_pids"]:
                run_receipts.append(
                    {
                        "vcpus": smp,
                        "round": round_no,
                        "returncode": None,
                        "qemu_returncode": None,
                        "boot_trace": "",
                        "metrics": 0,
                        "failure_markers": True,
                        "busy_before_percent": before_busy,
                        "busy_after_percent": before_busy,
                        "contamination": "qemu",
                    }
                )
                print(
                    f"PEX-0: vcpus={smp} round={round_no} skipped: another QEMU is running",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            if before_busy > args.max_busy_percent and not args.allow_busy:
                run_receipts.append(
                    {
                        "vcpus": smp,
                        "round": round_no,
                        "returncode": None,
                        "qemu_returncode": None,
                        "boot_trace": "",
                        "metrics": 0,
                        "failure_markers": True,
                        "busy_before_percent": before_busy,
                        "busy_after_percent": before_busy,
                        "contamination": "cpu_busy",
                    }
                )
                print(
                    f"PEX-0: vcpus={smp} round={round_no} skipped: CPU busy "
                    f"{before_busy:.1f}%",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            cmd = [
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
                cmd,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            (prefix.with_suffix(".result")).write_text(result.stdout)
            rows = parse_serial(prefix.with_suffix(".serial"), smp, round_no)
            committed_rows.extend(rows)
            time.sleep(5)
            after = host_sample(Path(f"{prefix}.environment-after.json"))
            after_busy = (
                cpu_busy(cpus)
                if args.allow_busy
                else wait_for_cpu_idle(
                    cpus, args.max_busy_percent, args.idle_wait_seconds
                )
            )
            rc_match = re.search(r"\brc=(-?\d+)\b", result.stdout)
            qemu_returncode = int(rc_match.group(1)) if rc_match else None
            receipt = {
                "vcpus": smp,
                "round": round_no,
                "returncode": result.returncode,
                "qemu_returncode": qemu_returncode,
                "boot_trace": result.stdout.strip(),
                "metrics": len(rows),
                "failure_markers": any(r["workload"] == "failure" for r in rows),
                "busy_before_percent": before_busy,
                "busy_after_percent": after_busy,
                "qemu_after": after["qemu_pids"],
                "valid": (
                    (args.allow_busy or max(before_busy, after_busy) <= args.max_busy_percent)
                    and not after["qemu_pids"]
                    and not any(r["workload"] == "failure" for r in rows)
                    and len(rows) > 0
                ),
            }
            run_receipts.append(receipt)
            print(
                f"PEX-0: vcpus={smp} round={round_no} rc={qemu_returncode} "
                f"metrics={len(rows)}",
                flush=True,
            )

    summary = median_summary(committed_rows)
    scaling = latency_scaling(summary)
    parallel_scaling = throughput_scaling(summary)
    workloads = {row["workload"] for row in committed_rows}
    parallel_rows = [
        row for row in committed_rows if row["name"] == "ring.parallel_throughput"
    ]
    parallel_keys = {
        (row["vcpus"], row["round"], row["workload"])
        for row in parallel_rows
        if row.get("valid", False)
    }
    expected_parallel_keys = {
        (smp, round_no, density)
        for smp in smps
        for round_no in range(1, args.rounds + 1)
        for density in ("low", "medium", "high")
    }
    coverage = {
        "vcpus": sorted({row["vcpus"] for row in committed_rows}),
        "low": "low" in workloads,
        "medium": "medium" in workloads,
        "high": "high" in workloads,
        "multi_ring": any(row.get("rings", 0) >= 2 for row in parallel_rows),
        "multi_process": any(row.get("processes", 0) >= 2 for row in parallel_rows),
        "parallel_ring_throughput": parallel_keys == expected_parallel_keys,
        "measurement_exclusive": not args.allow_busy,
        "valid": all(
            not args.allow_busy
            and r["qemu_returncode"] in (33, 37)
            and not r["failure_markers"]
            and r["metrics"] > 0
            and r.get("valid", True)
            for r in run_receipts
        )
        and all(row.get("valid", True) for row in committed_rows),
        "cpu_set": args.cpus,
        "max_observed_busy_percent": observed_busy,
    }
    coverage["complete"] = (
        coverage["valid"]
        and coverage["vcpus"] == [1, 2, 4, 8]
        and coverage["low"]
        and coverage["medium"]
        and coverage["high"]
        and coverage["multi_ring"]
        and coverage["multi_process"]
        and coverage["parallel_ring_throughput"]
    )
    result = {
        "schema": 1,
        "milestone": "PEX-0",
        "commit": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        ).stdout.strip(),
        "dirty": bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            ).stdout.strip()
        ),
        "coverage": coverage,
        "runs": run_receipts,
        "metrics": committed_rows,
        "summary": summary,
        "scaling": scaling,
        "throughput_scaling": parallel_scaling,
    }
    (out / "matrix.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_markdown(out / "matrix.md", summary, coverage)
    host_sample(out / "environment-after.json")

    if not coverage["complete"]:
        print("PEX-0: incomplete matrix; inspect matrix.json", file=sys.stderr)
        return 1
    print(f"PEX-0: PASS evidence={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
