#!/usr/bin/env python3
"""Run the S-4 eight-vCPU KVM campaign and stop only between complete rounds."""

import argparse
import json
import os
import pathlib
import select
import socket
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("--seconds", type=float, default=300)
parser.add_argument("--out", required=True)
parser.add_argument("--image", required=True)
parser.add_argument("--cores", default="4-11")
args = parser.parse_args()
if args.seconds <= 0:
    raise SystemExit("seconds must be positive")

out = pathlib.Path(args.out).resolve()
out.mkdir(parents=True, exist_ok=False)
address = pathlib.Path("/tmp") / f"jasper-s4-{os.getpid()}.sock"
server = socket.socket(socket.AF_UNIX)
server.bind(str(address))
server.listen(1)
server.settimeout(120)
blank = out / "blank.img"
with blank.open("wb") as handle:
    handle.truncate(16 * 1024 * 1024)

cmd = [
    "taskset", "-c", args.cores,
    "qemu-system-x86_64",
    "-accel", "kvm", "-cpu", "host",
    "-drive", f"format=raw,file={pathlib.Path(args.image).resolve()}",
    "-device", "virtio-rng-pci",
    "-device", "virtio-net-pci,netdev=n0", "-netdev", "user,id=n0",
    "-device", "virtio-blk-pci,drive=d1",
    "-drive", f"if=none,id=d1,file={blank},format=raw",
    "-smp", "8", "-m", "256M", "-display", "none", "-monitor", "none",
    "-no-reboot", "-serial", f"unix:{address}",
    "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
]
state = {
    "pass": False,
    "requested_seconds": args.seconds,
    "cores": args.cores,
    "cmd": cmd,
    "phase": "booting",
    "start_utc": time.time(),
}


def save():
    tmp = out / "status.tmp"
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(out / "status.json")


ready = None
stop = None
progress = None
complete = False
terminal = False
pending = b""
connection = None
started = time.monotonic()
save()
with (out / "qemu-stderr.log").open("wb") as err, (out / "serial.log").open("wb") as log:
    proc = subprocess.Popen(cmd, stderr=err, stdout=err)
    state["pid"] = proc.pid
    save()
    try:
        connection, _ = server.accept()
        connection.setblocking(False)
        while True:
            now = time.monotonic()
            if ready is not None and stop is None and now - ready >= args.seconds:
                connection.sendall(b"S")
                stop = now
                state["phase"] = "stopping"
                save()
            if ready is None and now - started > 1200:
                raise RuntimeError("boot/ready timeout")
            if progress is not None and now - progress > 900:
                raise RuntimeError("workload progress timeout")
            if stop is not None and now - stop > 900:
                raise RuntimeError("graceful stop timeout")
            readable, _, _ = select.select([connection], [], [], 1)
            if readable:
                data = connection.recv(262144)
                if not data:
                    break
                log.write(data)
                log.flush()
                pending += data
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if b"[JSR-S4] ready cpus=8 " in line:
                        if ready is not None:
                            raise RuntimeError("unexpected second ready/reboot")
                        ready = progress = time.monotonic()
                        state.update(
                            phase="running",
                            ready_utc=time.time(),
                            deadline_utc=time.time() + args.seconds,
                        )
                    if b"[JSR-S4] progress " in line:
                        progress = time.monotonic()
                        state["latest_progress"] = line.decode(errors="replace").strip()
                        state["elapsed_seconds"] = progress - ready if ready else 0
                        os.fsync(log.fileno())
                        save()
                    if b"[JSR-S4] complete " in line:
                        complete = True
                        if stop is None:
                            raise RuntimeError("guest completed before host stop")
                    if b"[JSR-EXIT] success" in line or b"[JSR-EXIT] timing-only" in line:
                        terminal = True
                    if (
                        b"[JSR-EXIT] failure" in line
                        or b"[JSR-S4] failure" in line
                        or b"[JSR-PANIC]" in line
                    ):
                        raise RuntimeError("guest functional failure")
            if proc.poll() is not None and not readable:
                break
        rc = proc.wait(timeout=30)
        elapsed = time.monotonic() - ready if ready is not None else 0
        if not (
            rc in (33, 37)
            and complete
            and terminal
            and stop is not None
            and elapsed >= args.seconds
        ):
            raise RuntimeError(
                f"incomplete run rc={rc}, elapsed={elapsed}, "
                f"complete={complete}, terminal={terminal}"
            )
        state.update({"pass": True}, phase="complete", elapsed_seconds=elapsed, exit_code=rc)
    except BaseException as error:
        state.update(phase="failed", error=str(error))
        raise
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=15)
        log.flush()
        os.fsync(log.fileno())
        state["end_utc"] = time.time()
        save()
        if connection is not None:
            connection.close()
        server.close()
        address.unlink(missing_ok=True)
