#!/usr/bin/env python3
# =============================================================================
# boot-trace.py —— 记录一次 x86_64 QEMU 启动的进度，用来判断撞时限是慢、卡住还是没进内核
#
# 用法：boot-trace.py --img <镜像> --out <前缀> [--timeout 秒] [--nice N] [--io-class 2|3]
#                     [--smp N] [--q35] [--stop-at-info] [--stop-at-lines N] [--stall-secs 秒] [--evict] [--keep-awake] [--icount N]
# QEMU 参数与 accept.sh 的 boot_qemu 一致。每 10 秒记一行 <前缀>.trace：
# 经过秒数、串口行数、loadavg、各线程累计 CPU 秒数。结束时向标准输出写一行汇总。
# --stop-at-info：串口出现 ^INFO : （已进内核）就结束，只测引导阶段。
# --stop-at-lines：串口到第 N 行就结束，只测启动的前段。
# --stall-secs：进内核后串口这么久没有新行，就取两次（相隔 5 秒）每个处理器的寄存器、栈顶与本地中断控制器写入 <前缀>.stall，继续运行。
# --icount：QEMU -icount shift=N,sleep=off：虚拟时钟按指令数走，每条指令 2^N 纳秒，N 越大相对指令的时钟中断越密（确定性地模拟 vCPU 很慢）。
# --evict：启动前把镜像移出页缓存，引导阶段的读盘必须真正到磁盘。
# 撞时限且没进内核时，从 monitor 取 CPU0 寄存器写入 <前缀>.regs。固件调试输出（端口 0x402）写入 <前缀>.bios。
# =============================================================================
import argparse
import os
import re
import socket
import subprocess
import tempfile
import time

ap = argparse.ArgumentParser()
ap.add_argument("--img", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--timeout", type=int, default=600)
ap.add_argument("--nice", type=int, default=19)
ap.add_argument("--io-class", type=int, default=3)
ap.add_argument("--smp", type=int, default=1)
ap.add_argument("--q35", action="store_true")
ap.add_argument("--stop-at-info", action="store_true")
ap.add_argument("--stop-at-lines", type=int, default=0)
ap.add_argument("--stall-secs", type=int, default=0)
ap.add_argument("--evict", action="store_true")
ap.add_argument("--keep-awake", action="store_true")
ap.add_argument("--icount", type=int)
ap.add_argument("--accel", default=os.environ.get("JASPER_ACCEL", "kvm"),
                choices=("kvm", "tcg"))
ap.add_argument("--cpus", default=os.environ.get("JASPER_CORES", ""))
ap.add_argument("--in-asm-log")
args = ap.parse_args()

TICK = os.sysconf("SC_CLK_TCK")


if args.accel == "kvm" and args.icount is not None:
    raise SystemExit("boot-trace: -icount is deterministic TCG-only; select --accel tcg explicitly")


def cpu_list(text):
    if not text:
        return list(range(os.cpu_count() or 0))
    cpus = []
    for part in text.split(","):
        bounds = part.split("-", 1)
        if len(bounds) == 1:
            cpus.append(int(bounds[0]))
        else:
            start, end = map(int, bounds)
            cpus.extend(range(start, end + 1))
    return cpus


def thread_cpu(pid):
    used = {}
    try:
        for tid in os.listdir(f"/proc/{pid}/task"):
            with open(f"/proc/{pid}/task/{tid}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            used[tid] = (int(fields[11]) + int(fields[12])) / TICK
    except OSError:
        pass
    return used


def monitor(sock_path, command):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    s.connect(sock_path)
    s.sendall(command.encode() + b"\n")
    data = b""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    s.close()
    return data.decode(errors="replace")


if args.evict:
    fd = os.open(args.img, os.O_RDONLY)
    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    os.close(fd)

spinners = []
if args.keep_awake:
    for cpu in cpu_list(args.cpus):
        spinners.append(subprocess.Popen(
            ["taskset", "-c", str(cpu), "chrt", "-i", "0", "sh", "-c", "while :; do :; done"]))

tmp = tempfile.mkdtemp(prefix="boot-trace-")
sock = f"{tmp}/mon.sock"
blank = f"{tmp}/blank.img"
with open(blank, "wb") as f:
    f.truncate(16 << 20)
serial_path = args.out + ".serial"
cmd = ["nice", "-n", str(args.nice), "ionice", "-c", str(args.io_class)]
if args.cpus:
    cmd += ["taskset", "-c", args.cpus]
cmd += ["qemu-system-x86_64", "-accel", args.accel]
if args.accel == "kvm":
    cmd += ["-cpu", "host"]
cmd += ["-drive", f"format=raw,file={args.img}",
       "-device", "virtio-rng-pci", "-device", "virtio-net-pci,netdev=n0", "-netdev", "user,id=n0",
       "-device", "virtio-blk-pci,drive=d1", "-drive", f"if=none,id=d1,file={blank},format=raw,discard=unmap",
       "-serial", "stdio", "-display", "none", "-monitor", f"unix:{sock},server,nowait", "-no-reboot",
       "-m", "256M", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-smp", str(args.smp),
       "-chardev", f"file,id=fw,path={args.out}.bios", "-device", "isa-debugcon,iobase=0x402,chardev=fw"]
if args.icount is not None:
    cmd += ["-icount", f"shift={args.icount},sleep=off"]
if args.q35:
    cmd += ["-M", "q35"]
if args.in_asm_log:
    if args.accel != "tcg":
        raise SystemExit("boot-trace: --in-asm-log requires TCG")
    cmd += ["-d", "in_asm", "-D", args.in_asm_log]

start = time.monotonic()
with open(serial_path, "wb") as serial:
    qemu = subprocess.Popen(cmd, stdout=serial, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
info_at = None
timed_out = False
regs = ""
with open(args.out + ".trace", "w") as trace, open(serial_path, "rb") as reader:
    lines = 0
    next_sample = start
    last_new = start
    max_gap = (0.0, 0)
    stall_dumped = False
    while qemu.poll() is None:
        now = time.monotonic()
        chunk = reader.read()
        if chunk.count(b"\n"):
            if info_at is not None and now - last_new > max_gap[0]:
                max_gap = (now - last_new, lines)
            lines += chunk.count(b"\n")
            last_new = now
        if args.stop_at_lines and lines >= args.stop_at_lines:
            qemu.terminate()
            break
        if args.stall_secs and info_at is not None and not stall_dumped and now - last_new >= args.stall_secs:
            stall_dumped = True
            try:
                with open(args.out + ".stall", "w") as f:
                    f.write(f"t={now - start:.0f} lines={lines} cpu={thread_cpu(qemu.pid)}\n")
                    for _ in range(2):
                        for c in range(args.smp):
                            f.write(monitor(sock, f"cpu {c}\ninfo registers\nx/48gx $rsp\ninfo lapic"))
                        time.sleep(5)
                    f.write(f"cpu={thread_cpu(qemu.pid)}\n")
            except OSError as e:
                print(f"stall dump failed: {e}", flush=True)
        if info_at is None and re.search(rb"(^|\n)INFO : ", chunk):
            info_at = now - start
            if args.stop_at_info:
                qemu.terminate()
                break
        if now >= next_sample:
            cpu = " ".join(f"{v:.0f}" for v in thread_cpu(qemu.pid).values())
            load = open("/proc/loadavg").read().split()[0]
            trace.write(f"{now - start:.0f} lines={lines} load={load} cpu=[{cpu}]\n")
            trace.flush()
            next_sample += 10
        if now - start >= args.timeout:
            timed_out = True
            if info_at is None:
                try:
                    regs = monitor(sock, "info registers")
                    with open(args.out + ".regs", "w") as f:
                        f.write(regs)
                except OSError as e:
                    regs = str(e)
            qemu.kill()
            break
        time.sleep(0.2)
    qemu.wait()
    lines += reader.read().count(b"\n")
    cpu_final = thread_cpu(qemu.pid)

for s in spinners:
    s.kill()
    s.wait()
os.unlink(blank)
if os.path.exists(sock):
    os.unlink(sock)
os.rmdir(tmp)

eip = re.search(r"EIP=(\w+)", regs)
hlt = re.search(r"HLT=(\d)", regs)
print(f"{os.path.basename(args.out)} rc={qemu.returncode} timed_out={int(timed_out)} "
      f"secs={time.monotonic() - start:.0f} info_at={'-' if info_at is None else f'{info_at:.1f}'} lines={lines} "
      f"max_gap={max_gap[0]:.0f}s@{max_gap[1]}{' STALL' if stall_dumped else ''}"
      f"{' eip=' + eip.group(1) if eip else ''}{' hlt=' + hlt.group(1) if hlt else ''}", flush=True)
