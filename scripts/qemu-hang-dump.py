#!/usr/bin/env python3
# =============================================================================
# qemu-hang-dump.py —— QEMU 撞时限前经 monitor 留下现场（accept.sh 调用）
#
# 用法：qemu-hang-dump.py <monitor 套接字> <等待秒数> <输出文件>
# 等到时限前的那一刻，取各 vCPU 的寄存器（隔 2 秒取两次，便于区分「卡在一处」与「很慢」）、
# 各 vCPU 当前栈顶 96 个字与本地中断控制器状态。QEMU 已退出（套接字连不上）就什么也不写。
# =============================================================================
import re
import socket
import sys
import time

path, delay, out = sys.argv[1], float(sys.argv[2]), sys.argv[3]


def command(sock, text):
    sock.sendall(text.encode() + b"\n")
    time.sleep(0.7)
    sock.settimeout(1.0)
    data = b""
    try:
        while True:
            part = sock.recv(65536)
            if not part:
                break
            data += part
    except socket.timeout:
        pass
    return data.decode(errors="replace")


time.sleep(delay)
try:
    mon = socket.socket(socket.AF_UNIX)
    mon.connect(path)
except OSError:
    sys.exit(0)
command(mon, "")
with open(out, "w") as f:
    f.write(command(mon, "info registers -a") + "\n")
    time.sleep(2)
    regs = command(mon, "info registers -a")
    f.write(regs + "\n")
    for cpu, rsp in enumerate(re.findall(r"[RE]SP=([0-9a-f]+)", regs)):
        command(mon, f"cpu {cpu}")
        f.write(f"== cpu {cpu} stack\n" + command(mon, f"x /96gx 0x{rsp}") + "\n")
        f.write(command(mon, "info lapic") + "\n")
