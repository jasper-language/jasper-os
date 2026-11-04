#!/usr/bin/env python3
# =============================================================================
# fs-stall-probe.py —— 验收期间记录文件系统卡顿（accept.sh 调用）
#
# 用法：fs-stall-probe.py <探针目录> <输出文件>
# 每秒在探针目录所在文件系统上做一次「写 + fsync」，耗时超过 1 秒就记一行
# （墙钟时间、耗时、当时的 loadavg 与 /proc/pressure/io）。QEMU 的串口写入与磁盘镜像读取都走这个文件系统，
# 用来判断 QEMU 撞时限或固件读盘超时是否与文件系统卡顿同时发生。没有超过 1 秒的卡顿时输出文件只有表头。
# =============================================================================
import os
import signal
import sys
import time

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
directory, out = sys.argv[1], sys.argv[2]
probe = os.path.join(directory, f".fs-stall-probe-{os.getpid()}")


def snapshot():
    with open("/proc/loadavg") as f:
        load = " ".join(f.read().split()[:3])
    try:
        with open("/proc/pressure/io") as f:
            pressure = f.readline().strip()
    except OSError:
        pressure = "-"
    return f"load={load} io=[{pressure}]"


try:
    with open(out, "w") as log:
        log.write("# 写 + fsync 超过 1 秒的记录\n")
        log.flush()
        while True:
            start = time.time()
            with open(probe, "w") as f:
                f.write("x")
                f.flush()
                os.fsync(f.fileno())
            cost = time.time() - start
            if cost > 1.0:
                stamp = time.strftime("%H:%M:%S", time.localtime(start))
                log.write(f"{stamp} {cost:.1f}s {snapshot()}\n")
                log.flush()
            time.sleep(1.0)
finally:
    try:
        os.unlink(probe)
    except OSError:
        pass
