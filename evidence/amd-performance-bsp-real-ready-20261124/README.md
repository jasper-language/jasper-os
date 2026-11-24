# AMD BSP-only physical benchmark handoff

This image removes the SMP wait that blocked the previous physical benchmark
before measurement. It still performs full firmware CPU discovery, but admits
only the bootstrap processor for the benchmark run.

## Image

- Kernel SHA-256:
  `6a471f2b936afec5e9b49e68673c14250bbb2c504574d01b09490f3c7ca707ad`
- PXE/TFTP target: `74:56:3c:ba:1f:c7`, `192.168.68.54`
- Physical download: `2026-11-24 14:03:14 Europe/Berlin`
- No replacement PXE request was observed for more than 60 seconds after
  download, so the early SMP reset loop is not present in this boot.

## OVMF control group

The exact image reached:

```text
[JSR-SMP] forced=bsp_only present=2 online=1 source=acpi.madt
[JSR-BENCH] stage=calibration_begin timer_hz=100 target_ticks=1000
[JSR-BENCH] name=frame.alloc iters=1000000
[JSR-BENCH] name=frame.free iters=1000000
[JSR-BENCH] name=heap.alloc_free_64 iters=1000000
[JSR-BENCH] name=heap.alloc_free_4096 iters=1000000
```

Raw control serial is in `normal/serial.log`. These values are QEMU/TCG
evidence only and are not physical AMD measurements.

The fast metrics are intentionally reported before `kernel.timer_irq`. A
million tick-driven interrupt observations at 100 Hz require approximately
10,000 seconds (2 hours 46 minutes 40 seconds); the long-running metric cannot
block the usable results from the other million-sample measurements.

Physical values still require capture from the AMD framebuffer/screen; no
physical serial channel is currently available.
