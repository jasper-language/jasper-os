# Persistent final performance summary

The benchmark progress stream previously reused framebuffer rows, so later
`progress=...` updates displaced completed metric results. This image retains
every final metric row in fixed test-report storage and redraws a complete
summary after the last million-sample batch finishes.

## Image

- Kernel SHA-256:
  `e6f5182af813696343679a16202dae57fa5ffb78431007e5bd59bad3b28974cd`
- Physical PXE download: `2026-11-24 14:09:53 Europe/Berlin`
- Target: `74:56:3c:ba:1f:c7`, `192.168.68.54`

## Final panel

The completed panel is titled `FINAL RESULTS - ALL MILLION-SAMPLE BATCHES` and
contains the retained kernel and user-space metrics with:

- sample count;
- P50;
- P99;
- P999;
- maximum;
- final failed/timing-failed/checks/resources-reclaimed status.

The running screen continues to display progress. Progress output no longer
destroys the retained result set.

## Verification state

OVMF reached BSP-only startup, clock calibration, and the first million-sample
metric on this exact image. Physical download was also observed. The physical
final panel cannot appear until the tick-driven million-sample interrupt test
finishes; at 100 Hz that phase requires approximately 10,000 seconds.

This directory is control-group evidence. It does not substitute for captured
physical AMD values.
