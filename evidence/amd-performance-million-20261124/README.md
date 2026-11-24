# Million-sample AMD performance run

Status: deployed for physical AMD validation; no physical result is claimed yet.

## Image deployed to PXE

- Kernel SHA-256: `c4523830d7e347ead2a92125dfe71ce2ac04ca914b5570906bd4ad4ee18db952`
- Kernel size: 2,786,648 bytes
- Loader SHA-256: `2665fafee89a0e0bbfbb6e43f5d6aa45280b9346d5f9a6cb0235dac18c548b86`
- Loader size: 176,128 bytes
- Boot profile: `bench-head`
- Target: AMD x86_64 bare metal, Realtek PCIe GBE PXE
- QEMU is a control group only and is not physical-hardware evidence.

## Control-group result

OVMF/QEMU completed the PXE handoff and entered the kernel. The serial log
records:

- `DEVICES SKIP PROFILE`
- Headless Ready and Console/Terminal Ready
- Explicit skipped records for Shell, Remote, UI Services, Desktop and
  compatibility assembly
- CPU discovery/admission/online/participation as separate fields
- CPUID cache topology
- TSC source, invariant-TSC state, RDTSCP and timer resolution
- `jasper.hardware.v1`, `jasper.boot.v1` and `jasper.perf.v1` records
- A complete `timer.read_overhead` run with 1,000,000 one-operation samples
- Nanosecond output instead of integer-microsecond zero

The full matrix is intentionally long-running: the timer benchmark retains one
real sample per timer interrupt and uses the configured timer frequency. A
sample reduction must not be reported as a complete million-sample result.

## Physical acceptance required

The machine must PXE boot the deployed image. Acceptance requires the physical
serial/framebuffer output to be retained, including:

- CPU vendor/model and discovered/admitted/online/participating CPU counts
- whether execution is BSP-only or SMP
- real cache topology and timer calibration source
- all stage baselines and all million-sample metrics
- final `BENCH RESULT` with failure and timing-failure counts

QEMU serial evidence is under
`evidence/amd-performance-million-qemu-20261124-r3/serial.log`.
