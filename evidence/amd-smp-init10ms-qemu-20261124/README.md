# INIT timing and four-CPU SMP control group

The previous AP bring-up used a 200 us INIT assert hold. QEMU accepted that
shortcut, but the physical Ryzen 5700X reset at INIT deassert. The x86
architectural INIT handshake requires a 10 ms assert interval before deassert
and the first SIPI.

## Fix

`kernel/src/arch/x86_64/apic.rs` now keeps INIT asserted for 10,000 us before
deassert. `smp-skip-init` remains diagnostic-only and is not part of this run.

## OVMF four-vCPU result

- Kernel SHA-256:
  `3310ff02bc5ee9403412a54bbf5b8c8ee47cfc12ee4851f26585b66d6e876366`
- APIC IDs 1, 2, and 3 each reached `RUST ENTRY`.
- `[JSR-SMP] start present=4 online=4 failed=0`.
- Full SMP checks completed: `online=4 checks=37 failed=0`.
- Single CPU: 1,000,000 scalar operations.
- All physical cores: 4 workers, 4,000,000 operations.
- All logical CPUs: 4 workers, 4,000,000 operations.

Raw serial: `serial.log`.

This is a QEMU/OVMF control result. Physical AMD SMP remains unverified until
the same sequence is observed on the Ryzen 5700X.
