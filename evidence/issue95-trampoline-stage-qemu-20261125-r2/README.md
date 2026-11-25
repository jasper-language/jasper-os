# Issue 95 first BSP yield trampoline control

Date: 2026-11-25.

Configuration:

- QEMU/TCG, q35, 512 MiB, 16 vCPUs.
- `smp-matrix-only,bench-exit,bench-switch-diagnostic`.
- `smp-force-x2apic`.
- 16 online logical CPUs, matching the diagnostic topology requested for the
  physical Ryzen 7 5700X.

## Confirmed result

The selected BSP worker reached both the trampoline dispatch boundary and its
actual Rust entry:

```text
T17.1 irq=false preemption=true
T17.4 before current_entry
T17.5 global scheduler lock wait
T17.5 global scheduler lock acquired
T17.6 current_entry returned some
[JSR-TRAMPOLINE] cpu=0 slot=1 generation=Some(1) task=12000 state=Some(Running) on_cpu=Some(0) percpu_current=1 entry=true
T17.2 before irq_enable
I01 high-resolution timer interrupt enter
T17.3 after irq_enable irq=true
T18 worker entry
[JSR-SMP-SW] stage=general_worker_start cpu=0 slot=1 ...
```

The first control run before this change showed the complete scheduler lookup
occurring only after interrupts were re-enabled. The new order resolves the
worker entry while the first switch still masks interrupts, then enables
interrupts at the entry boundary.

Three high-resolution timer transactions are still observable after
`T17.2`/`irq_enable` and before `T17.3`. They are real production timer
transactions, not injected test events. In this QEMU control they did not
prevent `T18` or the worker body from running.

## Evidence boundary

This directory proves the QEMU control reached the worker body. It does not
prove the physical AMD machine or the full 16-thread benchmark completed.
The 16-vCPU TCG stress control later stalled at per-CPU sample 800 before the
formal completion summary and was terminated after collecting the first-yield
stage evidence above. Physical validation remains required.

Kernel ELF used by this control:

```text
57de75a2b11f86c55d3b4aa2df702f2c09ed4c8e0b2f9112ab0df0757f91b3db
```
