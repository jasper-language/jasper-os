# Issue #47: lock diagnostics and runtime-capacity reporting

更新时间：2026-11-20。

状态：**software slice passed**。该切片移除锁统计中的永久 128-CPU 数组上限，
并纠正启动报告把 bootstrap 槽位误报为实际 CPU 数量的问题；不代表
`CPU-DYNAMIC-CONSUMERS-1` 或 Issue #47 全部完成。

## 实现

- `kernel-core::sync::CpuAtomicCounter` 封装 bootstrap 区内每 CPU 原子计数和统一
  overflow 原子计数；CPU 2/129 的宿主测试验证超出 bootstrap 后计数不回绕到
  CPU 0。
- `IrqSpinLock` 的 acquisition 诊断使用该计数器；CPU 下标超出 bootstrap 区时不再
  越界访问或别名 CPU 0。
- scheduler 的 `timer_progress` 从 bootstrap-only `MAX_CPUS` 数组迁移为
  bootstrap 区加 AP 启动前预留的 heap tail；CPU 129 的计时准入和退出统计不再
  越界，预留失败会在 secondary CPU 启动前失败关闭。
- CPU 129 及以后不再越界访问、停机或别名 CPU 0 的计数；`LockStats.acquired`
  汇总 bootstrap 计数与 overflow 计数。
- 正常 bootstrap 范围内的锁热路径仍使用本 CPU 独立原子计数，不引入额外共享
  cache line RMW；只有超出 bootstrap 区的诊断计数使用 overflow 原子。
- `[JSR-CAP]` 启动报告的 `cpus=` 改为 `cpu_bootstrap_slots=`，不再把
  `MAX_CPUS`/128 冒充实际硬件或最终逻辑 CPU 数。
- 拓扑准入失败日志从错误的 `cpu_set_capacity` 改为
  `topology_inventory_incomplete`；动态 CPU 拓扑不再报告一个虚假的固定容量。

## 验证

```text
cargo check -p jasper-kernel --target x86_64-unknown-none
PASS

cargo check -p jasper-kernel --target x86_64-unknown-none --no-default-features
PASS

cargo check -p jasper-kernel --target aarch64-unknown-none
PASS

cargo check -p jasper-kernel --target riscv64gc-unknown-none-elf
PASS

cargo check -p kernel-core --target loongarch64-unknown-none-softfloat \
  --features cpu-dynamic
PASS

cargo test -p kernel-core sync --lib
27 passed; 0 failed

python3 scripts/check-hardcode-gate.py --base HEAD
PASS

python3 scripts/check-hardcode-gate.py --inventory \
  --inventory-baseline docs/hardcode-inventory-baseline.json
findings=278; added=0; cleared=0
```

## IRQ detach handoff slice

`irq::device::detach_cpu_lines(cpu)` now performs the line-interrupt portion of a
CPU departure:

- computes the complete replacement route set against `online - departing_cpu`
  before touching the interrupt controller;
- rejects if no other CPU is online or any active line has no remaining legal
  affinity;
- masks every affected line before moving it, keeps a hardware-routing failure
  masked instead of delivering to the departing CPU, updates the route table
  only after controller routing succeeds, then unmasks;
- `demote_cpu_quota(cpu)` clears stale tick/throttle/statistics state only after
  no enabled line remains routed to that CPU.
- `msi_quiesce_cpu(cpu)` publishes a detached generation before clearing every
  MSI handler and budget callback. New MSI binding fails closed; a late arrival
  is counted in `detached_arrivals` and cannot invoke the previous handler.
  `msi_resume_cpu(cpu)` reopens dispatch without restoring old vector bindings.
- `interrupt::quiesce_cpu(cpu)` composes the dispatch stop with Interrupt-object
  teardown: affected objects are closed and completed as closed, MSI-X entries
  are masked/unbound, vectors are returned, and residual bindings are reported.
  The real `irqprobe-depart` mode keeps one hardware MSI-X interrupt object
  parked on a non-BSP CPU, then quiesces that CPU. The user wait completes with
  `INTERRUPT_CLOSED`, a later wait is rejected, and the kernel reports
  `objects=1 bindings=1 vectors=1 residual=0 resumed=true`.

The existing CPL3 SMP-3 drill now routes both device lines to a secondary CPU,
detaches that CPU, verifies no stale or offline target remains, demotes its
quota and checks resource restoration. Real KVM runs passed in x86_64 4-vCPU,
8-vCPU and q35 4-vCPU guests:

```text
[JSR-SMP3] case=detach ... rerouted=Ok(2) stale_targets=0 outside_online=0
  msi_quiesced=true quota_demoted=true resources=true
[JSR-SMP3] summary ... checks=35 failed=0
```

The complete x86_64 `accept.sh` run with 240-second per-guest limits reports
`accept: ALL PASS`; 4-vCPU, 8-vCPU and q35 4-vCPU guests exit 37 for timing-only
overruns while all functional SMP-3 checks pass.

This is an IRQ/MSI dispatch and active-object teardown milestone, not complete
CPU offline: scheduler task migration, architecture stop IPIs, CPU runtime
generation publication and hotplug rollback remain before
`CPU-DYNAMIC-CONSUMERS-1` can become done.

The runtime registry also rejects `mark_offline(boot_logical)` while another
CPU is online and reports `LastOnlineCpu` before the final online CPU can leave.
Both failures are transactional: the online set, per-CPU generations and the
registry generation remain unchanged.

## 未完成

- 当前主机没有 129+ CPU 的真实启动环境，因此该切片只证明软件不再以固定数组
  表达最终 CPU 统计容量，不冒充大拓扑运行验收。
- 亲和 ABI、剩余架构/path platform adapters、真实 129/256/1024-CPU、稀疏 NUMA、
  discovery failure 和 hotplug race 矩阵仍属于后续 CPU dynamic 阶段。
- LoongArch 完整 kernel build 仍被既有 `kernel/build.rs` “内嵌用户程序尚不支持
  loongarch64”阻断；本轮只验证 CPU dynamic 的 kernel-core 目标构建，不冒充
  LoongArch kernel/QEMU 验收。
- 其余每核 state 必须继续按同一 admitted runtime inventory 审计，不能用新的大
  魔数替代 128，也不能把 bootstrap-only 存储冒充最终容量。
