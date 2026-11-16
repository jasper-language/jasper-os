# PEX-6：并行 TLB 击落公告板

状态：**done（声明的 PEX-6 验收门）**。

## 问题

旧实现只有一块全局 `ShootdownBoard`。这保证单请求的帧释放顺序简单，但不同 CPU
针对不同地址空间同时发起击落时，后者只能得到 `Busy` 并重试。一个发起者的慢目标
会串行阻塞所有无关发起者。

## 实现

- 启动期按固件已准入的逻辑 CPU 数分配一块 `ShootdownBoard`，每个发起 CPU 独占一块；
- 目标 CPU 收到一次 TLB IPI 后遍历所有发起者公告板，在同一 IPI 内处理发给自己的全部请求；
- 每个请求仍只在**自己的全部目标应答后**完成，超时也只撤销自己的代号；
- 帧回收、地址空间 `shootdown_pending` 和 FV-4 的“应答后才释放”顺序没有改变；
- 固件拓扑发现前的单 CPU 启动路径使用独立 bootstrap 公告板，发现完成后切换到动态板集合；
- 宿主测试覆盖两个发起者并行、共享目标一次服务、单方撤销不影响另一方，以及非法分片不改变在途状态。

公告板锁仍是叶子锁。`ShootdownBoards::service` 只逐板调用原有的单请求状态机，不持有
任何调度器、对象表或内存分配器锁。

## 真实运行证据

同一 ELF 在 `qemu-system-x86_64`、KVM、`q35`、8 vCPU、512 MiB RAM 下运行，QEMU
仅绑定宿主 CPU 4–11：

```text
[JSR-PEX6] parallel initiators=7 spawned=7 completed=7 request_failures=0 requests=7 peak_inflight=7 overlapping=true idle=true
[JSR-SMP] summary cpus=8 online=8 checks=45 failed=0
```

这说明 7 个 AP 的请求确实同时在途，而非单板重试后逐个执行；全部请求完成，且没有
遗留公告板状态。原有 8 核 TLB 可见性仍为
`before=A:7/7 after_shootdown=B:7/7 frames_back=true`。

本地开发证据：`evidence/pex6-parallel-r3-20261116/`。该完整默认镜像也在与 PEX-6
无关的硬件演练上返回非零退出码，因此本节点只使用 `smp_failed=0`、上述 PEX-6
定点行和既有 FV-4 单请求契约；不把无关套件结果算作 PEX-6 证据。

## 回归门

- `cargo test -p kernel-core --lib smp::tests::`：18/18；
- x86_64、AArch64、RISC-V64 `jasper-kernel` 检查通过；
- `scripts/check-hardcode-gate.py` self-test 和 `d218012` 基线检查通过；
- `scripts/accept.sh` 的 `SMP-1a` 现在要求 4 核和 8 核日志分别出现
  `peak_inflight=3` 与 `peak_inflight=7`，并同时要求完成数等于发起数、
  `request_failures=0` 和 `idle=true`。

## 边界

本实现解决的是**不同发起者之间的全局串行化**，没有把同一目标上的多个 flush 合并为
硬件事务，也没有宣称降低所有目标的总工作量。任意请求到 P 个目标仍存在 Ω(P) 的传播
下界；后续只有在真实热点数据证明请求板锁或同目标 flush 合并成为瓶颈时，才需要继续
分片或批处理。
