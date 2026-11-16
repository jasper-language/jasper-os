# HC-05：RISC-V 启动物理图与线性映射

状态：**fixed（用户新范围：排除物理硬件资格，保留 QEMU 可验证实现）**。

## 已消除的硬编码

- Sv39 早期线性映射不再无条件覆盖 `0..4 GiB`；
- 引导期只映射内核映像所在 GiB 与固件 DTB 所在 GiB；
- DTB 校验后遍历所有节点的 `reg`，把实际 RAM 终点、DTB 终点、内核映像和硬件窗口合并为所需物理图；
- 只有该图完整落在线性映射窗口内才继续启动；超出窗口明确失败；
- CPU inventory 与 IRQ 账目不再在 Heap 之前尝试堆分配，也不会把“尚无堆”的失败永久缓存；
- IRQ 路由和每核 quota 的所有堆分配在取得高等级 IRQ 锁之前完成，保持锁序。

## 真实验证

同一 ELF，QEMU `virt`，Sv39 CPU，单核：

```text
256 MiB:
[JSR-MMAP] source=fdt ram_end=0x90000000 graph_end=0x90000000 covered=0xc0000000 complete=true

1024 MiB:
[JSR-MMAP] source=fdt ram_end=0xc0000000 graph_end=0xc0000000 covered=0xc0000000 complete=true
```

两种拓扑均通过中断线动态准入：

```text
[JSR-IRQ] topology source=smp_ready discovered=2 admitted=2 rejected=0 capacity=2 ... complete=true
```

证据：`evidence/hc05-riscv-map-r9-20261116/`。

## 回归

- `cargo test -p kernel-core --lib --features runtime-registries -- --test-threads=1`：919/919；
- FDT 全节点 `reg` 遍历测试通过；
- RISC-V64 与 x86_64 内核检查通过；
- hardcode gate 的 self-test 与 `004e547` 基线检查通过。

## 外部边界

运行期间在 Sv39/Sv48 之间按 `mmu-type` 选择，以及超过当前 64 GiB 线性窗口的物理硬件资格，属于用户已排除的物理平台验收范围；本节点不再让该外部资格阻塞软件 DAG。系统仍对不满足当前窗口的物理图失败关闭，不伪造可访问性。
