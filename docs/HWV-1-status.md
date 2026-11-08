# HWV-1 vCPU、GPA 与 EPT/NPT 管理面

更新日期：2026-11-08。

## 定位

HWV-1 建立硬件虚拟化的管理面和二级地址空间：

* vCPU 是带 Handle/Rights 的内核对象，不属于某个通用“虚拟机空对象”；
* 每个 vCPU 拥有独立的 48 位客体物理地址空间和独立 EPT/NPT 根；
* GPA 映射固定对应的 Memory 对象，并保留每项映射自己的内部引用；
* 状态只能在稳定边界保存，Running 时拒绝完整状态覆盖；
* VMCS/VMCB 装载、VM Entry、VM Exit 和宿主硬件模式切换仍属于 HWV-2/HWV-3。

本阶段不会执行 `VMXON`、`VMLAUNCH`、`VMRUN` 或任何等价入口，也不能用“存在 EPT/NPT”
冒充已经能运行客体。

## 对象与权限

`Vcpu` 是独立 `ObjectType`/`Kind`，默认句柄权限为：

```text
READ | WRITE | WAIT | CONTROL | DUPLICATE
```

句柄不可经 IPC 转移。vCPU 对 Memory 是强引用；closing 在对象表锁内停止新操作、清空
全部 GPA 映射并逐一释放 Memory 内部引用。vCPU 对象自身死亡后，二级页表在对象表锁外销毁，
故不会在 closing 路径递归获取调度器或帧分配器锁。

## 生命周期与状态

基础状态机为：

```text
Offline -> Ready -> Running -> Halted
                         \-> Failed
任意非 Closed -> Closed
```

HWV-1 冻结以下约束：

* 只有 Ready 能进入 Running；
* 完整架构状态只能在非 Running 边界保存；
* 关闭后的对象不再接受映射、状态或查询操作；
* Running 的实际进入/退出由 HWV-2/HWV-3 的硬件后端负责。

## GPA 契约

每个 vCPU 最多保存 64 个非重叠映射项。单项映射满足：

* GPA、Memory offset 和页数按 4 KiB 粒度校验；
* GPA 位于 `[0, 2^48)`；
* Memory offset 和完整页范围不得越出 Memory 对象；
* read 是基础权限，write/execute 只能在 read 上叠加；
* 同一 vCPU 内 GPA 不得重叠；
* 一项映射对应一项 Memory 内部引用，失败路径不得残留引用或页表项。

同一 Memory 可映射到多个 GPA，形成受控别名；不同 vCPU 即使使用相同 GPA，也拥有独立根表，
不会共享缺页、权限或映射生命周期。

## EPT/NPT

`kernel/src/arch/x86_64/second_level.rs` 定义两种真实的四级表项格式：

| 后端 | 表格式 | 关键权限 |
|---|---|---|
| Intel VMX | EPT | R/W/X、EPT memory type（WB/UC）、52 位物理地址掩码 |
| AMD SVM | NPT | present/write/NX、PCD、52 位物理地址掩码 |

内核只为当前 HWV-0 实际选中的后端创建对应根：

* 根和中间页表均为真实 4 KiB 物理帧；
* 表通过引导器建立的全物理内存映射写入；
* 映射失败回滚本次已建立的 GPA 页和新建中间表；
* 取消映射时自底向上删除变空的中间表并归还页表帧；
* 关闭 vCPU 时回收其全部下级表和根表。

EPT/NPT 在 HWV-1 只是已构建、可走查的二级表，未装入 VMCS/VMCB。HWV-2/HWV-3 才能证明
硬件实际使用这些表完成地址翻译和隔离。

## Memory 固定与失效

每个 GPA 映射保留 Memory 对象的一份内部引用。关闭用户侧 Memory 句柄不会在 vCPU 仍在映射时
清除 backing；显式取消 GPA 或关闭 vCPU 才释放对应内部引用。最终引用消失后，Memory 页和
页表帧按既有 RAII 路径归还。这样避免“句柄关闭”和“固定仍有效”混为一谈。

## 验收合同

`hwv1-verify` 独立构建和全量验收运行同一 drill：

* 真实创建两个 vCPU 和两个 Memory 对象；
* 检查 EPT/NPT 根不同且页对齐；
* 同一 Memory 双 GPA 别名得到同一宿主页；
* 两个 vCPU 的同 GPA 得到不同 backing，写入互不影响；
* 拒绝重叠、错对齐、越出 Memory、无 read 和越出 48 位 GPA 窗口；
* 状态保存/恢复与 Offline → Ready；
* 精确取消后硬件表项和元数据同时消失，其他别名保留；
* Memory 句柄关闭后，vCPU 固定仍有效；
* vCPU/Memory/进程关闭及清理后，对象、页帧、固定计数回到基线；
* 串口明确记录 `entered=false`。

独立启动命令：

```bash
cargo build --release --target x86_64-unknown-none \
  -p jasper-kernel --features hwv1-verify
```

标准 KVM 验收仍通过 `scripts/accept.sh`，CPU 固定为 4–11，不并行启动多个 QEMU。

宿主 KVM 全量证据 `accept-20261108-173014`：x86_64 单核、4 核、8 核、q35 ECAM
与 S-2 均通过；`HWV-1 PASS`，QEMU 退出码为 37 只因既有 9 行计时参考超界，
功能合同与资源守恒无失败。

## 当前边界

* 尚无 vCPU 系统调用 ABI；当前入口是内核模块 API，待用户态 VMM 里程碑再冻结稳定 ABI；
* 不支持 2 MiB/1 GiB 二级大页，当前只实现 4 KiB 叶子；
* 尚无 EPT/NPT TLB 激增与跨核 invalidate 协议，因为表还未激活；
* 尚无虚拟中断、VM Exit、虚拟设备或 IOMMU；
* 宿主 KVM 中成功运行不能证明 Jasper-OS 自己的 VMX/SVM 已通过，必须等待 HWV-2/3 真机路径。
