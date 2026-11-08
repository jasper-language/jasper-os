# HWV-2 Intel VMX 执行路径

更新日期：2026-11-08。

## 定位

HWV-2 把 HWV-1 的 vCPU、GPA 和 EPT 管理面接到真实 Intel VMX 执行路径：

* 打开 CR4.VMXE，执行 VMXON/VMXOFF；
* 分配并初始化真实 VMXON、VMCS、MSR bitmap 和三页 I/O bitmap；
* 用 `VMCLEAR`/`VMPTRLD` 建立当前 VMCS；
* 写入并回读执行、退出和进入控制；
* 执行真实 `VMLAUNCH`，后续退出使用 `VMRESUME`；
* VM Exit 后同步硬件保存的 RIP/RSP/GPR，再由 Rust 处理退出原因。

这是一条真实嵌套 Intel VMX 功能路径，不是用软件模拟“看起来进入了客体”。
当前证据来自宿主机 Intel VT-x + KVM 嵌套虚拟化；裸机 Jasper-OS 结果仍应单独记录，
不能把本检查点扩大成裸机认证。

## 客体与地址空间

验收客体是内核内置的最小 64 位 guest：

* guest 四级页表把低 2 MiB 映射为 GPA 恒等地址；
* HWV-1 EPT 把同一 GPA 窗口映射到真实 Memory backing；
* guest 使用独立 CR3、RIP、RSP、RFLAGS、EFER 和段状态；
* EPT 根由 HWV-1 vCPU 持有，HWV-2 只把它写入 `EPT_POINTER`；
* 第二个 guest 页表项故意指向 EPT 未映射的 2 MiB GPA，用于真实 EPT violation。

## VMCS 控制

当前冻结的控制至少包含：

* MSR bitmap、I/O bitmap、HLT exiting、RDTSC exiting、TSC offset；
* secondary controls 中的 EPT 与 RDTSCP；
* IA-32e entry/exit；
* entry/exit 时加载 host/guest IA32_EFER；
* 独立 exception bitmap，拦截 #UD、#DF、#GP、#PF。

控制位先按对应 IA32_VMX_* capability MSR 的 mandatory/optional 集合收敛；
请求了硬件不支持的位时在 VMXON 前结构化拒绝。

## VM Exit

以下退出路径已真实执行并可恢复：

| 退出 | 处理 |
|---|---|
| CPUID | 模拟 leaf/subleaf，写回 RAX/RBX/RCX/RDX，推进 RIP |
| RDTSC | 读取宿主 TSC，叠加 guest TSC offset，写回 EDX:EAX |
| RDMSR | 当前仅允许 TSC MSR；读取值同样叠加 TSC offset |
| I/O instruction | 校验端口和方向；验收端口 0x80 返回明确值并推进 RIP |
| EPT violation / MMIO | 记录 GPA 访问并从错误指令之后恢复 |
| #UD exception | 作为 expected terminal exception 返回，不泄漏到宿主 IDT |

其他未实现的退出原因返回结构化 `InvalidState`，不会静默吞掉。

## XSAVE 与宿主状态

VMX 执行期间临时启用：

* `CR0.NE`；
* `CR4.VMXE`；
* `CR4.OSXSAVE`；
* `CR4.OSFXSR | CR4.OSXMMEXCPT`。

宿主 XSAVE 状态先保存到私有 4 KiB 区域；guest 设置受支持的 XCR0 子集并执行
`FNINIT`、`FLD1`、SSE/XSAVE 路径。VMXOFF 后用 `XRSTOR64` 恢复宿主状态，再恢复
CR4/CR0 原值。当前 XCR0 支持的启用状态总量必须不超过 4 KiB，否则拒绝启动后端。

## 生命周期与失败原子性

* vCPU 在 `Ready -> Running` 后才能进入硬件后端；
* Running 时禁止 GPA 映射、取消映射和完整状态覆盖；
* 正常退出回到 Halted 并提交硬件 GPR/RIP/RSP 状态；
* 执行失败进入 Failed；
* 每次失败路径都执行 VMCLEAR/VMXOFF、宿主 XSAVE/CR/GDTR/IDTR/段寄存器恢复和页帧回收；
* 对象、Memory pin、页帧、固定计数最终回到基线。

VM Entry 前还校验：

* EPT 根 4 KiB 对齐；
* CR0.PE/PG、CR4.PAE、EFER.LME/LMA；
* RIP/RSP canonical；
* guest XCR0 是真实支持集合的子集；
* 控制字段可由当前硬件接受。

非法 EFER 和错对齐 EPTP 在启动硬件执行前被拒绝。

## 验收合同

独立构建：

```bash
cargo build --release --target x86_64-unknown-none \
  -p jasper-kernel --features hwv2-verify
```

验收串口必须满足：

```text
[JSR-HWV2] backend=Vmx entered=true vmxoff=true vmcs=true ept=true
cpuid=1 rdtsc=1 msr=1 io=1 ept_exit=1 exception=1 exits=6
tsc=true xsave=true state_saved=true failed=0
```

标准全量验收仍串行使用宿主 KVM CPU 4–11。

宿主 KVM 全量证据 `accept-20261108-192551`：x86_64 单核、4 核、8 核、q35 ECAM
与 S-2 均通过，`HWV-2 PASS`；只有既有 9 行计时参考超界，功能合同无失败。

## 当前边界

* 只实现 Intel；AMD SVM/VMCB/NPT 属于 HWV-3；
* 没有 VM-Exit Ring 投递、vCPU 等待/取消或虚拟中断控制器，属于 HWV-4；
* 没有 virtio 设备、PIO/MMIO 总线模型或用户态 VMM，属于 HWV-5；
* 没有 IOMMU 直通，属于 HWV-6；
* 当前最小 guest 不是 Linux/Windows 兼容客体；
* 全量验收把 HWV-2 放在计划末端，避免把嵌套 KVM 中“VMX 后继续切换用户态”的宿主实现差异混入 HWV-2；post-VMX 用户调度、等待和长期运行属于 HWV-4；
* 尚未执行裸机主机认证，也未把嵌套 KVM 结果当成裸机性能或安全证据。
