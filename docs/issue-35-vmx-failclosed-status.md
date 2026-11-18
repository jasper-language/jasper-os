# Issue #35 VMX 读取失败关闭切片

更新时间：2026-11-18。

状态：**控制决策相关 VMREAD 已改为失败关闭；仅故障日志保留显式 best-effort
读取。真实 VMX 故障注入矩阵仍待补。**

## 本切片

- 注入中断前读取 `GUEST_INTERRUPTIBILITY` 不再失败时默认“可注入”，而是把
  `Vmread` 错误返回给上层，阻止基于未知 guest 状态继续执行；
- VM-exit 指令长度、CR8 退出资格、EPT 物理地址与 qualification、observer
  使用的退出字段不再默认成 `0`/`u64::MAX`，读取失败直接终止本次运行；
- MMIO 指令仿真读取 `GUEST_CR3` 时不再回退到过时的软件 guest CR3；翻译失败或
  VMREAD 失败都会阻止错误地址被当作设备访问；
- 故障日志统一通过 `vmread_diagnostic`，读取失败显示 `u64::MAX`，并在注释和
  `hardcode-review-sources.tsv` 中登记为仅诊断用途；
- `SYSCALL` MSR 未显式写入时的 0 保留：该组 MSR 的架构 reset 值就是 0，不是
  VMREAD 失败回退。

## 验证

```text
cargo check -p jasper-kernel --target x86_64-unknown-none --no-default-features
PASS

HWV2_XSTATE_ACCEL=kvm HWV2_XSTATE_CPU=host \
HWV2_XSTATE_TASKSET=5 bash scripts/hwv2-xstate-check.sh
hwv2-xstate: PASS

python3 scripts/check-hardcode-gate.py --inventory \
  --inventory-baseline docs/hardcode-inventory-baseline.json
findings=384, added=0, cleared=29
```

## 尚未完成

- 仍需要可控 VMREAD 失败注入，证明每个运行路径返回
  `hwvirt.vmx.error.vmread` 且不继续推进 RIP、不注入 IRQ、不访问推测 GPA；
- 真实 KVM/TDX/厂商 CPU 的 VMCS 不可用、损坏 VMCS、EPT qualification 异常与
  host recovery 矩阵仍属于硬件验收；
- 故障日志的 `u64::MAX` 是明确 unknown，不是架构事实。
