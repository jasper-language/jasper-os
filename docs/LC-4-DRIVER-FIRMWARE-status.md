# LC-4 驱动与固件生命周期

更新日期：2026-11-17。

状态：**core-passed；真实设备矩阵未完成**。

## 当前切片

`kernel-core/src/driver_lifecycle.rs` 在既有 Driver Host 单一设备权威之外增加纯生命周期
策略，不建立第二套设备授权：

- 驱动/固件包必须具有非零 digest、签名者、release 和 security epoch；
- 只有显式信任的签名者及有效签名事实可以进入 `Verified`；
- release floor、安全纪元和已运行版本阻止未经批准的回滚/降级；
- `Verified → Authorized → Active` 必须由 generation token 驱动；
- 热插拔移除立即使活动租约进入 `Quarantined`，旧 token 失效；
- reset 只有确认 DMA/IRQ 静默后才能进入 `Unloaded`，否则保持隔离；
- recovery 只能使用显式 recovery package 或已知良好版本，并产生新 generation。

该状态机不访问真实设备、不替换 PEP/Driver Host 授权，也不执行厂商固件格式。

## 验证

```text
cargo test -p kernel-core driver_lifecycle::tests
3 passed; 0 failed
```

覆盖坏签名、非信任签名者、降级、安全纪元、热插拔隔离、reset 静默失败、恢复与
陈旧 token。

## 仍需完成

- 将状态机接入真实 Driver Host 的 admission/reset/crash receipt；
- 使用设备实际 vendor/device/class 能力和上游签名策略；
- 在 Pixel 6a 与至少一种非 Pixel 设备/虚拟设备上完成驱动、固件、热插拔、
  降级、reset 和 recovery 矩阵；
- 验证失败固件不会摧毁恢复路径，并保留安全审计和资源回收证据。

因此 LC-4 只能升为 `core-passed`，不能标为 done。
