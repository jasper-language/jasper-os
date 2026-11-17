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

## Driver Host 组合层

`admit_and_activate`、`reset_and_unload`、`crash_and_quarantine` 与
`recover_and_reactivate` 把签名包生命周期和 `DriverHostBroker` 放进同一代际链：

- 包先完成签名/信任/降级/security epoch 检查，再按 Driver Host 的显式最小权限
  policy 准入；Host 准入失败不会产生包激活或设备 Pass；
- 若后续包激活失败，刚创建的未使用 Pass 会被撤销，设备恢复为可准入而不是留下
  隐藏租约；
- orderly reset 和 crash receipt 都先验证 DMA/IRQ 静默事实；失败不会部分释放；
- 成功 crash 会立即 quarantine 包所有权，旧 Host Pass、生命周期 token 和请求
  全部失效；
- recovery 只从显式 recovery package 或已知良好包恢复，并在 Host 和驱动两侧都
  通过后才重新发布 Active。

该组合仍使用内存中的 Host/控制器事实；真实 Driver Host 的持久 admission、
vendor firmware 格式和设备矩阵仍未完成。

## 验证

```text
cargo test -p kernel-core driver_lifecycle::tests
5 passed; 0 failed

cargo test -p kernel-core driver_host::tests
7 passed; 0 failed
```

覆盖坏签名、非信任签名者、降级、安全纪元、热插拔隔离、reset 静默失败、恢复与
陈旧 token，以及 Host 准入失败、激活失败 Pass 回滚、reset/crash/recovery 的
双 generation 失效链。

## 仍需完成

- 将状态机接入真实 Driver Host 的 admission/reset/crash receipt；
- 使用设备实际 vendor/device/class 能力和上游签名策略；
- 在 Pixel 6a 与至少一种非 Pixel 设备/虚拟设备上完成驱动、固件、热插拔、
  降级、reset 和 recovery 矩阵；
- 验证失败固件不会摧毁恢复路径，并保留安全审计和资源回收证据。

因此 LC-4 只能升为 `core-passed`，不能标为 done。
