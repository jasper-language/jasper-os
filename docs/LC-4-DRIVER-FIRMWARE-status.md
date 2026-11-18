# LC-4 驱动与固件生命周期

更新日期：2026-11-18。

状态：**core-passed；真实设备矩阵未完成**。

## 当前切片

`kernel-core/src/driver_lifecycle.rs` 在既有 Driver Host 单一设备权威之外增加纯生命周期
策略，不建立第二套设备授权：

- 驱动/固件包使用独立 Ed25519 32 字节公钥身份，必须具有非零 digest、signer、
  release 和 security epoch；`Package::verified` 只允许承载已经由签名信任边界
  验证过的包事实，不能再把窄整数当作签名者；
- 生命周期策略带固定容量撤销集合；已撤销 signer 即使仍是当前受信 signer 也
  优先失败，避免轮换期间旧键重新进入准入；
- 只有显式信任的签名者及有效签名事实可以进入 `Verified`；
- release floor、安全纪元和已运行版本阻止未经批准的回滚/降级；
- `Verified → Authorized → Active` 必须由 generation token 驱动；
- 热插拔移除立即使活动租约进入 `Quarantined`，旧 token 失效；
- reset 只有确认 DMA/IRQ 静默后才能进入 `Unloaded`，否则保持隔离；
- recovery 只能使用显式 recovery package 或已知良好版本，并产生新 generation。

该状态机不访问真实设备、不替换 PEP/Driver Host 授权，也不执行厂商固件格式。

## Android boot image / AVB 格式预检

`jasper-lifecycle-model::android_firmware` 新增 Android boot image v4 与 AVB
vbmeta 的只读验证，支持 AVB 公钥编码、SHA-256/SHA-512、RSA PKCS#1 v1.5
签名、rollback index 和分区哈希描述符。signer 指纹和内容摘要作为输入映射到
Jasper 自己的生命周期/Driver Host 策略，AVB 本身不成为授权根。

匹配 Pixel 6a factory `boot.img` 的 RSA-4096、header hash、签名和 `boot`
描述符已验证；篡改内核、篡改签名和错误分区请求均失败关闭。详见
`docs/LC4-ANDROID-AVB-status.md` 与 `evidence/lc4-pixel6a-avb-20261118/`。
该切片仍不包含 AVB chain-partition 递归、Jasper 公钥/rollback 持久化、
真实固件写入和失败恢复。

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

Driver Host 的 registration/admission 回执现已接入同一 P0 virtio-blk 的独立
32 KiB 保留区。空区首次启动格式化，非空但无效或损坏的区域失败关闭；第二次
OVMF 启动复用同一 P0/OVMF 后得到 `initialized=false` 和相同 receipt sequence，
且明确 `live_restored=false`，不会复活旧 host、pass、request 或 capability。

生命周期控制器现已和同一持久日志形成完整五段回执链：

```text
Registered → Admitted → Crashed → Recovered → Reset
```

第一次真实 OVMF 启动从 virtio-rng 设备取得实际 reset 结果，并读回 PCI
bus-master 已关闭，将 DMA/IRQ 静默事实同时交给 Driver Host crash/recovery
和 package lifecycle。准入 pass 在 crash 时被撤销，recovery 产生新 host
generation，最终 orderly reset 再产生一代并持久写入。第二次启动只恢复
`sequence=5 last=reset` 的审计历史，`initialized=false`、
`live_restored=false`，不会复活旧 host/pass/package token。

证据：
`evidence/driver-host-lifecycle-20261118-r4/README.md`。

## Issue #39 授权与技术双门禁

`evaluate_driver_admission` 把本地权限授权和设备技术准入拆成独立门禁：

- 授权记录绑定决策者、执行主体、设备/系统 OwnerScope、设备身份与 generation、
  policy epoch、revocation generation 和可选期限；
- 技术事实分别记录设备匹配、ABI、资源作用域、隔离要求/证明、可撤销性、
  DMA/IRQ 静默和 recovery 能力；
- 授权失败无论技术结果如何都拒绝；技术失败在生产模式拒绝，只有显式
  `Development` 模式可返回不具生产资格的 `DevelopmentOnly`；
- 过期、撤销 generation 变化、policy epoch 变化、执行主体替换、错误设备或
  作用域均在技术成功前失败关闭。

该模型现在仍是策略组合层；真实签名包、Driver Host receipt 和设备事实尚未全部
接入，因此不改变 core-passed 状态。

## 验证

```text
cargo test -p kernel-core driver_lifecycle::tests
7 passed; 0 failed

cargo test -p kernel-core driver_host::tests
7 passed; 0 failed
```

覆盖坏签名、非信任签名者、降级、安全纪元、热插拔隔离、reset 静默失败、恢复与
陈旧 token，以及 Host 准入失败、激活失败 Pass 回滚、reset/crash/recovery 的
双 generation 失效链。

## 仍需完成

- 状态机已接入真实 Driver Host 的 admission/reset/crash/recovery receipt；
- 已完成 P0 持久五段回执链、真实 virtio-rng reset 与 bus-master 读回；
- 使用设备实际 vendor/device/class 能力和上游签名策略；
- 在 Pixel 6a 与至少一种非 Pixel 设备/虚拟设备上完成驱动、固件、热插拔、
  降级、reset 和 recovery 矩阵；
- 验证失败固件不会摧毁恢复路径，并保留安全审计和资源回收证据。

因此 LC-4 只能升为 `core-passed`，不能标为 done。
