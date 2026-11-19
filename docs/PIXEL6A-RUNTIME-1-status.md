# PIXEL6A-RUNTIME-1 实机回归状态

更新时间：2026-11-19。

状态：**当前公开内核在 Pixel 6a 上进入、完成 runtime 路径、PSCI reset 并恢复 Android；桌面、驱动域和持久安装仍未覆盖。**

## 构建与设备

- 公开代码：`5854046`
- 目标：`aarch64-unknown-none-softfloat`
- 特性：`pixel6a-runtime-verify`
- 设备：`bluejay` / Pixel 6a
- Android build：`google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys`
- stock boot carrier：匹配该 build 的 factory `boot.img`
- 内核 ELF SHA-256：`838b4b50f4a22a54f338facf134cf69a41595b54a38e93e8ce658f33da158e43`
- 临时 boot image SHA-256：`e4b62f32470c29697de9d6601acb0a4f7603b4d24ad8bb5268bb8de499799138`

## 执行方式

`scripts/pixel6a-runtime.sh` 将 Jasper Image 注入匹配 stock kernel PE 载体，生成临时
Android boot image，然后执行：

```text
adb reboot bootloader
fastboot getvar current-slot
fastboot getvar unlocked
fastboot boot <temporary-runtime-boot.img>
```

没有执行 `flash`、`erase` 或分区写入。fastboot 成功后设备实际离开 FASTBOOT，
Jasper runtime 在 `4.48 s` 到达唯一成功 PSCI reset 路径，随后重新进入 FASTBOOT，
脚本执行 `fastboot reboot`。

## 恢复结果

reset 后实际恢复信息：

```text
product=bluejay
fingerprint=google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys
sys.boot_completed=1
slot=_a
```

证据保存在本地 `evidence/pixel6a-runtime-20261119-182834/`。

## 验证边界

该结果证明当前 Issue #47 CPU runtime registry、任务亲和堆后备表和 per-CPU 记录表
没有破坏已完成的 Pixel runtime reset 路径。它不证明：

- 桌面或原生 Terminal 在 Pixel 屏幕上可见；
- Android/Linux Driver Domain、HAL 或厂商驱动已接入；
- UFS 原生块设备、持久安装、更新和断电回滚可用；
- 大于 128 CPU 的实机拓扑已通过。

这些能力仍由各自 DAG/Issue 的独立真实退出门验收。
