# PIXEL6A-RUNTIME-1 实机回归状态

更新时间：2026-11-19。

状态：**当前公开内核在 Pixel 6a 上进入、完成 runtime 路径、PSCI reset 并恢复 Android；桌面、驱动域和持久安装仍未覆盖。**

## 构建与设备

- 公开代码：`c88bb41`
- 目标：`aarch64-unknown-none-softfloat`
- 特性：`pixel6a-runtime-verify`
- 设备：`bluejay` / Pixel 6a
- Android build：`google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys`
- stock boot carrier：匹配该 build 的 factory `boot.img`
- 内核 ELF SHA-256：`c1c3fae98eedf74185062fe7296ad6ff8c7cf77de97334701cff13ef9ce5bc59`
- 临时 boot image SHA-256：`08f99a8126bd227fe358e2c7228d80beae942b7f510943cee46931be872afcdf`

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
Jasper runtime 在 `4.49 s` 到达唯一成功 PSCI reset 路径，随后重新进入 FASTBOOT，
脚本执行 `fastboot reboot`。

## 恢复结果

reset 后实际恢复信息：

```text
product=bluejay
fingerprint=google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys
sys.boot_completed=1
slot=_a
```

证据保存在本地 `evidence/pixel6a-runtime-20261119-181818/`。

## 验证边界

该结果证明当前 Issue #47 CPU runtime registry、任务亲和堆后备表和 per-CPU 记录表
没有破坏已完成的 Pixel runtime reset 路径。它不证明：

- 桌面或原生 Terminal 在 Pixel 屏幕上可见；
- Android/Linux Driver Domain、HAL 或厂商驱动已接入；
- UFS 原生块设备、持久安装、更新和断电回滚可用；
- 大于 128 CPU 的实机拓扑已通过。

这些能力仍由各自 DAG/Issue 的独立真实退出门验收。
