# Android ART Native Compatibility

更新日期：2026-11-17。

状态：**in progress**。本文件记录未修改 AOSP ART 在 Jasper x86_64
Linux/Android 兼容环境中的真实执行边界。

## 上游输入

- AOSP ART commit：`3c05e56adf5b268ec5b20bf8aec460815e45161c`；
- 官方测试：`001-HelloWorld`、`002-sleep`、`003-omnibus-opcodes`；
- 运行入口：未修改的 `/system/bin/dalvikvm64` 与 `/system/bin/linker64`。

## 已通过

- ART 首选 RegionSpace 地址 `0x0ec00000` 可在 Jasper 用户地址空间建立；
- `001-HelloWorld` 的 warm-up 与 measured 两次执行均退出 0；measured 执行
  约 22,605 次 syscall，页帧回到运行前基线；
- `002-sleep` 的 measured 执行退出 0，页帧回基线；
- 运行使用 2 GiB guest RAM，足以容纳 ART 512 MiB RegionSpace 与运行时映射。

Jasper x86_64 `MAP_32BIT` 低窗口已从 `[1 GiB, 2 GiB)` 扩展为
`[128 MiB, 2 GiB)`。128 MiB 以下现有内核低映射保留；用户地址空间使用独立
PDPT/PD，不通过新增低地址映射修改共享内核页表。

## 当前失败

`003-omnibus-opcodes` 已完成算术、数组、类和多数 opcode 测试后，在
`UnresTest1.run` 的未解析实例字段读取处触发 `Main.assertTrue(false)`。
它预期 `NoSuchFieldError`，当前 ART/Dalvik 解析路径没有产生该类错误。

这是 Android/Dalvik 字段解析与失败语义缺口，不是地址空间或内存容量问题。
节点不能据此标记完成。

## 证据

真实 UEFI/QEMU 证据：

- warm-up：`android-art-official-001` 退出 0；
- measured：`android-art-official-001`、`android-art-official-002` 退出 0，
  `resources=true`；
- `android-art-official-003` 在 `UnresTest1.java:11` 失败并退出 1。
