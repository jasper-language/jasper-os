# Android ART Native Compatibility

更新日期：2026-11-18。

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
- 官方测试 DEX 必须按 AOSP harness 顺序编译 `src`、执行 `javac_post.sh`，
  再用 `src2` 覆盖；`003-omnibus-opcodes` 特别依赖这一步骤把 `UnresStuff`
  替换成只有字段 `x` 的未解析成员夹具。可复现入口为
  `scripts/build-aosp-art-tests.sh`。
- 上游 `AndroidAutoBuildAPK-v18.apk`（SHA-256
  `22c31a97…c0d05`）通过 AOSP `aapt2` 的 ZIP、Manifest、包名、launcher
  Activity、SDK 和 `classes.dex/classes2.dex/classes3.dex` 结构检查；
  未修改 ART 在真实 Jasper UEFI/root image 中从该 APK 加载并执行
  `androidx.constraintlayout.core.motion.parse.KeyParser`，退出 0，第二次
  measured 运行 `resources=true`。

Jasper x86_64 `MAP_32BIT` 低窗口已从 `[1 GiB, 2 GiB)` 扩展为
`[128 MiB, 2 GiB)`。128 MiB 以下现有内核低映射保留；用户地址空间使用独立
PDPT/PD，不通过新增低地址映射修改共享内核页表。

## 当前失败

使用正确重建的官方 DEX 后，`003-omnibus-opcodes` 已完成算术、数组、类、
`UnresTest1`、`UnresTest2` 等测试；随后在 `InternedString.run` 触发用户态
缺页：`ip=0x1002ea5a5920 addr=0x6d`。地址形态类似空基址后的结构体字段访问，
表明字符串驻留/弱引用 GC 路径仍有对象元数据或内存映射缺口。

这是 Android/Dalvik 字符串/弱引用/GC 运行时缺口，不是地址空间或内存容量问题。
节点不能据此标记完成。

## 证据

真实 UEFI/QEMU 证据：

- warm-up：`android-art-official-001` 退出 0；
- measured：`android-art-official-001`、`android-art-official-002` 退出 0，
  `resources=true`；
- `android-art-official-003` 在 `InternedString.run` 后发生
  `addr=0x6d` 用户态缺页并终止。
- APK 内的 DEX 与容器入口已经可执行，但 Activity、Framework、资源/配置、
  graphics、input 和 audio 生命周期尚未接入，因此仍不能把 APK 节点标为完成。

APK 专用证据：
`evidence/issue21-uefi-boot-20261118-144543/README.md`。

## Framework namespace 实机前置门

`scripts/android-framework-preflight.py` 直接以只读 `debugfs` 检查真实 Android 34
`framework-root-v1.img`，不启动 Android，也不把文件存在当作 Activity 成功。当前
实测镜像包含：

- `app_process64`、`servicemanager`、`installd`；
- `framework.jar`、`services.jar`、`am.jar`；
- `framework-res.apk` 的 7,880 个 ZIP 条目和 16,421,724 字节
  `resources.arsc`；
- `/system/etc/permissions` 与 `/apex/com.android.runtime`。

该根镜像的 `init.zygote64.rc` 使用
`app_process64 -Xzygote /system/bin --zygote --start-system-server` 启动 zygote
并拉起 system_server；现代 Android 不需要独立的 `zygote64`/`system_server`
二进制。

第二次按实际 AOSP 启动链复核后，又纠正了两个静态误判：

- `/linkerconfig/ld.config.txt` 本来就不在 system 镜像中；`init.rc` 会创建
  bootstrap 目录、写入早期配置、bind-mount 到 `/linkerconfig`，启动
  `apexd-bootstrap` 后执行 `update_linker_config`；
- 原厂 `/system/etc/passwd` 是 UID/GID 1000 拥有的空文件，Android 运行时身份由
  user/group 服务提供，不能用“非空 passwd”作为启动门。

当前静态前置为 `container_ready=true`、`activity_runtime_ready=false`、
`missing=[]`。尚未实际启动 zygote/system_server，所以仍不能宣称 Framework 或
Activity 生命周期完成。报告见
`evidence/android-framework-preflight-20261120/report.json`。

## Activity/Framework 生命周期边界

APK 中的 DEX 能由 unmodified ART 执行，不等于 Android Activity 已可启动。当前
固定夹具已有 zygote/system_server 的 init 启动定义、运行时 linker-config 生成链、
`installd`、`services.jar`、`am.jar` 和 framework resources，但还没有证明运行中的
ActivityManager Binder service，也没有实际挂载完整的
`/system`、`/apex` Framework namespace 和服务图。

`app_process64` 自身依赖 `libandroid_runtime.so`、`libbinder.so`、
`libhidlbase.so`、`libwilhelm.so`，并继续引入 graphics、media、audio、camera、
EGL/Vulkan 等系统库。因此单独启动 `app_process64 com.android.commands.am.Am`
不能证明 Activity 生命周期，当前也不是只需补一个 syscall 的小修。

后续真实门必须先把 `zygote64`/`system_server` 及其匹配的 APEX、权限链接和后端
服务关系纳入受权限约束的 Framework namespace，再启动 ActivityManager Binder，
随后验证 APK 安装登记、
Activity `onCreate/onStart/onResume`、资源与 configuration 交付、
graphics/input/audio 以及撤销和资源回收。任何只验证 shell、固定文本或 mock
Activity 成功的路径都不能关闭该节点。
