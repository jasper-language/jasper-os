# Pixel 6a LC-2 安装前置审计

更新时间：2026-11-18。

状态：**preflight 完成；持久安装被公开 UFS 后端缺失阻断**。

## 已确认真实设备事实

`scripts/pixel6a-lc2-preflight.sh` 只读取 Android、AVB、slot 和 fastboot 分区
事实，没有执行 `flash`、`erase` 或持久分区写入；随后通过 `fastboot reboot`
返回 Android，`slot=a`、`sys.boot_completed=1`。

```text
serial=31311JEGR07191
product=bluejay
fingerprint=google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys
slot=a
verifiedbootstate=orange
unlocked=yes
data_available_kib=104327188
userdata_bytes=118398996480
super_bytes=8531214336
boot_a_bytes=67108864
boot_b_bytes=67108864
```

证据：`evidence/pixel6a-lc2-preflight-20261118-135800/` 与
`evidence/pixel6a-lc2-preflight-20261118-140500/`；两次均无损往返 Android，
第二次也用于验证脚本退出恢复 trap。

## 当前阻塞

当前 Jasper 内核的生产块设备路径只有已验证的 virtio-blk。Pixel 6a 上的 UFS
由 Android/Linux 的上游驱动族管理，不能直接链接进 Apache-2.0 Jasper 内核；
项目尚未提供公开 UFS Driver Host/UAPI adapter。没有该后端时：

- 不能把 Android `userdata` 文件系统中的普通文件当作跨重启 P0 块设备；
- 不能通过 `fastboot boot` 把 P0 保存在 RAM 中并声称持久安装；
- 不能为了测试重写 Pixel 私有 UFS 驱动；
- 不能直接覆盖 `userdata`、`super` 或 boot slot 来制造“安装成功”。

## 上游 UFS 复用审计

已固定的 AOSP 快照为 `kernel/google-modules/soc/gs` 提交
`204078758737776959ecc85c527a00fd2cabb62f`。其中 Pixel UFS 后端位于
`drivers/ufs/`：

- `ufs-exynos.c`：GPL-2.0-only；
- `ufs-pixel.c`：GPL-2.0-or-later；
- `ufs-pixel-fips.c`：GPL-2.0-only。

这些文件依赖 Linux `platform_device`、clock、regmap、DMA、SCSI、电源管理、
SBBM/FIPS 和 Linux UFS core，不能直接链接进 Jasper 内核，也不能复制其内部
逻辑来规避许可证边界。当前 upstream U-Boot master 只有通用 UFS UCLASS，
没有可复用的 Exynos/GS101/Tensor UFS platform driver。

因此允许的下一步是隔离驱动执行域：将固定版本的 AOSP/Linux UFS 栈运行在独立
Driver VM 或完整 Linux 内核执行域，通过受限 Block I/O capability 暴露
read/write/flush/reset/quiesce；Jasper 仍以 Handle/Rights、PEP、DMA/IOMMU 和
资源世代作为唯一准入边界。也可等待稳定的公开用户态 UFS 接口，但不能自造私有
驱动或 shim。

在接入该后端前还需只读审计全部 LUN/GPT，确认是否存在未使用且足够大的专用持久
范围。`metadata` 属于 Android metadata encryption，不得挪用；`userdata` 不得被
当作 Jasper P0。若不存在专用范围，必须先完成可恢复分区方案和 Android 重装演练。

## 后续允许的安装切片

1. 优先复用 AOSP/Linux 公共 UFS 驱动，以独立 Driver Host 提供受控块设备；
   驱动仍通过现有 Device/IOMMU/IRQ/DMA/Handle-Rights/SEC/PEP 边界准入。
2. 在擦写前固定设备 fingerprint、GPT、活动 slot、关键分区与 Android 恢复镜像，
   并验证 USB/fastboot 救援路径。
3. 使用显式专用 P0 存储范围。若必须重分区，先完成可恢复备份、分区表恢复和
   Android 重新安装演练；不得默认以丢失用户数据为代价。
4. 在该后端上运行真实 install、health trial、update、rollback、power-loss 和
   archive/audit 矩阵，并保留 Android 恢复证据。

preflight 不是 LC-2 安装验收，不关闭任何 DAG 节点。
