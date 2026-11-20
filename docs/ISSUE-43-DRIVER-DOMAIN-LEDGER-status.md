# Issue #43 驱动兼容域退出门台账

更新时间：2026-11-20。

状态：**software contracts and inventory only; no real compatibility driver domain**。

## 台账

`verification/issue43-driver-domain-ledger.tsv` 固定追踪 12 个退出门：

1. Linux/Android ABI 与版本范围；
2. Jasper 唯一物理设备所有权；
3. 真实 Linux Device UAPI 链；
4. 隔离 Linux 内核驱动域；
5. 真实 Android HAL/Binder 链；
6. Android GKI/KMI/厂商驱动域；
7. 兼容域身份不得提升为宿主权限；
8. 物理 MMIO/IRQ/DMA/IOMMU/reset 隔离；
9. 取消、超时、崩溃、复位和旧代际唯一终态；
10. 兼容域独立安装、升级、禁用与移除；
11. Pixel 6a 启动 UFS/救援依赖环；
12. 许可、固件、漏洞响应与支持矩阵。

`scripts/check-issue43-driver-ledger.py` 校验 ID、状态、分层和证据路径，CI
同时运行 self-test 与全表检查。

## 当前事实

- Pixel 6a 的设备、GKI、323 个 vendor 模块、26 个 vendor HAL 库和关键设备节点
  已只读盘点；
- `kernel-core::linux_device_uapi` 与 `kernel-core::android_hal` 是软件契约，
  复用 Driver Host pass、统一授权、generation、death 和 quiescence；
- 尚无真实 Linux/Android 驱动域、真实 Binder/HAL 执行、真实 ioctl 设备链、
  物理 IOMMU/reset 或启动 UFS 路径；
- 因而 DC-2、DC-4、LC-4 驱动部分和 Issue #43 均不能标记 done。

台账中的 `blocked-hardware` 与 `missing` 是结果，不是暂时跳过；只有相应真实
执行证据出现后才能迁移状态。
