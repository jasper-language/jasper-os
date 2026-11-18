# Issue #35 Linux 兼容共享内存与 BAR 容量切片

更新时间：2026-11-18。

状态：**错误生产容量已移除并改由既有内存/MMIO 准入；真实 Linux 用户态超限矩阵仍待
兼容层运行验收。**

## 裁决与实现

- System V shared memory 的 64 MiB 不是 ABI 常量；删除该上限，保留非零值与页数
  转换检查，由进程 `memory_account` 的页预算原子准入；
- ION 单对象 16 MiB 与每进程 32 个元数据项不是 ION wire ABI；大小改由进程内存
  预算裁决，句柄元数据由可失败堆增长和现有句柄/配额治理；
- ashmem/memfd set-size 与写入尾部的 16 MiB 上限不是 Linux/Android ABI；删除后
  仍必须先通过同一内存预算和 seal/fscrypt 检查，失败不发布 size 或页；
- 单设备 BAR 的 1024 页（4 MiB）不是 PCI BAR 协议限制；删除固定页数上限，
  由实际 BAR 长度、用户地址窗口、page-table 映射能力和
  `memory_capabilities(DeviceMmio)` 预算共同裁决；
- MMIO capability 预算检查移到逐页冲突扫描之前，超大请求不会先消耗 O(pages)
  扫描工作。

以上仍使用既有 MemoryAccount、MemoryCapability、Handle/Rights、Device Broker 和
页表机制，不创建第二套容量或权限权威。

## 验证

```text
cargo check -p jasper-kernel --target x86_64-unknown-none \
  --features compat-syscall-verify
PASS

python3 scripts/check-hardcode-gate.py --inventory \
  --inventory-baseline docs/hardcode-inventory-baseline.json
findings=423, added=0, cleared=5
```

## 尚未完成

- 需要在未修改 Linux 用户态中实际请求超过旧 16/64 MiB 阈值、超过旧 4 MiB BAR
  包络，并验证预算内成功、超预算失败、unmap/free/exit 后页与 capability 回基线；
- ION/ashmem/memfd 元数据容量仍应与最终进程/Workload 配额模型统一；
- BAR 的 IOMMU 物理隔离、热插拔和真实设备 reset 仍属于 LC-4/DC-1 真实设备门。
