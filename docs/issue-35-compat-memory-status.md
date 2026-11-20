# Issue #35 Linux 兼容共享内存与 BAR 容量切片

更新时间：2026-11-20。

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
- ELF 页计划器不再保留私有 1 GiB 页数上限或 64 KiB 页大小默认上限；
  `ImageLayout` 和动态程序规划显式接收调用方页预算，内核按进程剩余内存额度与
  当前可用物理帧的较小值准入。
- fscrypt 全局 keyring 不再固定 4 个 key、4 个用户 claim。key 条目和每 key 用户
  列表改为 `try_reserve` 准入的可失败堆增长；全部用户撤销时清零 master key 并
  删除条目，保留原有权限和 `ENOKEY` 失败语义。
- Linux `read`、`pread64` 和 `readv` 的 1 MiB 运行期默认上限已移除。ashmem 临时
  缓冲改为 `try_reserve_exact` 后零初始化；向量、pin 与复制范围表的元数据也使用
  可失败堆准入；实际读取继续由调用方长度、文件/终端可用数据、进程 IO 和 pin
  预算裁决。
- `getrandom` 的 1 MiB 单次总长度上限已移除；输出缓冲由调用方长度和
  `try_reserve_exact` 的堆准入决定，分配失败返回 `ENOMEM`，不改变合法 flags 和
  随机源回退语义。
- root verification VFS 的 96 个 library slot 固定数组改为直接使用
  `ANDROID_FILE_PATHS.len()`；槽位数量由实际登记源集合决定，并增加编译期断言保证
  索引仍可无损编码进现有 `FileId::AndroidFile(u8)`。
- 每个 epoll 实例的 64 条 interest registration 固定上限已移除；新增登记继续先
  `try_reserve`，失败返回 `ENOSPC`，实际容量由可失败堆增长决定。
- Linux supplementary groups 不再固定 32 项，`getgroups`/`setgroups` 使用调用方
  数量、可失败 `Vec` 准入和逐项用户读取/写入；System V user/logon/keyring 不再
  固定 16 项，keys 与 process keyring 继续由 `try_reserve`、序列号和内存失败
  语义准入。
- Android Binder 不再固定 64 queue、128 node、512 local handle 或 64 looper 项。
  queue、node、handle、thread、wake target 和退出通知快照全部在变更前使用可失败
  堆准入；分配失败在会改变事务/队列之前返回 `ENOMEM`，清理路径仍保持代际与
  dead-node tombstone 语义。
- Linux graphics `GraphicsService<..., Y>` 的 fence、binary semaphore 和 timeline
  容量改由调用方显式选择；`Y=1` 负例验证第二对象 `Capacity` 拒绝，销毁后槽位可
  重新使用。
- `process_vm_readv/writev` 删除 1 MiB 总传输上限；iovec 解析到 `usize` 溢出边界，
  实际复制量由双方向量长度、进程 IO 预算和可失败 `try_reserve_exact` 共同裁决。
- `move_pages` 删除 1024 页固定批次上限；页地址、状态和可选节点数组使用
  `checked_mul`、`try_reserve_exact` 与用户复制边界准入。
- Unix-domain `SCM_RIGHTS` 删除 32 个描述符批次上限；在捕获每个 fd transfer 前
  使用 `try_reserve(1)`，失败返回 `ENOMEM`，接收侧仍受目标 FdTable 和进程预算约束。
- Legacy AIO `io_submit` 删除 32 请求批次数上限；调用方列表按偏移和用户长度解析，
  已有 context `max_events` 在有界完成队列耗尽时返回部分提交数。
- System V shared memory 的每段 32 attachment 上限已删除；映射完成后的 attachment
  记录使用 `try_reserve(1)`，失败会 unmap 并返回 `ENOSPC`，段生命周期与权限检查
  不变。
- USI 请求幂等账本删除每进程 16 槽固定数组；completed 项仍按最老顺序复用，
  pending 项需要增长时使用 `try_reserve(1)`，分配失败返回 `Exhausted`。
- Linux `flock` 删除每进程 64 lock/waiter 固定数组；记录按 `try_reserve(1)` 增长，
  解锁时直接移走 waiter 集合后在锁外逐个唤醒，不在中断路径分配临时向量。
- Linux realtime signal record 队列删除固定 256 槽；入队时寻找空槽或
  `try_reserve(1)` 增长，分配失败仍返回 `EAGAIN`，已有记录不被覆盖。

以上仍使用既有 MemoryAccount、MemoryCapability、Handle/Rights、Device Broker 和
页表机制，不创建第二套容量或权限权威。

## 验证

```text
cargo check -p jasper-kernel --target x86_64-unknown-none \
  --features compat-syscall-verify
PASS

cargo test -p jasper-compat-loader
36 passed

cargo check -p jasper-kernel --target x86_64-unknown-none
PASS

python3 scripts/check-hardcode-gate.py --inventory \
  --inventory-baseline docs/hardcode-inventory-baseline.json
findings=287, runtime-resource-capacity=30, unclassified=0, added=0
```

## 尚未完成

- 需要在未修改 Linux 用户态中实际请求超过旧 16/64 MiB 阈值、超过旧 4 MiB BAR
  包络，并验证预算内成功、超预算失败、unmap/free/exit 后页与 capability 回基线；
- ION/ashmem/memfd 元数据容量仍应与最终进程/Workload 配额模型统一；
- BAR 的 IOMMU 物理隔离、热插拔和真实设备 reset 仍属于 LC-4/DC-1 真实设备门。
