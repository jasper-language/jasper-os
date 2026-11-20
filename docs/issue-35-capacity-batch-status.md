# Issue #35 配置容量与 Linux 批次审计

更新时间：2026-11-20。

状态：**配置上限与四个兼容批次语义已裁决；poll 超限 errno 和每进程 epoll
实例固定上限已修复；其余高规模运行证据仍待补。**

## 配置容量（HC-A10）

`KernelConfig::validate` 对 timer Hz、Task/Object/RT 槽位和内核栈设置上下界，
并在越界时返回具体字段错误；`capacity::resolve` 进一步检查 RT 与 Task 一致性及
内存预算，超限不发布部分容量。这些数值是已声明、可测试的产品安全/验证策略，
不是硬件发现事实：

- timer 50–1000 Hz 约束调度粒度与中断开销；
- Task 默认 64、验证上限 256，独立容量验收构建允许 1024；
- Object 默认 1024、验证上限 65536；
- RT 在册表默认 8、验证上限 64，且必须小于 Task 槽位；
- 内核栈至少 32 KiB，现役 Profile 使用 128 KiB。

上层 Workload/Profile 仍可通过更小预算收窄；任何超过验证边界的配置必须失败，
不能按硬件数量静默扩容。更高规模的调度/Object 表实现和真实压力矩阵仍未完成。

## Linux 固定批次（HC-A11）

- `signalfd` 一次最多 16 条记录：Linux `read` 返回可写下的部分记录数，剩余记录
  留在队列中，不丢事件；
- `fanotify` 一次最多 8 条事件：返回部分批次，失败时把整批事件放回队首并撤销
  本次已安装的 event fd；
- epoll wait 每次最多写回 64 条：Linux 允许返回小于 `maxevents` 的就绪数量；
- `sendfile`/`copy_file_range` 每轮最多 1 MiB：当前实现返回完成的部分字节并推进
  文件/显式 offset，调用方可以继续循环，语义不是静默截断；
- `poll` 单次最多 64 条 `pollfd`：这是兼容服务的显式扫描/用户复制 DoS 策略。
  以前超限返回 `EINVAL`，会错误地把合法大请求当作参数损坏；现在返回 `ENOMEM`。

`poll` 的 64 条上限仍不是最终产品目标。后续应由 Workload IO/CPU 预算动态授予
扫描容量，并取得超过 64 个 fd 的未修改 Linux 程序、取消/超时和资源回收证据。

### epoll 实例数量

`linux_epoll_create1` 原先除 fd 表预算外还有一个独立的每进程 8 实例上限。
该上限没有协议或安全依据，现由以下既有资源链统一决定：

- 每进程 FdTable 的运行时 soft/hard 预算；
- epoll 元数据 `Vec::try_reserve` 的堆准入；
- `Rights::READ | Rights::WRITE` 和兼容句柄世代。

真实静态 Linux ET_EXEC 在一个进程中创建 12 个 epoll fd，再全部关闭；成功退出，
未授权 syscall 拒绝仍保持，进程退出后页帧回到基线。证据见
`evidence/issue35-epoll-capacity-20261119/`。

### eventfd 实例数量

每进程 32 个 eventfd 的独立上限同样已移除。实例元数据由
`Vec::try_reserve` 和运行时 FdTable 预算准入，不增加固定数组。真实静态
Linux ET_EXEC 一次创建 40 个 eventfd，完成 write/read，再全部 close；进程继续
执行 futex/mmap/io_uring 并以 0 退出，资源回基线。探针先前误用只传一个参数的
`syscall1` 调用 `eventfd2`，未初始化 flags 在第三轮变成 2 并被内核正确拒绝；
修正为显式 `flags=0`。证据见 `evidence/issue35-eventfd-capacity-20261119/`。

### timerfd 与 signalfd 实例数量

timerfd 和 signalfd 原先各自还有每进程 32 实例的独立上限；它们同样由
FdTable、metadata `try_reserve` 和 Rights 决定，现一并移除。真实 Linux ELF
分别创建并关闭 40 个 timerfd 与 40 个 signalfd，随后继续 futex/mmap/io_uring，
以 0 退出且进程资源回基线。证据见
`evidence/issue35-timerfd-signalfd-capacity-20261119/`。

### pipe 实例数量

pipe endpoint 记录的每进程 32 上限已移除。每个 pipe2 仍需由运行时 FdTable
分配两个描述符，并保持 READ/WRITE Rights 和失败原子安装。真实 Linux ELF 同时
创建 40 对 pipe，共 80 个端点；每对完成单字节写回读，再全部关闭并继续其余
兼容测试。资源回基线。证据见 `evidence/issue35-pipe-capacity-20261119/`。

### Linux 顺序读取总长度

`read`、`pread64` 和 `readv` 原先各自包含 1 MiB 单次总长度上限，超过时返回
`EINVAL`。该值不是 Linux ABI；现已移除，实际可读量由调用方长度、文件/终端可用
数据、进程 IO、pin 和用户内存预算共同裁决。ashmem 临时缓冲、iovec 表、pin 表和
复制范围表均改用可失败堆准入，分配失败返回 `ENOMEM`。

当前已证明 x86_64 `no_std` 构建和 hardcode inventory `added=0`；尚未取得未修改
Linux 程序单次读取超过 1 MiB 的 UEFI 执行证据，因此该项只记为生产上限移除，
不能替代兼容层产品验收。

`getrandom` 同样的 1 MiB 单次总长度上限已移除。输出缓冲改为调用方长度下的
`try_reserve_exact` 准入，RDRAND、virtio-rng 回退和 flags 语义不变；大请求仍未取得
UEFI 用户态压力证据。

## 验证

```text
cargo check -p jasper-kernel --target x86_64-unknown-none \
  --features compat-syscall-verify
PASS

JASPER_ACCEPT=spot JASPER_CHECKS=compatsyscall \
  bash scripts/accept.sh
accept: SPOT PASS

python3 scripts/check-hardcode-gate.py --self-test
python3 scripts/check-hardcode-gate.py --base HEAD^
python3 scripts/check-hardcode-inventory-ledger.py --check \
  docs/hardcode-inventory-ledger.json
```

## 未完成

- 配置上限的更高容量实现、真实 256/1024 Task 和 65536 Object 压力矩阵；
- poll、signalfd 投递、fanotify、epoll/eventfd/timerfd/pipe 大规模批次、
  sendfile/copy 在真实 Ubuntu/Android 程序中的
  大规模分批、取消和资源回基线；
- 所有固定批次值最终应与 Workload/Profile 资源预算统一，而不是成为跨设备 ABI。
