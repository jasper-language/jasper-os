# Linux 管道动态容量切片

更新时间：2026-11-19。

状态：**Linux 兼容层的默认管道容量与运行期最大容量已经分离；64 KiB 不再
限制 `F_SETPIPE_SZ` 或内核缓冲增长。**

## 语义

- `LINUX_PIPE_DEFAULT_CAPACITY = 64 KiB` 只是新管道和 AF_UNIX socket 的
  兼容 Profile 默认值，由 `linux-pipe-uapi-v1` 登记为 ABI/策略事实；
- 每个管道创建一个由内核实际堆预算派生的 `max_capacity`，该值是运行期准入，
  不是编译期产品上限；
- `F_SETPIPE_SZ` 接受大于 64 KiB 的合法请求；它只发布逻辑容量，实际写入会先
  调用 `try_reserve` 准入所需存储，再向管道追加数据；
- 请求溢出、请求低于 `PIPE_BUF`、新容量小于已缓冲数据或写入时实际存储不足，
  原容量与缓冲内容保持不变，并向 Linux 兼容层返回明确错误；
- `sendfile`、`splice`、`vmsplice` 与 `tee` 的长度上限取自目标/源管道当前
  已准入容量，不再读取固定 64 KiB 常量；
- AF_UNIX socket 的两个方向共同使用连接时的运行时预算；连接双方的默认值和
  单向预算在连接时校验，任一侧分配失败都不会发布半连接状态。

这项改动不会把 Linux 兼容行为推进 Jasper 原生 ABI。管道、`F_SETPIPE_SZ`、
Linux `fcntl` 和 Unix socket 语义仍完全位于可选兼容层。

## 验证

```text
cargo test -p jasper-compat-core
54 passed; 0 failed

cargo check -p jasper-kernel --target x86_64-unknown-none \
  --features compat-syscall-verify
PASS

python3 scripts/check-hardcode-gate.py --inventory
346 findings; runtime-resource-capacity 70 unique fingerprints
```

真实 QEMU 定点验收：

```text
JASPER_CHECKS=compatsyscall JASPER_ACCEPT=spot \
  JASPER_CORES=6-7 JASPER_QEMU_TIMEOUT=240 \
  bash scripts/accept.sh

COMPAT-SYSCALL PASS
qemu_rc=33
evidence/accept-20261119-224502/serial.log
sha256=e247106ec1c060baede44f88c43502c663d969fd40f57c5b0b187287e474e57d
```

该探针在真实 CPL3 Linux ET_EXEC 中把管道从 64 KiB 调整到 128 KiB，并通过
`F_GETPIPE_SZ` 读回；原有 epoll、futex、mmap、io_uring、退出和页帧回收同时
通过。它是单处理器定点验收，不代表全量矩阵。

新增宿主测试覆盖：

- 默认容量仍为 64 KiB，既有 Linux 探针的 `F_GETPIPE_SZ` 预期不变；
- `F_SETPIPE_SZ` 等效路径可提升到 2 MiB 并写入 512 KiB；
- 超过运行期预算的扩容失败且原容量、缓冲数据保持不变；
- 低于 `PIPE_BUF` 的扩容失败且保持事务原子性。

## 尚未完成

- 宿主测试不能替代真实 OVMF/Ubuntu 探针中的大于 64 KiB
  `F_SETPIPE_SZ` 端到端测试；实时 QEMU 探针已覆盖 128 KiB 调整与读回，
  但 2 MiB/512 KiB 写入仍只有宿主测试证据；
- 管道缓冲仍由内核堆分配器准入，尚未形成按进程/Workload 独立计费的管道
  配额；
- 其余 `runtime-resource-capacity` 存量仍需逐项迁移，不能据此关闭 Issue #35。
