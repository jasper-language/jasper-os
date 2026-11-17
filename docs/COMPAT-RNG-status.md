# Linux getrandom 非 RDRAND 熵源状态

更新日期：2026-11-17。

状态：**verified software slice**。该切片关闭 `COMPAT-UBUNTU-1` 中“非 RDRAND
entropy service”缺失的运行时证据，但不把整个 Ubuntu 兼容节点升级为 done。

## 实现

`system.getrandom` 的回退路径现在可以由 `compat-dynamic-libc-verify` 路径构建，
不再只依赖 `lifecycle-root-exec-verify`。验收专用特性 `compat-rng-force` 会刻意
忽略 CPU 的 RDRAND 结果，强制未修改的 glibc `getrandom()` 调用进入
`compat_rng::fill()`：

- `getrandom` 请求仍受 1 MiB 上限和合法 flags 检查；
- virtio-rng 队列有界，单次请求最多使用固定 64 字节设备缓冲区；
- used-ring 轮询同时受 tick 和自旋次数上限；
- 设备失败时关闭 bus-master、reset 队列并使后续请求失败关闭；
- 成功时由未修改的 Ubuntu glibc fixture 检查两次 32 字节结果非零且不相同。

## 验证

```text
bash scripts/compat-pthread-sample.sh
compat-pthread: PASS cpus=1

COMPAT_PTHREAD_CPUS=4 bash scripts/compat-pthread-sample.sh
compat-pthread: PASS cpus=4
```

验收要求串口同时出现：

```text
[JSR-COMPAT-RNG] source=virtio-rng forced=true ...
[JSR-COMPAT-PTHREAD] ... exit_zero=true ... resources=true failed=0
```

这证明 QEMU 虽提供 RDRAND，验收仍真实使用了 virtio-rng 回退。它不替代 Linux
熵池初始化语义、阻塞/非阻塞池状态转换、跨重启熵持久性或完整文件/网络/设备
兼容矩阵。
