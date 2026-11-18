# Issue #35 Linux FD 动态容量切片

更新时间：2026-11-18。

状态：**软件高位 FD 与运行时预算切片通过；完整 Linux 用户态高位压力运行仍待
纳入兼容层验收。**

## 本切片

- 删除 `MAX_FDS=1024` 和生产 `FdTable<64>` 编译期数组；
- `FdTable` 改为堆后备的懒增长槽位、generation 与 shared open-file description
  三列，只增长到实际使用的最小编号包络；
- 每张表携带运行时 soft/hard limit，初值由进程页帧预算推导，
  `setrlimit(RLIMIT_NOFILE)` 更新同一许可边界，不再维护第二份固定上限；
- `close_range` 只扫描已分配包络与 soft limit 的交集，不会因
  `RLIMIT_NOFILE=UINT_MAX` 遍历数十亿空槽；
- 关闭低号 fd 会恢复 lowest-free 分配语义；高号 fd 关闭后保留 generation，
  旧 `FdHandle` 不能复活；

## 验证

```text
cargo test -p jasper-compat-core fd -- --nocapture
13 passed; 0 failed

cargo check -p jasper-kernel --target x86_64-unknown-none \
  --features compat-syscall-verify
PASS
```

覆盖 fd 2048、运行时 limit 拒绝、limit 扩展、lowest-free 复用、shared
open-file description、fork clone、CLOEXEC/exit close、STALE generation、权限无法
提升及元数据预算估算。

硬编码存量审计从 437 个候选降为 436 个，新增候选为 0。

## 尚未完成

- 进程初始 FD 预算仍由现有 `MAX_PROCESS_FRAMES` 显式内存政策换算；后续应把
  它接入最终的 Workload/Profile 资源预算，而不是依赖旧的进程常量；
- 尚未在真实 Linux 夹具中创建并操作编号 >1024 的 fd、执行
  `close_range(0, UINT_MAX)` 和 fork/exec 后高位回收；
- SysV shm、ION、ashmem/memfd 与设备 BAR 的固定上限仍按 HC-A08 逐项裁决。
