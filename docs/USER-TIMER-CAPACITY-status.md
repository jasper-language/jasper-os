# 原生用户定时器容量切片

更新时间：2026-11-19。

状态：**固定 256 个用户定时器上限已移除；coalescer 元数据由启动期对象预算
一次性预留。**

## 实现

- `kernel/src/user_timer.rs` 的 allocated、registration、deadline entry 和 heap
  position 表改为堆后备 `Vec`；
- 容量不再来自独立 256 常量，而是使用 `bootcap::validate()` 已批准的
  `objects` 容量；
- `Capacity` 启动阶段在任何用户运行时和 secondary CPU 之前调用
  `user_timer::init_runtime(cap.objects)`，一次完成全部预分配；
- 分配失败明确拒绝启动，不发布部分表；
- `sys_create` 仍在对象表允许范围内分配；唯一 ID 溢出或对象创建失败会回滚
  coalescer slot 与 live 计数；
- arm/cancel/close/wake 热路径不再扩容，只访问已发布表。

该容量与进程/Workload 的对象配额仍由既有对象表准入决定；本切片没有引入新的
定时器 ABI 或第二套配额体系。

## 验证

```text
cargo check -p jasper-kernel --target x86_64-unknown-none \
  --features compat-syscall-verify
PASS

python3 scripts/check-hardcode-gate.py --inventory
345 findings; runtime-resource-capacity 69 unique fingerprints
```

真实 QEMU 定点验收：

```text
JASPER_CHECKS=j1 JASPER_ACCEPT=spot JASPER_CORES=6-7 \
  JASPER_QEMU_TIMEOUT=240 bash scripts/accept.sh

J-1 PASS
qemu_rc=37 (functional PASS; timing-class exit policy)
evidence/accept-20261119-225353/summary.txt
serial_sha256=62ec92c51da57ce9d77058ad2bd7a55eba277ad67f0c1ed792c58ad0a067877a
```

## 尚未完成

- 真实 QEMU J-1 定点已通过，但全量矩阵尚未在本提交完成后运行；
- 定时器对象仍受对象表总预算约束，尚需专门验证大量 armed/waiting timers 的
  调度延迟、取消竞争和资源回收矩阵；
- 其余运行期容量条目仍未清零，Issue #35 保持未完成。
