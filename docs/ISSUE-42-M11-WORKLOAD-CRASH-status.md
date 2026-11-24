# Issue #42 M11：层级 Workload 与崩溃编排

更新时间：2026-11-21。

状态：**implemented-tested**。原生 Workload/Sandbox 提供层级限额、聚合账务、
成员退出和有序崩溃恢复；Linux namespace/cgroup 与 NT Job API 仍是兼容语义。

## 验证

- `workload_recovery` 7/7：OOM、成员退出、崩溃计划、恢复和对象生命周期。
- 新增 64 个直接成员 Workload 的树局部崩溃计划：计划固定为 65 个目标，64 个
  子 Workload 先于 root，每个子级保留自身 member 计数并进入 Failed 终态。
- 失败原子验证确保没有任何子 Workload 被跳过后 root 才失败。
- `WorkloadTable`/Sandbox 既有测试覆盖父子 CPU 承诺、聚合内存/线程/ring 账务、
  预算不放大、成员退出、资源未排空不得 Stopped。

## 边界

namespace、mount、cgroup v1/v2 文件、rlimit 数字模型和 NT Job API 不进入原生
Workload。它们由兼容层映射到稳定的 WorkloadKey/generation、统一资源和安全域。
