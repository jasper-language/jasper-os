# Issue #42 M04：原生 Workload 生命周期与恢复

更新时间：2026-11-21。

状态：**implemented-tested**。关闭原生 task/Workload 身份、成员退出、
资源排空、孤儿处理与同域新 generation 恢复；Linux PID/TID、namespace/cgroup
格式仍由兼容层适配。

## 验证

- `task_lifecycle` 覆盖稳定 task identity、parent retention、typed terminal 和
  stale generation。
- `workload_recovery` 6/6：OOM 候选跨域/root/critical 拒绝、确定顺序与失败原子、
  成员退出不跳过资源或子 Workload、崩溃计划深度优先、恢复要求同域新 key 和旧树
  完全排空。
- 新增 64 个独立 Workload 压力循环：每个成员退出、资源释放前不可发布恢复；
  退出和资源归还后才允许同域 replacement；128 个原/新 Workload 无 key 复用，
  member 表最终归零。
- 完整 CI `44897174802` 的真实 kernel/Process/Workload 路径通过。

## 边界

Linux PID namespace、cgroup v1/v2 文件格式、SIGCHLD/subreaper 和 pidfd ABI 不进入
原生 Workload，继续由兼容层解释。
