# Linux vfork, external exec and orphan reaping

更新日期：2026-11-17。

状态：**verified software slice**。完整 `COMPAT-UBUNTU-1` 仍由 glibc/Bionic、
文件、网络、设备与 Wine 等后续矩阵共同决定，不能因本切片升级为 done。

## 新增验收

未修改的 Ubuntu 26.04 glibc 动态程序现在执行以下完整路径：

1. `fork()` 创建中间进程；
2. 中间进程调用 `vfork()`；
3. vfork 子进程用 `execve()` 重新运行同一个未修改动态 ELF；
4. 中间进程在 exec 提交后退出，子进程成为 `ppid=0` 的兼容根孤儿；
5. 子进程确认收养完成、写入完成标记并以 0 退出；
6. 原父进程不能消费孤儿的退出状态，资源通过统一清理路径回收。

验收同时要求真实 `SCHED_FLAG_RESET_ON_FORK` 可以设置、回读和清除，并要求
`CLOCK_REALTIME` 使用可信 RTC 的 1 秒分辨率。

## 运行时证据

```text
ISSUE21_UEFI_MODE=root-exec
issue21-uefi-boot: PASS mode=root-exec qemu_rc=33
```

证据：`evidence/ubuntu-orphan-vfork-20261117-r20/`。

关键输出：

```text
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
jasper-orphan-vfork-ok
[JSR-LIFE-ROOT-DYNAMIC] program=usr/bin/jasper-getppid ... exit_zero=true ... resources=true failed=0
[JSR-LIFE-HEALTH] result=root_execution_complete
```

## 同步修复

- 进程线程注册表和用户页固定诊断表在 capacity 阶段预分配，避免首次用户
  spawn/buffer 在资源基线建立后隐式增长内核堆；
- `first_program` 对只增不缩的内核堆按映射增长量做精确对账，同时要求堆内
  活跃字节数不高于基线；
- 健康探针的能力集合与其实际 syscall 行为对齐，`getppid` 继续明确拒绝；
- `SCHED_FLAG_RESET_ON_FORK` 缺失时现在表示清除，不再错误继承旧值；
- `clock_getres(CLOCK_REALTIME)` 报告可信 RTC 的 1 秒分辨率。
