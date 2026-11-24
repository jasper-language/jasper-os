# Issue #42 M12：原生定时事件与 tickless 生命周期

更新时间：2026-11-21。

状态：**implemented-tested**。关闭的是 Jasper 原生单调时刻、每核仲裁、
deadline、周期重装和 tickless 停表机制；Linux clock/syscall/POSIX 格式仍在
兼容层。

## 验证

- `timer_event` 5/5：精确/容差仲裁、一次性至多交付、周期相位重装、拥有者
  预算、旧 generation 拒绝、溢出失败、时钟非单调观察、大跨度前进和跨 owner
  关闭隔离。
- `deadline` 边界、差分与穷举模型通过；比较更新、取消、generation 和周期相位。
- `tickless` 13/13：最近期限、除法窗口、tick 消费者、停表/恢复、时间记账、
  稀疏高 CPU 和容量预分配。
- 完整 CI `44897174802` 的真实 1/4/8-CPU 验收通过 RT2、高精度/NOHZ、
  timer progress 和 8-vCPU q35 拓扑。

## 边界

Linux `clock_*`、timerfd、POSIX timer ID/错误码和 ABI 结构不进入内核原生契约。
硬件时钟异常只通过真实平台驱动/中断适配器上报单调时刻；QEMU 结果不替代未完成
的物理时钟源资格。
