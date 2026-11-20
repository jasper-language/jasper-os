# Issue #42 原生用户态 Pager 状态机

更新时间：2026-11-20。

状态：**native state-machine slice passed**。新增 `kernel-core::fault_pager`，
用于收口 M-04 的授权、请求、递归缺页、处理者死亡、超时、撤销和两阶段页表裁决
语义。本切片不是新用户 ABI，也不表示页表接线或 Android userfaultfd 已完成。

## 边界

- Pager 权限从既有 active `MemoryCapability` 派生，绑定 backing identity、
  capability id、epoch、对象范围和 READ/WRITE 权限，不创建第二套对象或权限根；
- 缺页访问使用 Jasper 原生 `Read/Write/Execute`，不编码 Linux page-fault 标志、
  errno、fd 或 userfaultfd 操作码；
- `FaultEvent` 以 backing identity 与页偏移为稳定身份，并绑定 faulting task；
- handler 使用既有 `Token` 的槽位代际识别；处理者死亡后旧 generation 和未完成
  resolution permit 永久失效；
- 请求队列使用调用方显式 `FaultPager<N>` 容量，不存在隐藏队列上限；
- 模块不修改页表。处理者必须取得唯一 `ResolutionPermit`，由真实调用方安装页表、
  完成安全检查或拒绝访问，然后调用 `complete`；
- 页表安装失败时调用 `abort_resolution`，原请求保留并可重试；撤销或处理者死亡
  会清除所有旧请求。

## 已覆盖的故障语义

- 非 active capability、权限不足、错误 backing、错误页偏移和未对齐页失败关闭；
- 同一页只发布一个 final-page decision；重复缺页返回已有事件 ID；
- pager handler 自己访问自己负责的缺失页返回 `RecursiveFault`，防止确定性自锁；
- 队列满、事件 ID 耗尽和已过期 deadline 不发布部分状态；
- 同一时刻只允许一个页表裁决；permit 重复完成、旧 permit、错误 handler 均拒绝；
- abort 后可重试，complete 只消费一次；
- handler exit 使旧 permit 失效并清空全部归属请求；新 handler 必须用仍然匹配的
  live capability 重新绑定；
- capability epoch 或 backing 改变后 `reauthorize` 失败；精确 capability/epoch
  撤销原子清除请求和裁决权；
- 已开始页表裁决的事件不会被普通 cancel/expire 抢走终态。

## 验证

```text
cargo test --locked -p kernel-core fault_pager --lib
7 passed; 0 failed
```

## 尚未关闭

- 尚未接入真实 Process/MemoryObject 临界区、页表安装、TLB shootdown 和调度停车；
- 尚无 compat 关闭后的原生 CPL3 多处理器缺页压力、重映射、对象撤销、任务退出和
  公平性证据；
- userfaultfd 只可作为后续兼容适配；本状态机不会把其协议写入内核 ABI；
- MemoryWorkloadRecovery、可丢弃页、回写和内存压力策略未在本切片中定义；
- Issue #42 的 FS/NET/device/graphics 后端静止、完整 syscall disposition 和原生
  Profile 全链路仍未完成。
