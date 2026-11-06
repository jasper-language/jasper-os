# issue #1 进度：SyscallSet、spawn 授权 ABI 与用户运行时能力集合

更新日期：2026-11-06
状态：第一、第二切片已实现并通过定点编译 / 宿主测试 / x86_64 QEMU 验收；Jasper 语言侧的显式构造、保留 ABI 和高编号操作仍未完成，issue #1 尚未整体关闭。

## 一、问题与切片边界

旧实现把任务可发起的操作集合写成 `pub struct SyscallSet(pub u64)`：

* `of()` 只是 `if id < 64` 才置位，ID ≥ 64 被**静默丢弃**；
* `contains()` 对 ID ≥ 64 恒为 `false`；
* `system.process.spawn` 的参数块 `SpawnDesc.calls` 也是 `u64`，`spawn_abi::check` 的
  `caller` / `known` 同样是 `u64`；
* 系统调用分发表在 `has_handler()` 与 `execute()` 中各写一份操作清单，新增操作时可能漂移。

本切片只做第一组可独立验收的改动：

1. 新的权威能力集合（`kernel-core::syscall_set::SyscallSet`）及其不变量测试；
2. `system.process.spawn` 参数块 v2（88 字节）接入这条真实路径，保持
   `child ⊆ parent`、未知操作拒绝、格式非法拒绝、全有或全无；
3. 登记表 → 生成常量 → 分发表 → 启动自检的单源一致性；
4. 中英文代码注释、性质登记与本文档。

本切片**没有**做：把登记表扩到 256 个以上操作、Jasper 语言侧能力集合 API、
`system.task.syscalls.set` 等保留 ABI 的重新启用、全量性能基准。这些在第五节按切片列出。

## 二、权威数据结构

`kernel-core/src/syscall_set.rs`：

| 项目 | 取值 |
|---|---|
| 表示 | 4 个 `u64` 的定长位图（`#[repr(transparent)]`） |
| 有效 ID | `0..=255`（`MAX_IDS = 256`） |
| 结构大小 | 32 字节 |
| 序列化 | 32 字节，小端，逐字固定顺序 |
| 分配 | 无堆分配、无锁、无系统调用 |
| `contains(id)` | 1 次 `u64` 比较 + 1 次数组下标 + 1 次移位测试 |
| `union` / `intersection` / `difference` / `is_subset_of` | 固定 4 次字运算 |
| 越界 ID | `try_of` / `from_id` 返回 `None`；受信任静态表 `of` 在越界时 panic（编译期常量越界即构建失败） |

唯一语义：位 i 为 1 ⇔ 操作 ID i 被授予。不存在第二种解释、影子 `u64` 通道或调用点特殊规则。
`contains` 接收 `u64`（系统调用寄存器宽度），越界返回 `false`；调用点先查登记表，未登记 ID
得到 `system.error.unsupported`，不会与「未授权」混淆。

### 方案对比

| 方案 | 结构大小 | 授权开销 | 最坏情况 | 序列化 | 内存预算 | 结论 |
|---|---|---|---|---|---|---|
| 旧 `u64` | 8 B | 1 次移位 | ID ≥ 64 静默失效 | 8 B | 极小 | 不满足 issue #1 |
| 定长位图（本切片，256 位） | 32 B | 1 次边界比较 + 下标 + 位测试 | 固定 4 字；无循环、无分配 | 32 B | 每任务 +24 B；512 任务约 +12 KiB | **采用** |
| 分段集合（`Vec<u64>` / 稀疏段） | 24 B + 堆块 | 查找段（最坏 O(段数)）或二分 | 分配失败、段表增长、热路径分支 | 变长 + 长度字段 | 按实际授权数增长，但每个任务多一次分配 | 当前规模不值得复杂度 |
| 能力表 / 链表 | 每能力一项 | 最坏 O(能力数) 遍历 | 分配失败、部分插入、回收路径 | 需要显式长度与校验 | 授权少时省，授权多时更贵 | 与「统一权限检查」热路径不符 |

选择定长位图的理由：当前最高登记 ID 为 55，256 位有 4.6 倍余量；热路径可预测；
失败模式只有「越界显式拒绝」；没有分配失败路径可被恶意参数触发。若登记表逼近 255，
把 `MAX_IDS` / `WORDS` 一起提高即可（生成器会重新校验），语义不变；不保留旧宽度通道。

### 32/64 位 ABI 与内存预算

* 序列化单位固定为 8 字节 `u64`，不使用 `usize`，因此 32 位与 64 位目标上的字节布局相同。
* `HandleId` 等既有 64 位字段不变；能力位图独立于指针宽度。
* 32 位目标上一次 64 位字运算由编译器展开为两条 32 位指令，仍是固定 4 字，无循环。
* 任务控制块增加 24 字节（8 → 32）；`SpawnDesc` 从 56 → 88 字节（冷路径，每进程创建一次）。
* 无堆分配 ⇒ 没有「分配失败导致部分授权」的路径。

## 三、spawn 授权协议 v2

`kernel-core/src/spawn_abi.rs` 的参数块：

| 偏移 | 大小 | 字段 |
|---|---|---|
| 0 | 4 | `magic = JSP2` |
| 4 | 2 | `version = 2` |
| 6 | 2 | `size = 88` |
| 8 | 8 | `image_ptr` |
| 16 | 8 | `image_len` |
| 24 | 32 | `calls`（4 个小端 `u64`） |
| 56 | 8 | `arg` |
| 64 | 4 | `cpu_limit_permille` |
| 68 | 4 | `flags`（必须为 0） |
| 72 | 8 | `out_process`（内核写回） |
| 80 | 8 | `out_channel`（内核写回） |

规则与拒绝顺序：

1. `magic` / `version` / `size` 不匹配 ⇒ `Format`（旧 56 字节布局、截断或伪造调用者被拒）；
2. `flags != 0` ⇒ `Reserved`；
3. 映像为空或超过 2 MiB ⇒ `ImageSize`；
4. 请求位不在登记集合中 ⇒ `UnknownCall`；
5. 请求位不在调用者集合中 ⇒ `Escalation`（`child ⊆ parent`）；
6. CPU 上限越界 ⇒ `CpuLimit`。

这些检查全部发生在改动任何状态之前；失败不会创建子进程、不会占用配额、不会发放句柄。
`decode` 先验头部，`check` 再验一次（防止调用方直接构造结构体绕过解码）。
用户运行时 `jasper-rt` 的 `Spec::calls` 转换为同一 `SyscallSet`，超出容量按参数非法拒绝。
`abi/system-ids.txt` 中 `system.process.spawn` 的主版本从 1 升到 2，标明参数块不兼容；
`abi/system-ids.lock` 保留已发布 v1 的身份记录（构建期只比对 ID/种类/名字），不保留 v1 影子解析路径。

## 四、登记表、分发与自检的单源化

* `kernel/build.rs` 读取 `abi/system-ids.txt` 后：
  * 校验每个操作 ID `< MAX_IDS`，越界直接构建失败；
  * 生成 `REGISTERED_OPS`、`REGISTERED_OPS_SET`、`MAX_REGISTERED_OP_ID`。
* `kernel/src/syscall/mod.rs` 用一次 `syscall_dispatch!` 展开同时生成：
  * `execute()` 的 `match`；
  * `IMPLEMENTED` 能力集合。
* 编译期断言：
  * `IMPLEMENTED ⊆ REGISTERED_OPS_SET`；
  * `IMPLEMENTED.count() == REGISTERED_OPS.len()`。
  两者合起来 ⇒ 分发表与登记表**完全相等**。「登记了却没实现」或「实现了却没登记」都会
  使内核编译失败，不再依赖两份手工清单。
* 启动自检 `syscall::self_check()` 仍逐条核对并输出 `ops=55 handlers=all`，同时检查
  ID 63/64/127/255 可表示、256 被显式拒绝。

## 五、对照 issue #1 验收条目

| issue #1 验收条目 | 本切片状态 | 证据 |
|---|---|---|
| ID 63、64、127 及更高有效编号的授权/拒绝确定测试 | 已满足（位图；spawn 子集授权/拒绝；255 边界） | `syscall_set` 与 `spawn_abi` 宿主测试 |
| 高编号不能被静默忽略 | 已满足：`try_of` 越界返回 `None`，`of` 越界 panic，启动自检拒绝 256 | 单元测试 + 启动日志 |
| 子集性质 | 已满足：`is_subset_of` 四字检查；spawn 4 位穷举 | `spawn_check_subset_exhaustive_small` 等 |
| 未知操作拒绝 | 已满足：请求位 ∉ 登记集合 ⇒ `UnknownCall` | `spawn_check_rejects_each_rule` |
| 恶意参数 | 已满足：magic/version/size/flags/映像/CPU 上限；解码前无副作用 | `spawn_desc_rejects_foreign_or_truncated_header` |
| 容量上限 | 已满足：255 可用、256 显式拒绝 | `capacity_boundary_is_explicit` |
| 分配失败 | 结构无堆分配；不存在部分授权路径 | 设计约束 + 代码审查 |
| 32/64 位布局 | 序列化固定 `u64`；32 字节结构断言；i686 目标编译通过（未在 32 位宿主运行全部用例） | `bit_63_64_127_are_distinct_and_visible`；`cargo test -p kernel-core --target i686-unknown-linux-musl --no-run` |
| ABI 声明与实现映射一致 | 已满足：生成常量 + 编译期断言 + 启动自检 | `REGISTERED_OPS_SET` / `self_check` |
| 性能基准无意外回退并记录原始数据 | **未在本切片完成**：热路径仍为固定次数位运算；完整基准留给集成轮 | 见第六节第 4 项 |

六步验证链（同一源码哈希一次跑完，脚本 `verification/toolbox/run-issue1-syscall-set-suite.sh`）：

| 步 | 工具 | 结果 |
|---|---|---|
| ① | Verus/Z3 | 正例 37 verified / 0 errors；负例（只比较第一个字，即旧 `u64` 缺陷）按预期失败 |
| ② | Proptest | 3 个性质对照 `BTreeSet` 参考模型全部通过 |
| ③ | Miri | kernel-core 13 项 + 多级 spawn 固定链 1 项，无未定义行为 |
| ④ | cargo-fuzz | `spawn_desc` 目标 200000 次无崩溃 |
| ⑤ | Kani | 7 个生产代码 harness 全部 VERIFICATION SUCCESSFUL |
| ⑥ | Loom | N/A：集合是无共享状态的值类型、准入为纯函数；以 QEMU 真实 spawn 断言替代 |

定点验收结果（x86_64，单处理器）：

* `cargo test -p kernel-core`：`483 passed; 0 failed`（另有集成/文档测试全部通过）；
* `cargo test -p kernel-core --target i686-unknown-linux-musl --no-run`：32 位目标编译通过；
* x86_64 裸机编译成功；
* QEMU 定点检查 `m11 m32 j6`：全部 PASS；启动日志
  `[JSR-SYSCALL] self_check ops=55 handlers=all`；
* QEMU 退出码 37（仅计时类断言超界，功能全过；BM-0 分层验收的既定语义）。

## 六、剩余工作（按可独立验收的切片）

1. **容量演进**：当登记表最高 ID 接近 255 时，提高 `MAX_IDS` / `WORDS` 并同步
   `SpawnDesc` 大小；同时补 32 位目标上的单元测试轮次。
2. **用户运行时 API**：Rust 运行时部分已完成（见第八节）；Jasper 语言侧的对应构造仍未完成。
3. **保留 ABI**：`system.task.syscalls.set`、扩展能力等目前仍返回 `unsupported`；
   若启用，必须复用同一个 `SyscallSet`，不得引入第二套授权通道。
4. **性能证据**：把系统调用权限检查、spawn 解码与任务切换的集合复制纳入 T-2 基准，
   记录 `u64` 与 256 位位图的原始样本，确认没有显著非预期回退。
5. **更多真实调用者**：为 CPL3 用户程序增加高编号操作（≥64）的端到端用例；
   本切片已验证参数块与位图，但登记表中尚无 ID ≥ 64 的操作可供真实调用。
6. **AArch64 仅编译**：本轮按要求不为 AArch64 写代码或跑验收；其构建由集成轮确认。

## 七、改动文件

* `kernel-core/src/syscall_set.rs`（新增）：权威能力集合与不变量测试；
* `kernel-core/src/spawn_abi.rs`：参数块 v2、头部校验、集合化规则与高编号测试；
* `kernel-core/src/lib.rs`：导出新模块；
* `kernel/build.rs`：容量校验与 `REGISTERED_OPS` / `REGISTERED_OPS_SET` 生成；
* `kernel/src/syscall/mod.rs`：复用 `SyscallSet`、宏单源分发表、编译期断言、自检；
* `kernel/src/proc/spawn.rs`：接入新参数块与登记集合；
* `user/rt/src/process.rs`：运行时能力集合转换；
* `user/ring/src/main.rs`：真实 CPL3 参数块构造；
* `abi/system-ids.txt`：`system.process.spawn` 主版本升到 2；
* `verification/check-abi-reservations.py`：容量上限改读 `MAX_IDS`，并识别单源分发表；
* `verification/PROPERTIES.md`：性质登记条目。

## 八、用户运行时显式能力集合 API（第二切片）

`jasper-rt::process::Spec::calls` 不再保存 `&[u64]`，改为值类型
`jasper_rt::process::CallSet`。真实调用者先显式构造能力集合，再把同一个值放入 spawn 参数：

```rust
let calls = jasper_rt::process::CallSet::try_from_ids(&[
    jasper_rt::ids::SYSTEM_PROCESS_EXIT,
    jasper_rt::ids::SYSTEM_TIME_WAIT,
])?;

let child = jasper_rt::process::spawn(jasper_rt::process::Spec {
    image,
    calls,
    arg: 0,
    cpu_limit_permille: None,
})?;
```

### 唯一集合语义

* `CallSet` 的私有字段是 `kernel_core::syscall_set::SyscallSet`，没有自己的位图、长度字段、
  序列化器或授权判定；spawn 直接把该内核集合写入既有 88 字节 v2 参数块。
* 构造输入仍使用寄存器宽度的 `u64`，不会把大于 `u32` 的值截断。任一 ID 满足以下条件即整体拒绝：
  * `OutOfRange`：ID 不小于 `MAX_IDS`（含 `u64::MAX`）；
  * `Unknown`：ID 不在 `abi/system-ids.txt` 生成的 `REGISTERED_CALLS` 中；
  * `Duplicate`：同一 ID 在输入中出现超过一次。
* `try_insert` 只在成功时替换内部集合；失败后集合内容和长度保持不变。
* 内核原有的 `child ⊆ parent`、未登记调用拒绝、映像/CPU/保留字段检查和全有或全无语义没有变化。
  用户运行时拒绝非法构造，内核仍独立执行最终授权检查，用户侧 API 不是新的可信授权点。

隔离模块的容器调用集合也改用 `CallSet`：先严格装入 `CONTAINER_CALLS`，再逐个合并清单声明的
登记系统调用。原先临时 `Vec<u64>` 只在构造阶段存在，不再穿过 spawn API。

### 验证证据

| 层 | 命令 / 位置 | 结果 |
|---|---|---|
| 单元 | `cargo test -p kernel-core syscall_set` | 8 passed / 0 failed；新增重复、未知、越界与失败不变测试 |
| 属性 | `cargo test --manifest-path verification/toolbox/Cargo.toml --test syscall_set` | 4 passed / 0 failed；严格构造对照独立 `BTreeSet` 参考模型 |
| Miri | `cargo +nightly miri test -p kernel-core --lib -- syscall_set::` | 8 passed / 0 failed |
| 编译 | `cargo build --release --target x86_64-unknown-none -p user-isohost` | 通过 |
| QEMU 契约 | `JASPER_ACCEPT=spot JASPER_CHECKS=j6 ... bash scripts/accept.sh`（共享 QEMU 锁内） | J-6 功能与计时项 PASS；`case=isohost exit=Some(0)`、`checks=43`、`reclaimed=true`；QEMU 退出码 37 仅计时类参考项超界 |

QEMU 串口同时出现
`isohost: calls duplicate_rejected=true unregistered_rejected=true out_of_range_rejected=true insert_atomic=true`
与原有的 spawn 越权拒绝、非法映像拒绝、配额和回收标记。

本切片未修改 `system.process.spawn` 参数块布局，也未登记或启用任何高编号 / 保留操作。
