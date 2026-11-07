# issue #1 进度：SyscallSet、spawn 授权 ABI 与用户运行时能力集合

更新日期：2026-11-07
状态：SyscallSet、spawn 授权、Rust 用户运行时和 `system.task.syscalls.set` 均已实现并通过 32/64 位宿主测试与真实 x86_64 CPL3 验收；Jasper 语言侧的显式构造仍未完成，issue #1 尚未整体关闭。

## 一、问题与切片边界

旧实现把任务可发起的操作集合写成 `pub struct SyscallSet(pub u64)`：

* `of()` 只是 `if id < 64` 才置位，ID ≥ 64 被**静默丢弃**；
* `contains()` 对 ID ≥ 64 恒为 `false`；
* `system.process.spawn` 的参数块 `SpawnDesc.calls` 也是 `u64`，`spawn_abi::check` 的
  `caller` / `known` 同样是 `u64`；
* 系统调用分发表在 `has_handler()` 与 `execute()` 中各写一份操作清单，新增操作时可能漂移。

第一切片完成第一组可独立验收的改动：

1. 新的权威能力集合（`kernel-core::syscall_set::SyscallSet`）及其不变量测试；
2. `system.process.spawn` 参数块 v2（88 字节）接入这条真实路径，保持
   `child ⊆ parent`、未知操作拒绝、格式非法拒绝、全有或全无；
3. 登记表 → 生成常量 → 分发表 → 启动自检的单源一致性；
4. 中英文代码注释、性质登记与本文档。

第一切片**没有**做：把登记表扩到 256 个以上操作、Jasper 语言侧能力集合 API、
`system.task.syscalls.set` 等保留 ABI 的重新启用、全量性能基准。第二切片补了 Rust 用户运行时
`CallSet`，第三切片补了真实 ID 64 的 CPL3 端到端路径；语言侧和保留 ABI 仍按后续切片处理。

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

选择定长位图的理由：当前最高登记 ID 为 64，256 位有 4 倍余量；热路径可预测；
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
* 启动自检 `syscall::self_check()` 仍逐条核对并输出 `ops=57 handlers=all`，同时检查
  ID 63/64/127/255 可表示、256 被显式拒绝。

## 五、对照 issue #1 验收条目

| issue #1 验收条目 | 本切片状态 | 证据 |
|---|---|---|
| ID 63、64、127 及更高有效编号的授权/拒绝确定测试 | 已满足；ID 64 是已登记真实操作并在 CPL3 成功/拒绝路径执行 | 32/64 位单元测试 + `user/isohost` QEMU 契约 |
| 高编号不能被静默忽略 | 已满足：`try_of` 越界返回 `None`，`of` 越界 panic，启动自检拒绝 256 | 单元测试 + 启动日志 |
| 子集性质 | 已满足：`is_subset_of` 四字检查；spawn 4 位穷举 | `spawn_check_subset_exhaustive_small` 等 |
| 未知操作拒绝 | 已满足：spawn 参数块非登记位 ⇒ `UnknownCall`；CPL3 原始 ID 255 ⇒ `unsupported` | `spawn_check_rejects_each_rule` + `user/isohost` |
| 恶意参数 | 已满足：magic/version/size/flags/映像/CPU 上限；解码前无副作用 | `spawn_desc_rejects_foreign_or_truncated_header` |
| 容量上限 | 已满足：255 可用、256 显式拒绝 | `capacity_boundary_is_explicit` |
| 分配失败 | 结构无堆分配；不存在部分授权路径 | 设计约束 + 代码审查 |
| 32/64 位布局 | 已满足：序列化固定 `u64`；ID 64 字边界断言在 x86_64 与 i686 实跑 | 两目标各 544 passed；`high_id_64_serialization_is_target_width_independent` |
| ABI 声明与实现映射一致 | 已满足：生成常量 + 编译期断言 + 启动自检 | `REGISTERED_OPS_SET` / `self_check` |
| 性能基准无意外回退并记录原始数据 | **未在本切片完成**：热路径仍为固定次数位运算；完整基准留给集成轮 | 见第六节第 4 项 |

六步验证链（同一源码哈希一次跑完，脚本 `verification/toolbox/run-issue1-syscall-set-suite.sh`）：

| 步 | 工具 | 结果 |
|---|---|---|
| ① | Verus/Z3 | 正例 37 verified / 0 errors；负例（只比较第一个字，即旧 `u64` 缺陷）按预期失败 |
| ② | Proptest | 5 项（3 个随机性质 + 2 个固定高编号链）全部通过 |
| ③ | Miri | kernel-core 16 项 + 多级 spawn 固定链 1 项，无未定义行为 |
| ④ | cargo-fuzz | `spawn_desc` 目标 200000 次无崩溃，cov 101 / ft 106 |
| ⑤ | Kani | 本轮按发版规则未运行；既有 7 个生产 harness 证据保留在原提交 |
| ⑥ | Loom | N/A：集合是无共享状态的值类型、准入为纯函数；以 QEMU 真实 spawn 断言替代 |

定点验收结果（x86_64，单处理器）：

* `cargo test -p kernel-core`：544 passed / 0 failed（另有集成/文档测试全部通过）；
* `cargo test -p kernel-core --target i686-unknown-linux-musl --lib`：32 位目标 544 passed / 0 failed；
* x86_64 裸机编译成功；
* QEMU 定点检查 `m32 j6`：全部 PASS；启动日志
  `[JSR-SYSCALL] self_check ops=57 handlers=all`；真实宿主与子进程均出现
  `system.sync.mutex.try.acquire id=64 ret=0`；
* QEMU 退出码 37（仅计时类断言超界，功能全过；BM-0 分层验收的既定语义）。

## 六、剩余工作（按可独立验收的切片）

1. **容量演进**：当登记表最高 ID 接近 255 时，提高 `MAX_IDS` / `WORDS` 并同步
   `SpawnDesc` 大小；同时补 32 位目标上的单元测试轮次。
2. **用户运行时 API**：Rust 运行时部分已完成（见第八节）；Jasper 语言侧的对应构造仍未完成。
3. **保留 ABI**：`system.task.syscalls.set` 已按第十一节启用；其余预留操作仍返回
   `unsupported`。后续扩展能力必须复用同一个 `SyscallSet`，不得引入第二套授权通道。
4. **性能证据**：把系统调用权限检查、spawn 解码与任务切换的集合复制纳入 T-2 基准，
   记录 `u64` 与 256 位位图的原始样本，确认没有显著非预期回退。
5. **AArch64 仅编译**：本轮按要求不为 AArch64 写代码或跑验收；其构建由集成轮确认。

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
* `kernel/src/user_mutex.rs`、`abi/system-ids.txt`：ID 64 非阻塞取得操作与 busy 错误；
* `user/rt/src/sync.rs`、`user/isohost/src/main.rs`：真实运行时调用人和权限边界验收；
* `modules/probe`、`kernel/src/rt_demo.rs`、`scripts/accept.sh`：spawn 子进程继承与 CPL3 串口契约。

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

第二切片未修改 `system.process.spawn` 参数块布局，也未登记或启用任何高编号 / 保留操作。

## 九、真实 CPL3 高编号操作（第三切片）

### 操作与语义

新增 `system.sync.mutex.try.acquire`，稳定 ID 为 **64**，恰好位于能力位图第二个 `u64` 字的第 0 位。
它复用既有继承互斥对象、Handle/Rights 和 `SyscallSet` 权限检查，没有新增授权通道：

* 未持有或旧持有者已死亡：按既有所有权引用规则取得对象，返回 0；
* 当前任务已持有：返回 `system.error.invalid_argument`，不把它伪装为递归成功；
* 其他活动任务持有：返回新增的 `system.sync.error.busy`（ID 4137），不修改对象或引用计数；
* 对象已关闭：返回取消错误；句柄类型或权限不符仍返回既有句柄错误。

`jasper-rt::sync::PriorityMutex` 是真实运行时调用人：`try_lock` 直接发 ID 64，只把
`busy` 映射为 `Ok(false)`，其他错误原样返回。操作编号 57..63 保持未分配，以便真实操作落在字边界，
同时让测试能区分“容量内未登记”与“已登记高编号”。

### 端到端覆盖

1. 获得 ID 64 的 `isohost` 宿主通过运行时创建互斥对象，成功尝试取得、拒绝递归并释放；
2. 隔离模块清单声明同一操作，`system.process.spawn` v2 把包含第二个字位 0 的集合交给子进程；
   串口 spawn 日志显示 `calls=[..., 1, 0, 0]`；
3. 子进程在宿主持有时得到 `busy`，宿主释放后成功取得、拒绝递归并释放；
4. 未获 ID 64 授权的第二个真实进程直接调用得到 `rights_denied`；
5. 同一进程经 spawn v2 试图把 ID 64 授予子进程，在创建对象前得到 `rights_denied`；
6. 子进程调用未登记 ID 255 得到 `unsupported`，证明登记检查先于权限检查；
7. 两个进程退出后内核对象、帧和固定计数全部回到基线。

### 验证证据

| 层 | 命令 / 位置 | 结果 |
|---|---|---|
| 64 位宿主单元/属性 | `cargo test -p kernel-core` | 544 passed / 0 failed |
| 32 位宿主单元/属性 | `cargo test -p kernel-core --target i686-unknown-linux-musl --lib` | 544 passed / 0 failed |
| 六步链 | `verification/toolbox/run-issue1-syscall-set-suite.sh`（步骤 1/2/3/4/6） | Verus 37/0 + 负例按预期失败；Proptest 5/0；Miri 16+1；fuzz 200000 次 cov101；Loom N/A；Kani 发版时验证 |
| 真实 QEMU | 共享锁内 `JASPER_ACCEPT=spot JASPER_CHECKS='m32 j6' bash scripts/accept.sh` | `accept-20261107-034359`：M3.2、J-6、J-6 计时均 PASS；`case=isohost` 与 `case=isohost-high-id-denied` 均退出 0，资源回基线 |

QEMU 串口关键行：

```text
[JSR-SYSCALL] self_check ops=57 handlers=all
[JSR-PROC] ... calls=[800000003bc0d6, 1, 0, 0] ...
[JSR-SYSCALL] exit name=system.sync.mutex.try.acquire id=64 task=spawned ret=-4137 status=system.sync.error.busy
[JSR-SYSCALL] exit name=system.sync.mutex.try.acquire id=64 task=spawned ret=0 status=OK
[JSR-SYSCALL] deny name=system.sync.mutex.try.acquire id=64 task=isohost-high-id-denied ret=system.error.rights_denied
[JSR-SYSCALL] reject id=255 task=isohost-high-id-denied ret=system.error.unsupported
```

本切片没有扩展第二切片的 `CallSet` API，没有启用 `system.task.syscalls.set` 或其他保留 ABI，
也没有修改 `SpawnDesc` 的既有 88 字节 v2 布局。

## 十、SyscallSet / spawn 性能证据（2026-11-07，宿主 KVM）

- 分支：`dev/issue1-perf`
- 基线：public/main `04f7391`
- 环境：宿主 KVM、`-cpu host`、CPU 4–11；QEMU 10.2.1；三轮宿主 1 分钟负载 1.71–1.83。
- 方法：真实内核基准 `kernel/src/bench_demo.rs` 比较生产 `SyscallSet` 与同一 `0..63` 范围的旧 `u64` 语义参考；每项 2048 个样本，最近秩计算 p50/p99/p99.9/max。旧 `u64` 仅作测试参考，不恢复影子授权通道。

三轮原始结果（周期）：

| 项目 | Run 1 p50/p99.9 | Run 2 p50/p99.9 | Run 3 p50/p99.9 |
|---|---:|---:|---:|
| SyscallSet contains | 26/34 | 26/32 | 26/32 |
| u64 reference contains | 20/32 | 18/30 | 18/32 |
| SyscallSet subset（4 字） | 18/24 | 18/26 | 18/24 |
| u64 reference subset | 18/26 | 18/26 | 18/26 |
| SyscallSet copy（32 B） | 24/34 | 24/30 | 24/32 |
| u64 reference copy | 18/30 | 18/28 | 18/26 |
| SpawnDesc decode（88 B） | 64/66 | 64/66 | 64/66 |
| calls field decode（SyscallSet） | 18/42 | 24/40 | 24/40 |
| calls field decode（u64 reference） | 18/24 | 18/26 | 18/26 |

结论：

- `contains` 稳定增加约 6–8 周期，`copy` 稳定增加约 6 周期，来自 256 位集合的边界检查/4 字处理；
- 4 字子集检查在当前样本中没有可见回归，p50 与 u64 参考同为约 18 周期；
- 32 字节 calls 字段解码的 p99.9 增加约 14–18 周期，但绝对成本仍只有约 11 ns（KVM 校准），远低于一次系统调用入口；
- `SpawnDesc::decode` 完整 88 字节 p50 约 64 周期、p99.9 约 66 周期；
- 没有发现需要恢复旧 u64 影子通道或改变 256 位权威语义的性能理由。

真实用户路径（三轮，p50/p99.9 ns）：

| 路径 | Run 1 | Run 2 | Run 3 |
|---|---:|---:|---:|
| syscall.roundtrip | 1,482,514 / 1,939,158 | 1,465,708 / 2,070,553 | 1,479,123 / 1,924,917 |
| ring.submit_complete | 1,700,237 / 2,101,034 | 1,679,014 / 2,148,927 | 1,677,767 / 2,035,855 |
| ipc.roundtrip | 6,373,765 / 7,759,356 | 6,399,375 / 7,392,175 | 6,388,945 / 7,990,471 |

这些是宿主 KVM 的端到端样本，包含虚拟化与宿主调度成本；只作当前环境的统一口径，不外推到裸机。三轮均通过 `T-2` 功能门禁；计时预算超界仍按现有分账记录，不改变功能结论。

证据：

- `evidence/accept-20261107-162456`
- `evidence/accept-20261107-162634`
- `evidence/accept-20261107-162803`

## 十一、任务能力集合替换与 ABI 2.0.0（2026-11-07，宿主 KVM）

### 操作契约

`system.task.syscalls.set`（ID 43）不再返回 `unsupported`：

| 参数 | 语义 |
|---|---|
| `args[0]` | 目标任务句柄；`0` 表示当前任务 |
| `args[1]` | 指向 32 字节规范 `SyscallSet` 的用户指针 |
| `args[2]` | flags，当前必须为 0 |
| 返回 | 成功 0；失败为登记的错误 ID |

非零目标必须是调用者进程句柄表中的 `Task` 对象，并带 `CONTROL`；句柄索引、代次、
对象类型和所属进程存活状态仍由既有 Handle/Rights 路径检查。请求位图先经过 32 字节
`SyscallSet` 解码，再由以下固定顺序检查：

1. 请求集合必须是 `REGISTERED_OPS_SET` 的子集，否则 `invalid_argument`；
2. 请求集合必须是调用者当前集合的子集，否则 `rights_denied`；
3. 调用者和目标都必须是尚未退出的用户任务，否则 `handle.error.invalid`。

检查与目标任务写回在同一个调度器事务内完成。任何失败均不改变调用者、目标、句柄、
引用或资源；成功只替换目标的 256 位任务集合。已经通过入口授权并在执行的系统调用
可以完成，撤权线性化于之后的统一权限检查，不追溯中断在飞调用。

`jasper-rt` 新增：

```rust
task::set_calls(&task_handle, calls)?; // 经带 CONTROL 的 Task 句柄
task::set_current_calls(calls)?;       // target = 0，当前任务
```

两者仍只用 `process::CallSet` 内部的唯一 `SyscallSet` 表示；`CallSet::encode` 只写既有
32 字节线上格式，没有新增位图、授权规则或特权旁路。

### ABI 世代裁决

ID 43 在已发布的 1.0/1.1/1.2 快照中都是稳定条目 `args=reserved|result=unsupported`。
同主版本规则禁止改写这条契约，因此原生 ABI 从 `1.2.0` 升到 **`2.0.0`**：

* 旧 1.x 快照保持逐字节不变；
* 旧锁文件归档到 `abi/archive/system-ids-1.2.0.lock`；
* 新快照 `abi/snapshots/2.0.0.contract` 记录 ID 43 的参数、返回与既有
  `syscall.set.v1|size=32` 布局；
* 所有内嵌用户程序随 ABI 2.0.0 重新构建，不保留 1.x 的 reserved 兼容解析路径。

这不是为新增操作顺带升级主版本：变化本身就是把一个稳定 reserved 契约改为可执行契约，
旧二进制无法在同一主版本兼容规则下安全获得新语义。

### 真实 CPL3 覆盖

`user/isohost` 的宿主先创建一个真实用户线程，再覆盖：

* 仅带 `WAIT` 的 Task 句柄不能设置集合，返回 `handle.error.rights_denied`；
* 无效 Task 句柄返回 `handle.error.invalid`；
* `flags != 0` 和含未登记 ID 255 位的请求返回 `invalid_argument`；非零 flags
  先于用户指针访问被拒绝，合法 flags 配无效指针返回 `memory.error.invalid_address`；
* 请求调用者没有的已登记操作返回 `system.error.rights_denied`；
* 上述失败后，目标任务仍能成功调用自己的 `system.time.now`，证明失败原子性；
* 成功收缩目标任务到 `{task.yield, task.exit}` 后，同一线程的 `system.time.now`
  被统一权限检查拒绝，随后正常退出；
* 参数块不含 `system.task.syscalls.set` 的角色直接调用返回 `rights_denied`，
  经 spawn 尝试给子进程该权限也返回 `rights_denied`；
* 宿主最后以 `target = 0` 自收缩到只剩 `system.process.exit`，下一个 `time.now`
  被拒绝后以退出码 0 正常结束。

### 验证证据

| 层 | 命令 / 位置 | 结果 |
|---|---|---|
| 64 位宿主 | `cargo test -p kernel-core --lib` | 559 passed / 0 failed |
| 32 位宿主 | `cargo test -p kernel-core --target i686-unknown-linux-musl --lib` | 559 passed / 0 failed |
| 属性 | `cargo test --manifest-path verification/toolbox/Cargo.toml --test syscall_set` | 新增集合替换模型与独立 `BTreeSet` 参考一致 |
| ABI | `bash scripts/abi-contract.sh check` | ABI 2.0.0 完整快照 PASS |
| 真实 QEMU | 共享锁内 `JASPER_ACCEL=kvm JASPER_CORES=4-11 JASPER_ACCEPT=spot JASPER_CHECKS='m32 j6' bash scripts/accept.sh` | `accept-20261107-183039`：M3.2、J-6 PASS；isohost 退出 0、资源回基线 |

关键串口证据：

```text
[JSR-SYSCALL] self_check ops=62 handlers=all ownership=complete
[JSR-SYSCALL] exit name=system.task.syscalls.set id=43 ret=-4102 status=system.handle.error.rights_denied
[JSR-SYSCALL] exit name=system.task.syscalls.set id=43 ret=0 status=OK
[JSR-SYSCALL] deny name=system.time.now id=3 task=thread ret=system.error.rights_denied
[JSR-USERTEXT] text=isohost: task_syscalls target_shrink=true denied_after=true atomic_failures=true invalid_target=true rights_checked=true unregistered_denied=true escalation_denied=true
[JSR-SYSCALL] exit name=system.task.syscalls.set id=43 ret=0 status=OK
[JSR-SYSCALL] deny name=system.time.now id=3 task=isohost ret=system.error.rights_denied
[JSR-PROC] event=system.process.exited id=0x3100000002 name=isohost code=0 threads=4 handles_closed=0
[JSR-RT] summary free_frames=61101/61101 objects=0/0 pending=0 pinned=(0, 0) reclaimed=true timers=0 coalesced=1 early=1 checks=28 failed=0 timing_failed=0
```

本切片没有实现 Jasper 语言侧的能力集合构造，也没有把 issue #1 的其他扩展能力一并启用；
这两项仍是 issue #1 整体关闭前的明确边界。
