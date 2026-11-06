# issue #4 进度：内核对象生命周期按类型局部注册（第一、二片）

- 日期：2026-11-06
- 分支：`dev/issue4-s1`、`dev/issue4-s2`
- 范围：第一片建立对象类型登记表与生命周期契约，closing 改为按种类查表，并让**所有创建新句柄的路径**先经登记表检查；第二片把锁外销毁也改为按种类查表，每种动作只进入所属模块的单一入口，并验证 `Destroy::None` 的销毁为空。对象身份、世代、引用计数、最后所有权释放与销毁入队仍只由唯一 `ObjectTable` 管理，不新增任何动态注册或独立计数。x86_64 为唯一运行目标；AArch64 只保证能编译。

## 1. 本片做了什么

| 项 | 内容 |
|---|---|
| `kobj_type::Kind` | 与内核 `KObject` 变体一一对应的封闭枚举（12 种）；声明顺序即强引用图的拓扑序。 |
| `kobj_type::Contract` / `REGISTRY` | 每种对象一行：类型名、句柄类型（`None` = 只被内部引用）、合法权限上限、可转移性、`Closing`（无 / 锁内有界动作）、`Destroy`（无 / 锁外动作）、强边、树形自边、`Carry`（不携带 / 只携带可转移句柄 / 携带任意句柄且退出时关闭）。 |
| `registry_well_formed` | 六条良构条件（见第 3 节），生产表以 `const _: () = assert!(…)` 断言，不良构即编译失败。 |
| `check_grant` | 句柄创建检查：类型与种类一致 → 带 `TRANSFER` 时种类须可转移 → 权限在上限之内。 |
| 内核 `KObject::kind()` | 穷举匹配，新增变体不登记即编译错误；`type_name()` 改取自登记表。 |
| 内核 closing 分派 | 原 `release_owner_in` 中的 `match` + `_ => {}` 兜底改为 `close_hook(kind)`（按 `Kind` 穷举、无兜底）生成的 `CLOSE_HOOKS` 表；编译期断言「有钩子 ⇔ 登记表声明 `Closing::InLock`」。 |
| 内核句柄创建 | `grant_in` / `grant_new_in` / `put_task_handle` / 子进程句柄（spawn）统一经 `proc::admit_handle`：类型不符 ⇒ 句柄无效；非可转移种类请求 `TRANSFER` ⇒ `NotTransferable`；超出上限 ⇒ `RightsDenied`。`grant_new_in` 在**插入对象之前**检查，不合法则根本不创建对象。 |
| 权限常量 | `RING_RIGHTS`、`INTERRUPT_RIGHTS`、`ENDPOINT_RIGHTS`、`DEVICE_RIGHTS`、互斥量权限改为取自登记表（唯一定义处）。 |
| 行为变化（无兼容包袱） | 以前可以给进程句柄加 `TRANSFER`，转移时才被拒；现在创建时即拒（`NotTransferable`），句柄表与外部所有权不变。内核自检 `[JSR-HANDLE]` 的「非叶子」一项改为验证创建时拒绝且无副作用，标记文本不变。 |

## 2. 对象依赖图（强边 = 存活期间持有的内部引用或发布者锚定的外部所有权）

```
Process ──► Task ──► ExitState ──► EventSource
   │  └──► ExitState                   ▲
   └──► Process（子进程，树形自边）       │
Ring ──► Interrupt ─────────────────────┤
   ├──► Subscription ───────────────────┘
   ├──► Endpoint
   └──► ExitState
携带句柄：Process（句柄表，任意类型，退出时关闭）；Endpoint（消息队列，只含可转移类型）
叶子（无强边、不携带）：EventSource、Mutex、Memory、Event、Device
```

每条强边都指向声明顺序更靠后的种类，所以类型层面无环；可转移种类（Task、Mutex、Memory、Event、Device）的强引用闭包里没有携带句柄的种类，消息里的句柄因此不能把端点或进程拉进环。

### 因安全正确性保留的集中依赖

| 集中点 | 为什么保留 |
|---|---|
| `ObjectTable`（身份、世代、两种计数、死亡入队） | 所有权证明只有在唯一权威处才成立；分布式计数会破坏「最后释放恰好一次」。 |
| `release_owner_in` 是释放外部所有权的唯一入口 | closing 必须在最后一份外部所有权释放**之前**执行，散到各处就可能漏掉。 |
| `run_cleanup` 的销毁钩子表 | 销毁要按值拿到各类型载荷；中心代码仍保留按种类下标查表和锁外调用，但类型载荷的解释与释放动作只存在于所属模块，`Destroy::None` 的槽为空。 |
| `transfer` 中的 `is_transferable_v1` 复核 | 登记表已在创建时拦截，此处作为纵深防御保留；二者一致性由良构条件 3 在编译期保证。 |

## 3. 登记表良构条件（编译期断言 + 六步链验证）

1. 表长 = 种类数，第 i 项就是第 i 个种类；类型名互异。
2. 不可经句柄访问 ⇒ 权限上限为空、不可转移、无 closing。
3. 可经句柄访问 ⇒ 句柄类型互异、上限非空；可转移 ⇔ 上限含 `TRANSFER` ⇔ 句柄类型属于 v1 可转移类型。
4. 每条强边指向更靠后的种类；只有「携带任意句柄」的种类可以有树形自边。
5. 有强边或携带句柄 ⇒ 有 closing 或锁外销毁来释放它们。
6. 可转移 ⇒ 叶子：不携带句柄，且强引用闭包中没有携带句柄的种类。

## 4. 新增对象类型需要修改的位置（前后对照）

| 位置 | 改动前 | 改动后 |
|---|---|---|
| 类型名 | `type_name()` 手写一行 | `REGISTRY` 一行（名字互异由条件 1 检查） |
| 种类 | 无 | `Kind` 一个变体 + `KObject::kind()` 一臂（漏写 ⇒ 编译错误） |
| closing | `release_owner_in` 的 `match`，**漏写 ⇒ 静默落入 `_ => {}`** | `close_hook` 一臂（穷举，漏写 ⇒ 编译错误；与声明不符 ⇒ 编译期断言失败） |
| 销毁 | `run_cleanup` 的 `match`，漏写可能落入空臂 | `destroy_hook` 一臂 + 所属模块 `destroy_object` 入口；存在性与登记表编译期比对 |
| 合法权限 / 可转移性 | 散在各模块的常量与 `is_transferable_v1` | `REGISTRY` 一行；创建句柄时统一检查 |
| 强引用 / 携带句柄 | 只在注释里 | `REGISTRY` 一行；无环与叶子条件编译期检查 |

## 5. 验证

- 六步链：`verification/toolbox/run-kobj-type-suite.sh`（Verus/Z3 → Proptest → Miri → cargo-fuzz → Kani → Loom），结果见性质登记表 `KOBJ-TYPE-01/02/03` 与 `RIGHTS-ALG-01`；Kani 按当前规则只在发版时验证。
- 内核：第一片定点验收 m11、m34、m41、m42、m43、m44、drv1c、drv2c1、sched2、fix；第二片在 `accept-20261106-151138` 定点运行 issue4_destroy、m41、m43、m44、fix，五项全部 PASS。QEMU 退出码 37 仅因既有计时项超界，功能断言无失败。
- 第二片宿主证据：`kernel-core` 定向 5/5、完整复跑 534 个单元测试加 33 个集成/文档测试全通过；toolbox Proptest 4 项各 512 例、Miri 固定序列 1/1，均 0 失败。x86_64 与 AArch64 release 构建通过。

## 6. 对照 issue 验收条目

| 条目 | 状态 |
|---|---|
| 编译期可审计的类型登记与生命周期契约（类型标识、合法 Rights、可转移性、外部所有权归零处理、销毁规则、锁序） | 本片完成：登记表 + 良构断言；closing 在锁内、销毁在锁外由契约字段声明。失败处理与锁序目前写在模块文档，未成为表字段。 |
| 身份 / 世代 / 计数 / 入队仍由唯一 `ObjectTable` 管理 | 满足，未改动。 |
| closing / destroy 类型特有部分局部化，穷举性可验证 | 第一、二片完成：closing 与锁外销毁均按种类查表；有锁外动作的类型由所属模块单一入口承载，编译期与启动期检查存在性。 |
| 锁内有界、昂贵销毁在锁外，释放期间引用变动 / 级联 / 等待取消有协议 | 现有行为保持；协议成文与逐类型审计在第三片。 |
| 用实际对象类型端到端接入 | 12 种现有类型全部接入登记表；句柄创建检查覆盖全部创建路径。 |
| 重复 close、取消与交付竞态、世代复用、失败回滚、锁序、资源基线、清理队列收敛 | 由既有 m41 / m42 / m43 / m44 / fix 回归覆盖；专门的竞态与锁序验证在第三片。 |
| 新增类型变更位置清单、对象依赖图 | 见第 2、4 节。 |

## 7. 第二片：销毁动作局部化

- `KObject` 的中心清理代码不再展开 12 个变体。`run_cleanup` 在锁内只取出死亡对象，放锁后按 `obj.kind()` 查询编译期常量表 `DESTROY_HOOKS`；表项为空时直接丢弃对象值，表项存在时调用所属模块的唯一锁外入口。
- 5 个有锁外动作的种类由原模块承载：`Process`、`Task` 在 `proc`，`Ring` 在 `ring`，`Endpoint` 在 `ipc`，`ExitState` 在 `exit_state`。每个入口独占并解释本类型载荷，不再接收已拆开的 `Box<T>` 或裸字段。
- 登记的 `Destroy::None` 有 7 种：`Interrupt`、`Subscription`、`EventSource`、`Mutex`、`Memory`、`Event`、`Device`。它们的钩子槽为空；硬件解绑、订阅摘除、互斥量关闭等有界动作仍在各自 closing 路径，页与设备叶子由对象值正常丢弃完成。
- `destroy_hook_matches` 是 `Destroy::None ⇒ 空钩子` 与 `Destroy::OutsideLock ⇒ 非空钩子` 的可执行谓词。生产 `DESTROY_HOOKS` 用 `const` 断言逐项比对登记表；启动期 `verify_destroy_dispatch()` 再次遍历生产表并输出 `[JSR-LIFE] destroy_dispatch` 证据，失败即拒绝启动。
- 对象身份、世代、外部所有权和内部引用计数仍只由 `ObjectTable` 管理。`take_dead` 与入队语义未变；交付给销毁入口前对象表锁已经释放，模块内部原有的锁序与级联释放路径也未改变。

## 8. 剩余切片

1. **第三片**：释放协议成文并验证——释放期间引用变动、跨对象级联与等待取消；锁序字段进入登记表；重复 close / 取消与交付竞态 / 世代复用的交错验证。
