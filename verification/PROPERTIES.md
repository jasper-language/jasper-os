# 形式化验证性质登记

## 可信计算基与假设

- 硬件保证页表写入在发出 TLB 作废前对其它处理器可见；跨核 IPI 最终送达，除非建模中的显式超时分支发生。
- TLA+ 模型覆盖单个页表版本的击落、逐核应答和超时撤销，不覆盖页表并发写入的全部硬件内存序。
- `model-checked` 只表示 TLC 在下列小状态空间中穷举无违例，不等同于代码级机器证明。
- 内核实现到模型的对应：`kernel_core::smp::ShootdownBoard::{begin,begin_all,service,abandon}` 对应请求与应答集合；`kernel::smp::tlb_shootdown_on` 对应本地作废、逐目标 IPI 与超时；`kernel::mm::space::VmSpace::active_cpus` 提供目标集合；`kernel::proc::{unmap_range,protect_range}` 和 `kernel::mm::map::{unmap,unmap_pages}` 在帧释放前调用击落；`kernel::mmio::Mapping::drop` 使用批量内核 unmap。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN-TLB-01 | 页表修改完成且所有目标核应答前，不归还任何可能仍被旧 TLB 引用的数据帧 | `kernel::proc::unmap_range`; `kernel::mm::map::unmap`; `kernel::mm::map::unmap_pages`; `kernel::mmio::Mapping::drop` | TLA+ + QEMU | model-checked | `bash verification/run-tlc.sh && bash scripts/accept.sh` | 模型假设 IPI 最终送达；硬件全局页刷新语义未形式化 |
| KRN-TLB-02 | 超大页范围只登记一次击落，并在每个目标核上执行整表刷新 | `kernel_core::smp::ShootdownBoard::begin_all`; `kernel::smp::tlb_shootdown_on` | 单元测试 + QEMU | tested | `cargo test -p kernel-core shootdown && bash scripts/accept.sh` | x86_64 整表路径在关闭 CR4.PGE 时刷新全局项；未在真机验证 |
| KRN-TLB-03 | 10^5 级跨核并发读取不会读到映射批次之外的数据，击落后其它核看到新映射 | `kernel::krn0_tlb::run`; `kernel::smp::tlb_shootdown_on` | QEMU 压力测试 | tested | `bash scripts/accept.sh` | 两核、内核映射窗口；不是用户地址空间的故障注入测试 |
| KRN-MMIO-01 | MMIO 槽位只在空位比较交换成功后推进，映射丢弃后位图恢复且槽位耗尽安全拒绝 | `kernel::mmio::{allocate_slot,release_slot,Mapping}` | QEMU 压力测试 | tested | `bash scripts/accept.sh` | 10,000 轮单线程映射/丢弃；并发争用由 CAS 结构保证，未做独立宿主模型 |
| KRN0-WRAP-01 | 中断到达计数从 `u32::MAX-3` 起递增 6 次后，按模差读到 6 | `kernel_core::interrupt::arrivals_since`; `kernel::irq::count_arrival` | 单元测试 + QEMU | tested | `cargo test -p kernel-core interrupt && bash scripts/accept.sh` | 局部计数走与真实路径相同的递增和求差函数 |
| KRN0-DMA-01 | virtio 复位超时后，只有关闭总线主控并读回为关时才归还队列帧，否则永久隔离 | `kernel_core::dma_quiesce`; `kernel::virtio::quiesce_with` | 单元测试 + QEMU | tested | `cargo test -p kernel-core dma_quiesce && bash scripts/accept.sh` | 真实 virtio-rng 不可用时 QEMU 用例报告跳过 |

## BM-1 虚拟机引导与日志协议

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| BM1-DMA-01 | 发送描述符仍归设备所有时保留 DMA 帧，失败路径不归还帧，客户机复位才终止该生命周期 | `kernel::arch::x86_64::bm1::upload`; `verification/bm1_boot.tla` | TLA+ | model-checked | `bash verification/run-bm1-tlc.sh` | 3 分包的单次启动抽象，45 状态；设备 DMA/复位与锁序由实现和环境承担，未证明真实硬件内存序 |
| BM1-ACCEPT-01 | 模型只有在全部分包、校验、串口对应、屏幕检查及复位满足后才可接受 | `tools/bm1/run.py`; `verification/bm1_boot.tla` | TLA+ | model-checked | `bash verification/run-bm1-tlc.sh` | hash/串口/屏幕验证被抽象为可信步骤；不证明 Python 实现或截图文字，实际十次启动见 BM-1-VM.md 证据 |
| BM1-LOG-01 | 固定种子输入乱序仍还原原文；缺包不完成；损坏、重复、跨启动及截断输入被拒 | `tools/bm1/run.py::{decode,Assembly}` | 属性测试 | tested | `python3 -m unittest discover -s tools/bm1 -v` | seed=0xB001；边界最小用例1字节，随机最长20000字节；不是代码级证明，FNV1a 不抗恶意碰撞 |

实现对应：`Submit/Complete` 对应 `upload` 中写 TSD 后轮询 TX OK；DMA 帧没有回收调用，错误即保留到复位。`Receive/Verify/Reset/Accept` 对应接收器分包累计、校验与串口比较、QMP RESET 计数和最终汇总。模型无公平性或最终完成结论，模型不单独代表连续十次虚拟机验收；实际十次及四核日志另有逐字节回放证据。

| BM0-AGG-01 | 汇总只豁免明确标记的计时 TIME；功能 TIME、FAIL 与未知状态仍阻塞，说明中的 PASS 不改变状态 | `scripts/accept.sh::row_nonblocking` | 契约测试 | tested | `python3 -m unittest discover -s tools/bm1 -v` | 表驱动9个状态边界；不证明整个 shell 脚本 |

## KRN-1 操作交错检查

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN1-RING-01 | 每条有界操作顺序中完成发布/销毁/引用回收至多一次、信用守恒，后端静止后可排空 | `kernel-core/tests/krn1_interleavings.rs::krn1_ring_all_six_operation_orders`; `async_ring::AsyncRing` | 穷举顺序测试 | tested | `cargo test -p kernel-core --test krn1_interleavings` | 2880条顺序，单请求、容量2、API边界串行化；不证明弱内存或多请求并发 |
| KRN1-IRQ-01 | 取消/关闭/到达竞争对同一等待者只交出一个所有者，关闭后无等待者且拒绝新等待 | `kernel-core/tests/krn1_interleavings.rs::krn1_interrupt_cancel_close_arrival_orders`; `interrupt::InterruptLine` | 穷举顺序测试 | tested | `cargo test -p kernel-core --test krn1_interleavings` | 24条顺序、单等待者；不含IRQ硬件或进程退出等待 |
| KRN1-EXIT-01 | 取消撤销与两次不同退出码通知的六排列中，第一次退出码不被覆盖且被取消等待不再通知、通知至多一次 | `kernel/src/exit_state.rs::{remove_waiter_in,notify_in}`; `kernel-core/tests/krn1_exit_interleavings.rs` | 顺序契约测试 | tested | `cargo test -p kernel-core --test krn1_exit_interleavings` | 直接包含实际内核源、真实ObjectTable；完成回调为记录适配器，不覆盖Ring引用生命周期与进程拆除 |
| KRN1-FAULT-01 | 显式arm后选定第n次调用只触发一次；未arm/触发后不注入 | `kernel_core::fault::FaultPoint`; `verification/fault_countdown.tla` | 属性测试 + TLA+ | model-checked | `cargo test -p kernel-core --test krn1_fault && bash verification/run-fault-tlc.sh` | 测试256种子及8线程；模型25状态、两个调用者、n=3；假设CAS线性化、工作负载静止时arm/disarm，不证明硬件原子实现 |

故障倒计时模型映射：`Hit(w)`为`FaultPoint::hit`的成功原子更新线性化点；`remaining=0`时`checked_sub`失败、不改变状态；`remaining=1`时唯一返回true。CAS重试及线程调度不可见，未证明并发重新arm（契约禁止）。KRN1-FAULT-01状态只对模型成立；实际帧/堆/复位/IPI挂钩需单独QEMU证据，不能由该小模型推导。

| KRN1-HOOK-01 | 显式注入帧/堆失败不扣资源，复位与IPI超时返回错误且下次重试可恢复 | `kernel::fault_inject::selftest`; `mm::frame`; `mm::heap`; `virtio::VirtioPci::reset`; `smp::tlb_shootdown_on` | QEMU契约测试 | tested | `bash scripts/krn1-fault.sh` | 4核TCG指令时钟，4站点一次触发；不覆盖全部调用者回滚或DMA在飞拆除；不作性能结论 |

## S-2 健壮性回归

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| S2-SEED-01 | 8个有效工作者使用互不相同固定种子、总探测数1000000，越界工作者被拒绝 | `kernel_core::argcase::{s2_seed,S2_PROBES,S2_WORKERS}`; `user/robust::_start` | 契约测试 | tested | `cargo test -p kernel-core --test s2_streams` | PRNG非密码学，输入流固定而调度不固定；测试不等于系统调用压力通过 |
| S2-MMIO-01 | 部分映射回滚未确认时槽位不允许复用 | `kernel::mmio::Mapping::map`; `verification/mmio_rollback.tla` | TLA+ | model-checked | `bash verification/run-mmio-tlc.sh` | 正例3状态无违例，旧行为negative配置出现NoStaleReuse反例；单槽位抽象，假设成功unmap包括远程TLB确认，不证明硬件内存序 |

| S2-CALL-01 | 8进程各125000次有界探测返回值符合预期、8核有实际调用且回收后资源回基线 | `kernel::s2::run`; `user/robust::{probe,_start}` | QEMU健壮性回归 | tested | `bash scripts/s2.sh` | 一轮8固定种子、1000528实际调用、每核125066；22探测类别不是全部系统调用全集；非弱内存证明，错误路径审计尚未全覆盖 |


## S-2 错误路径与启动屏障

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| S2-ERROR-01 | OOM/部分帧失败/击落超时的预期错误不导致进程退出回收后资源漂移 | `kernel::s2::process_error_tests` | QEMU契约测试 | tested | `bash scripts/s2.sh` | 4用例、无运行线程的测试进程；不覆盖故障核继续执行旧用户空间 |
| S2-MMIO-LIVE-01 | 实际回滚超时保留槽位，成功回滚及后续正常映射可回收 | `kernel::s2::mmio_rollback_test`; `kernel::mmio::Mapping::map` | QEMU故障注入 | tested | `bash scripts/s2.sh` | 单个实际BAR的2页映射；明确隔离1槽，未访问设备寄存器 |
| S2-DMA-NONE-01 | 读回未知时真实关主控后仍隔离队列，隔离数与未归还帧数相同 | `kernel::s2::dma_missing_readback_test`; `virtio::quiesce_with` | QEMU故障注入 | tested | `bash scripts/s2.sh` | 注入观测None；真实设备仍按规范运行；明确隔离4帧 |
| S2-START-01 | TLB自检writer只在双方登记后开始内存批次，等待时让出boot创建机会 | `kernel::krn0_tlb::{writer,reader}`; `verification/tlb_test_start.tla` | TLA+ + QEMU | model-checked | `bash verification/run-tlb-start-tlc.sh && bash scripts/s2.sh` | 模型检查启动安全性，不证明调度公平或原停滞唯一根因 |
| S2-ARM-01 | 同一真实机制库及集成契约在ARM用户态三轮全部通过 | `kernel-core`; `scripts/s2-pda.sh` | ARM宿主测试 | tested | `bash scripts/s2-pda.sh` | 405项×3轮，8线程；Android用户态musl，不是Jasper原生启动证明 |


## issue #1 系统调用能力集合与 spawn 授权

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| SYS-ABI-01 | 256 位能力集合的成员判定与位图一致；ID 63/64/127/255 可见且互不串位；ID≥256 显式拒绝；32 字节序列化往返不变 | `kernel_core::syscall_set::SyscallSet` | 属性测试（固定种子 512 轮 + 边界/穷举） | tested | `cargo test -p kernel-core syscall_set` | 不证明编译后的机器码；32 位目标已编译但未在 32 位宿主运行全部用例 |
| SYS-ABI-02 | spawn 通过 ⇔ 请求集合同时是调用者集合与登记集合的子集；头部/保留字段/映像/CPU 上限在改动状态前拒绝 | `kernel_core::spawn_abi::{SpawnDesc,check}` | 穷举 + 边界/恶意参数测试 | tested | `cargo test -p kernel-core spawn_` | 只覆盖无状态准入规则；配额、帧分配与 ELF 装载由内核集成路径另行验证 |
| SYS-ABI-03 | 分发表实现集合与 `abi/system-ids.txt` 生成的登记集合完全相等 | `kernel::syscall::{IMPLEMENTED,execute,self_check}`; `kernel/build.rs`; `kernel::syscall::table::{REGISTERED_OPS,REGISTERED_OPS_SET}` | 编译期集合断言 + 启动自检 | tested | `cargo build --release --target x86_64-unknown-none -p jasper-kernel`（编译期断言）；QEMU 日志 `[JSR-SYSCALL] self_check ops=55 handlers=all` | 断言针对生成代码的常量；不证明登记表文本本身符合安全策略，也不替代每项系统调用的功能测试 |
| SYS-ABI-04 | 六步链①Verus/Z3：4 字位图的 from_id/contains/union/intersection/difference 逐位满足集合语义；is_subset_of 可靠且完备；check 通过 ⇔ 头部/保留位/映像/CPU 界内且请求 ⊆ 登记集合 ∧ 请求 ⊆ 调用者集合；子集传递 | `verification/toolbox/verus/syscall_set.rs`（逐式对应 `kernel_core::syscall_set::SyscallSet` 与 `spawn_abi::check`） | Verus 0.2026.10.18.7d82994 + Z3 | proved（规格级） | `VERUS=<verus> STEPS=1 bash verification/toolbox/run-issue1-syscall-set-suite.sh` | 37 verified / 0 errors；负例 `syscall_set_bad.rs`（只比较字 0，即旧 u64 缺陷）必须失败：1 error。四字段重写，不是对编译后生产代码的证明 |
| SYS-ABI-05 | 六步链②Proptest：生产集合运算、try_of 越界整体拒绝、序列化往返、spawn 准入与拒绝原因均等于独立 `BTreeSet` 参考模型；多级 spawn 不提权 | `verification/toolbox/tests/syscall_set.rs` | Proptest（默认 256 例/性质，自动收缩） | tested | `cargo test --manifest-path verification/toolbox/Cargo.toml --test syscall_set` | 3 passed / 0 failed；ID 偏向字边界与越界值 |
| SYS-ABI-06 | 六步链③Miri：能力集合/参数块单元测试与多级 spawn 固定链无未定义行为 | `kernel_core::{syscall_set,spawn_abi}` tests；`multi_level_spawn_never_escalates` | Miri（nightly 2026-10-20） | tested | `STEPS=3` 同上 | kernel-core 13 passed + 工具箱 1 passed；两个 proptest 性质在 Miri 下单项超过 10 分钟未纳入，其随机覆盖由②④⑤承担 |
| SYS-ABI-07 | 六步链④cargo-fuzz：任意 88 字节参数块 + 任意调用者/登记集合：非 v2 头部必拒；解码后逐字节往返；通过 ⇒ 请求 ⊆ 两集合；拒绝原因与集合关系一致 | `verification/toolbox/fuzz/fuzz_targets/spawn_desc.rs` | cargo-fuzz 0.13.2 | tested | `STEPS=4` 同上 | 200000 次无崩溃，cov 102；不是证明 |
| SYS-ABI-08 | 六步链⑤Kani：生产 `SyscallSet` 对任意字/任意 u64 ID 的成员判定、单元素构造、并交差逐位语义、子集可靠完备、32 字节往返；生产 `SpawnDesc::decode` 对任意 88 字节只接受 v2 头部且往返；`check` 通过 ⇔ 全部准入规则 | `kernel_core::syscall_set::proofs::*`（5 项）；`kernel_core::spawn_abi::proofs::*`（2 项） | Kani 0.68.0 / CBMC 6.11.0 | proved（有界：展开 9/33/89，覆盖全部循环与 memcmp） | `STEPS=5` 同上 | 7/7 VERIFICATION SUCCESSFUL；无 assume/stub |
| SYS-ABI-09 | 六步链⑥Loom | `SyscallSet`、`spawn_abi::check` | — | N/A：`SyscallSet` 是无共享可变状态的 Copy 值，`check` 为纯函数，无原子量/锁/线程交错 | — | 替代证据：x86_64 QEMU 定点 m11/m32/j6（CPL3 真实 spawn、越权调用 rights_denied、自检 `ops=55 handlers=all`）；不标 PASS |
| SYS-ABI-10 | `jasper-rt::process::CallSet` 只由登记操作 ID 构造；越界、未登记、重复输入整体拒绝，失败插入不改变原集合；spawn 使用该类型内部唯一 `SyscallSet`，不新增位图或序列化通道 | `user/rt/src/process.rs::CallSet`; `kernel_core::syscall_set::SyscallSet::{try_from_ids,try_with_id}`; `user/isohost/src/main.rs::spawn_boundary` | 单元 + Proptest + Miri + CPL3 契约 | tested | `cargo test -p kernel-core syscall_set`; `cargo test --manifest-path verification/toolbox/Cargo.toml --test syscall_set`; `cargo +nightly miri test -p kernel-core --lib -- syscall_set::`; 共享 QEMU 锁内 `JASPER_ACCEPT=spot JASPER_CHECKS=j6 bash scripts/accept.sh` | kernel-core 8/0；属性 4/0；Miri 8/0；isohost `checks=43`、`insert_atomic=true`、退出 0。父/子集合最终判据仍由内核 `spawn_abi::check` 独立执行；未覆盖 Jasper 语言侧构造、高编号登记操作或保留 ABI |

## FV-1 真实代码有界验证（V2）

机器可读逐性质规格、工具/版本、输入位宽、容量/步数、TCB、复现和最新记录统一登记于`verification/FV1.toml`。12项Kani harness实际通过，0失败，无assume/stub；不是测试结果的改名。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| FV1-V2-SUITE | 权限不提升/未授权拒绝、代次/引用、真实跨表转移、Ring唯一性及配额/索引边界 | `kernel-core/src/{fv1,object,objtable,quota}.rs` | Kani | proved | `bash verification/run-kani.sh` | 各有界范围见FV1.toml；容量1/2、Ring4步、64位目标；锁/硬件/完整Channel队列不在代码证明内 |
| FV1-RING-LIVE | 一个执行中请求在显式弱公平后端完成/发布/回收假设下最终回收，始终保持唯一性与缓冲静止约束 | `verification/ring_fv1.tla`; `async_ring::{finish,cancel,close,quiesce}` | TLA+ | model-checked | `bash verification/run-ring-fv1-tlc.sh` | 54可达状态；公平性是假设，不证明真实调度器/驱动最终进展 |

## RT-3 优先级反转全链

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| RT3-MUTEX-01 | 用户互斥对象唯一持有、直接交接、关闭/退出后引用守恒；递归和成环在阻塞前拒绝 | `kernel-core::inherited_mutex`; `kernel::user_mutex`; `verification/rt3_mutex_lifecycle.tla` | TLA+正负模型 + 契约/四核CPL3 | tested | `bash verification/run-rt3-mutex-lifecycle-tlc.sh && bash scripts/rt3-mutex-sample.sh <label>` | 模型6可达状态；实际三用户任务；不证明任意链长或物理等待上界 |
| RT3-IPC-01 | Ring等待回复时事件登记、阻塞和服务线程继承边原子建立，任意完成/关闭唤醒清除继承 | `kernel::ring::enroll_wait_in`; `kernel::ipc::donation_owner_in`; `Scheduler::enroll_event_wait`; `verification/rt3_ring_donation.tla` | TLA+正负模型 + 跨进程CPL3 | tested | `bash verification/run-rt3-ring-donation-tlc.sh && bash scripts/rt3-mutex-sample.sh <label>` | 模型4可达状态；实际两进程两轮请求应答；不含硬件弱内存或物理截止期保证 |
| RT3-KMUTEX-01 | 可能扫描依赖并修改多记录的批处理队列使用阻塞继承锁，不在整个操作期间关中断自旋 | `kernel::job`; `kernel::sched::turnstile` | 编译/默认定点 | tested | `cargo build -p jasper-kernel --lib --release` | 默认1/4核作业27项0失败，但整机因既有非RT3项退出35，未记整机PASS；仅任务上下文，IRQ须有界转交 |

## FV-3 Verus试点结论

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| FV3-VERUS-PILOT-01 | 试点实现的权限截断、交集、原地降权成功/拒绝原子性均不可增加权限；并集负例必须违反后置条件 | `verification/toolbox/verus/{handle_rights,handle_rights_bad}.rs` | Verus+Z3正例/严格负例 | proved | VM `bash verification/toolbox/run-fv3-verus.sh` | 正例9verified/0errors；证明对象是独立可执行Verus实现，不是生产`object.rs`，因此不登记为生产V3证明 |
| FV3-HANDLE-DIRECT-01 | 生产HandleTable降权、旧句柄、容量和跨表转移保持权限及唯一所有者，缺失TRANSFER检查产生反例 | `kernel-core/src/{object,fv1}.rs`; `verification/toolbox/tests/handle_sequence.rs` | Kani + Proptest/Miri/fuzz/Loom + 源码变异负例 | proved / tested | VM `bash verification/toolbox/run-fv3-handle-suite.sh` | 两个Kani harness各0失败；Proptest/Loom2、Miri1、fuzz10000；Loom验证外部互斥串行化，不证明生产锁或任意并发调用 |

## KRN-3 每核队列迁移协议

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN3-MIGRATION-PROTOCOL-01 | 跨核迁移按较小CPU号先取锁；可运行任务在源核、事务保管或目标核三者中恰有一个所有者；提交/回滚只发生一次 | `kernel-core::percpu_migration`; `verification/krn3_percpu_migration.tla` | TLA+正负模型、Verus伴随、Proptest/Miri/fuzz/Kani/Loom | tested / model-checked / bounded Kani | VM `bash verification/toolbox/run-krn3-migration-suite.sh` | 正模型无错、破坏detach所有权的负例违反Safety；Proptest256、fuzz10000、Kani2 harness。当前Rust类型是生产迁移事务使用的纯协议，但不证明未来真实两把锁的弱内存或公平性 |
| KRN3-MIGRATION-INTEGRATION-01 | 生产rehome仅在队列迁移成功后发布目标home；失败保留源home，代次不截断；CPL3亲和迁移后EDF/准入/退出资源守恒 | `kernel/src/sched/scheduler.rs::rehome`; `scripts/rt1-admission-sample.sh` | 默认内核编译 + 受控四核guest | tested | `krn3-migration-production-20261026` | exit33，CPL3/EDF/ADMISSION标记全真且source前后同；仍持全局Scheduler锁，不代表每核锁完成、低争用或物理性能达标 |
| KRN3-TARGET-INBOX-01 | 远程wake/PI进入目标CPU独立有界inbox；消费前释放inbox锁，完整代次和PI轮次不匹配时不应用；wake满队列同步回退 | `kernel/src/sched/mod.rs`; `kernel/src/sched/scheduler.rs`; `kernel_core::percpu_migration::PiMailbox` | Verus+Z3/Proptest/Miri/fuzz/Kani/Loom/TLA + 四核定点guest | tested / model-checked / bounded Kani | `migration-suite/PASS`; `inbox-target-consume-20261026`失败；`inbox-irq-safe-20261026`目标标记 | 首轮未屏蔽同核中断而timeout124；修复后remote wake和16+1满邮箱全部返回、列表一致、资源守恒。该guest默认套件另有cap50时序/预算失败，故只登记目标契约，不登记默认套件通过；不证明真实RunLists已拆锁 |
| KRN3-RUNLEAF-01 | 每核策略状态和真实运行列表由独立leaf锁拥有；跨核迁移按CPU号同时持源/目标leaf，策略成员与链表成员同事务迁移；旧源不能重复迁移或双入队 | `kernel-core::sched::queue::CoreQueue::migrate_to`; `kernel/src/sched/scheduler.rs::{RunLeaf,rehome,relist}` | 定点core契约 + 默认release编译 + 四核定点guest | tested | `cargo test -p kernel-core separately_locked_core_queues_migrate_exactly_once`; `evidence/krn3/runleaf-fixed-20261026/PASS` | 初次guest因decide持leaf后递归waiting自锁而timeout124；改为锁外等待快照后目标标记、列表和资源守恒通过。任务/current/Link仍受全局控制锁保护，不证明调度热路径已去全局锁；同次默认套件cap50时序失败不计通过 |
| KRN3-MIGRATION-COMPLETION-01 | 任务热槽先迁到目标leaf时，源CPU切换完成仍必须清除目标热槽的旧执行所有权，并在冷结算后向目标CPU发kick；旧源不能令任务永久不可选 | `kernel/src/sched/scheduler.rs::{finish_leaf_switch,finish_switch}`; `kernel/src/sched/mod.rs::{finish_switch,on_timer_interrupt,on_local_timer}` | 默认release编译 + 双核聚焦guest + 热槽六工具套件 | tested | `evidence/krn3/fused-switch-migration-final2-20261026/PASS`; `bash verification/toolbox/run-krn3-task-hot-suite.sh` | 首次完整guest在亲和迁移后timeout124，定位为目标leaf热`on_cpu`残留；修复后CPU1→CPU0恢复、worker完成、列表和资源均通过。时钟tick与prepare已合并一次事务，但普通竞争路径仍取得一次`KERNEL_SCHED`，不登记KRN-3完成或物理性能达标 |
| KRN3-BSP-LEASE-ISOLATION-01 | BSP tick不得排空普通无组非RT AP的本地记账；预算任务保持单tick结算；批次耗尽或控制事务后精确归并且退出不能越过在核运行所有权 | `kernel-core::tick_lease::TickLease`; `kernel/src/sched/mod.rs::lock_state_from`; `kernel/src/sched/scheduler.rs::{bsp_tick_lease_participants,drain_local_ticks,workers_settled}` | core契约 + 默认release编译 + 双核聚焦guest | tested | `cargo test -p kernel-core tick_lease`; `evidence/krn3/bsp-partial-batch-fixed-20261026/PASS` | 首轮发现退出到switch发布窗口会让run提前返回，已保留失败并用热`on_cpu`补齐settled边界；最终连续峰值8且实体/CPU账精确。竞争选择与切换仍回退全局，不证明KRN-3完成或物理延迟 |
| KRN3-LOCAL-COMPETING-SWITCH-01 | 同核普通任务竞争时，获授权AP tick在单个RunLeaf内精确完成记账、策略选择、requeue/dispatch与切换发布；冷事务按完整代次结算原owner且不得重复扣费、双入队或提前复用 | `kernel/src/sched/scheduler.rs::{fast_leaf_competing_tick,settle_leaf_transition,drain_local_ticks}`; `kernel/src/sched/mod.rs::on_local_timer` | 默认release编译 + 热槽六工具套件 + 双核真实竞争guest | tested | `bash verification/toolbox/run-krn3-task-hot-suite.sh`; `bash scripts/krn3-fast-tick-sample.sh competing-local-switch-final2-20261026`（仅VM） | guest33/整批0/source同；两任务3次本核切换，lease hits6、实体/CPU账均12，队列/热槽审计全0且资源回收。仅覆盖无RT、无组预算、无ns预算、无PI提升的普通竞争；复杂控制保持全局事务；TCG不证明物理延迟或弱内存 |
| KRN3-POSTSPLIT-REGRESSION-01 | 结构拆分后的真实4/8核规模用例不得死锁、丢任务、双入队、遗留wake或漂移资源；全局控制事务取得的叶锁数应不超过全部在线叶理论上界 | `kernel/src/scale_demo.rs`; `kernel/src/sched/{mod.rs,scheduler.rs}`; `scripts/krn3-postsplit-sample.sh` | 默认release编译 + 聚焦4/8核guest | tested / timing deferred | `evidence/krn3/krn3-postsplit-focused-20261026/PASS` | 4/8核均脚本0、功能失败0、资源回收、wake拒绝0；同步工作分别避免45/273次叶获取。TCG计时仍有2/4项超界，调度锁696/967‰、对象表296/179‰；raw wake各64条且丢弃82/66、complete=false，不能形成p99.9或物理性能验收 |
| KRN3-KVM-WAKE-P999-01 | wake起点与resume终点使用同一序列化校准域；完整直方图不随64项raw审计缓冲截断；性能专项不得继承同步串口切换观察者或重复全表刷新；同一高精度事务批量发布所有已到期owner并把本核决定/切换合并，另报deadline→runnable与deadline→resume | `kernel-core/src/raw_timing.rs`; `kernel/src/sched/{mod.rs,scheduler.rs}`; `kernel/src/scale_demo.rs` | core契约 + RT-2定点回归 + Linux宿主KVM八核两次实际guest | tested / requested fanout targets met | `evidence/krn3/p999-batch-fused-kvm-20261026`; `evidence/krn3/p999-batch-fused-kvm-r2-20261026`; `evidence/evt1/p999-batch-fused-rt2-20261026/PASS` | 两轮各隔离10000项、七核14336项，invalid0/complete/资源守恒；七核wake→resume p99.9均50us、deadline→runnable为40/50us、deadline→resume为60/70us，均低于用户指定200us。隔离deadline→resume仍为230/250us，继续报告且不混入七核结论；共享TSC同步为平台假设，开发宿主KVM不替代裸机BM-PERF。旧4.48/5.82ms串口污染与260us端到端日志保留。 |

实现映射：模型Finish覆盖真实finish或已取消后quiesce，Publish对应advance内发布判断，Destroy对应满足Q且P或closing后的控制块回收。模型不建模锁或多请求并发。Kani跨表转移证明针对内核实际复用的transfer_to，不替换为假想转移模型。

## KRN-1 长跑数据消费

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN1-DATA-01 | 运行中或短于8小时不接受；完整审查要求连续批次、基线守恒、完成及内核终态一致 | `tools/krn1/report.py::audit` | 契约/固定种子属性测试 | tested | `python3 -m unittest discover -s tools/krn1 -p 'test_*.py' -v` | 7项、seed0xb001及64资源变异；信任本地控制器单调时长与kernel标记来源，不认证恶意日志；不是实际8小时已通过 |

## ENV-0 executable contract (chatgpt)

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| ENV-ADMIT-01 | 无效观测保持已有租约；容量只下调；硬冲突原子拒绝；低临界度先卸载；软偏好不绕准入 | kernel-core/src/environment.rs Admission/Sample/Recovery | 契约测试 | tested | cargo test -p kernel-core environment:: | 固定种子4096采样；单核纯模拟；不证明执行器/平台/份额或截止期；开销预算是算术规格未实测 |
| ENV-PLAN-01 | 并发准备计划按版本提交，任何可达提交/降级后容量及独占不冲突 | verification/env0.tla Safety ↔ Admission::commit/observe/propose | TLA+ | model-checked | bash verification/run-env0-tlc.sh | 130可达状态/463生成/深度8，3任务/容量0..2/版本0..4，单核锁串行化，不覆盖弱内存/跨核事务 |

## KRN-2 first tranche (chatgpt; integration pending)

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN-TICKET-01 | 排号唯一持有、try_lock不绕过已排队票、不留下失败票洞、服务号安全回绕 | kernel-core/src/ticket.rs ↔ verification/ticket_lock.tla Safety | TLA+ | model-checked | bash verification/run-ticket-tlc.sh | 773状态/2479生成/深度25；3调用者/模4；生产u32未完成票数<2^32，持有者必须释放，未证明硬件内存模型或无条件进展 |
| KRN-TICKET-02 | 8线程32000次互斥发布、排队顺序、失败尝试和计数回绕 | kernel-core/src/ticket.rs tests | 契约测试 | tested | cargo test -p kernel-core ticket:: | 4组实际宿主测试；FIFO按取票顺序，不按API调用墙钟时间；非硬件弱内存证明 |
| KRN-WORKERS-01 | 成功发布增加、首次退出减少，切换未完成不能复用槽位，计数等于存活任务数 | kernel/src/sched/scheduler.rs spawn_on/mark_current_exited/live_workers ↔ verification/worker_count.tla | TLA+ | model-checked | bash verification/run-worker-count-tlc.sh | 81状态/145生成/深度17；2槽/各2代，调度锁内迁移假设，实际内核回归待完成 |
| KRN-GUARD-01 | 锁守卫不会自动允许跨线程共享非Sync载荷 | kernel-core/src/sync.rs SpinLockGuard、kernel-core/src/ticket.rs TicketGuard | 契约测试 | tested | cargo test -p kernel-core --doc | 两项compile_fail实际通过；IRQ守卫另为CPU本地不可Send，不声称类型检查能验证ISA中断状态 |

| KRN-DEADLINE-01 | 定容索引堆每槽最多一项；更新/取消不积累旧节点；未到期不弹出；错误代次拒绝且失败不改状态 | kernel-core/src/deadline.rs DeadlineHeap | 属性/契约测试 | tested | cargo test -p kernel-core deadline:: | seed=0x4b524e3248454150，20000步与8槽独立参考差分，失败删除操作收缩；另含容量/代次/u64末值；调用者独占且保持存储一致，非真实代码数学证明 |
| KRN-DEADLINE-02 | 串行化登记/改期/取消/到期/复用不会唤醒旧代次，排队项有界 | verification/deadline_heap.tla Safe ↔ Scheduler::block_current/make_runnable/tick/mark_current_exited | TLA+ | model-checked | bash verification/run-deadline-tlc.sh | 432状态/1801生成/深度9；2槽、2代、时刻0..2，调度锁串行；排序由真实堆差分测试验证，不声称证明每核消息或硬件弱内存 |
| KRN-RT-REFILL-01 | 周期推进保相位、不逐周期循环；下一边界必须严格晚于now或明确拒绝不可表示结果 | kernel-core/src/deadline.rs next_period | 契约测试 | tested | cargo test -p kernel-core deadline::periodic_tests | 30,720组小范围独立循环参考及u64末值/period0边界；未声称全整数域机器证明 |
| KRN-RT-REFILL-02 | 串行扣费/到期补充/退出中，预算不因补充而累加超过quota，活跃下一周期严格在未来 | verification/rt_refill.tla Safety ↔ Scheduler::charge_rt/set_rt/mark_current_exited | TLA+ | model-checked | bash verification/run-rt-refill-tlc.sh | 235状态/465生成/深度9，2任务/时刻0..6，非EDF/跨核预算/每核堆证明；执行器与准入仍TCB |
| KRN-YIELD-01 | 许可按已提交队列快照发布；本核IRQ屏蔽快路径的自愿yield标志不会归并到切换后的其他任务 | verification/yield_gate.tla Safe ↔ YieldGate/StateGuard/yield_now | TLA+ | model-checked | bash verification/run-yield-gate-tlc.sh | 130状态/233生成/深度14，单核2种owner、远程队列事务与本核切换；前提是当前槽仅由本核IRQ屏蔽路径切换，硬件原子/周期tick进展属TCB；未证明弱内存/有界延迟 |
| KRN-YIELD-02 | 撤销/发布与可合并自愿yield标志保持；空需求仲裁不改变aging；归并调用真实Watchdog::yielded | kernel-core/src/yield_gate.rs tests | 契约测试 | tested | cargo test -p kernel-core yield_gate:: | 3组真实函数测试；kernel完整百万次8核回归另验；不把空需求优化解释为关闭仲裁或跳过RT/组额度 |
| KRN-START-PEER-01 | CPU0 writer发布前CPU1 reader已经发布；参与屏障禁止过早测试工作 | verification/tlb_test_start.tla WriterHasPeer/NoEarlyWork ↔ krn0_tlb::run/writer/reader | TLA+ | model-checked | bash verification/run-tlb-start-tlc.sh | 先reader后writer的启动序；原顺序负模型立即违反WriterHasPeer；硬件CPU归属/公平进展为TCB，不声称参与屏障单独即可避免创建者被抢占 |

## KRN-2 全宽任务标签索引算法（尚未接入调度器）

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN2-IDX-01 | 压缩二叉索引沿途位号严格递增，查询至多64分支加1叶；完整u64标签精确匹配；删除归还叶和父节点；重复/满容量失败不改树 | `task_index::{TaskIndex,tests}` | 固定种子参考差分 + 结构属性测试 | tested | `cargo test -p kernel-core task_index -- --nocapture` | seed=0x4b524e3249445831，20000操作、独立BTreeMap、删除收缩；65标签覆盖实际深度64；调用者串行化且存储不被外改；不证明真实调度器/并发/硬件或性能 |

契约：N个标签最多需要2N-1节点，零节点拒绝插入。借用或拥有的定容slice容器均可；构造清空全部存储。插入不替换同名标签；删除不存在标签无变化；Token中的slot/generation仅原样保存，不自动分配或验证代次。结构审计逐操作检查树/空闲链无环、互斥、覆盖全部存储，所有参考键可达，节点位号单调。该算法无共享原子操作，不新增并发协议；真实任务预留/发布/回滚/退休仍待生产接入及独立生命周期模型，不能据此宣布代次槽定位已完成。

## KRN-2 槽位发布与代次生命周期（生产接入待完成）

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN2-SLOT-01 | 运行栈未detach前不允许复用；abort消耗代次且保留历史；旧预约不能提交/撤销新预约；旧代次不能操作新live任务；溢出拒绝且保留历史 | `task_lifecycle::SlotLifecycle`; `verification/task_lifecycle.tla` | 契约测试 + TLA+ | model-checked | `cargo test -p kernel-core task_lifecycle && bash verification/run-task-lifecycle-tlc.sh` | 33可达状态，77生成，深度10；负例重现旧代次1作用到新代次2；实际代码2组契约测试通过；单个规范槽、2代次模型；串行持锁调用，同一slot只初始化一个规范状态；真实索引与任务表的原子提交、进程全局ID唯一性、跨CPU协议尚未接入 |

实现对应：Reserve递增sequence并保留published历史；Abort只撤pending而不退sequence；Publish只接受匹配Reservation并原子替换槽内published（索引更新仍是调用者契约）；Dispatch/Exit/Detach分离任务退出与执行栈释放；live对slot+generation精确比较。TLA把标签和索引预检抽象掉，只枚举一次一槽两代次的完整生命周期及旧消息滞留。CheckGeneration=FALSE负例必须产生Safety反例。测试覆盖实际u64::MAX、外槽token、过期预约、历史保留和正在执行时拒绝预留；不把模型覆盖扩大成真实Scheduler证明。

## KRN-2 真实调度器标签定位接入

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN2-IDX-PUB-01 | 一次锁内发布后每个历史标签恰好指向一个规范槽；复用删除旧标签；live重复标签和栈未换下标签拒绝；退出历史可查 | `Scheduler::{spawn_on,historical_slot,live_slot,wake,cpu_ticks,grow,prepare_switch,finish_switch}`; `scale_demo::identity_contracts` | TLA+ + 实际内核契约回归 | model-checked | `bash verification/run-task-index-publish-tlc.sh && bash scripts/s2.sh` | 433状态/1333生成，2槽3标签每槽2代次；负例不删除旧标签产生IndexMatches反例。模型抽象掉堆树布局/分配失败；真实8核TCG百万调用与新增重复/历史/复用/资源断言通过；不是弱内存/真并行性能或真实代码Kani证明 |

对应：规范epochs与TaskIndex同由StateGuard保护。spawn_on优先复用同标签的已退出且换下槽；活/在栈标签返回DuplicateId；reserve后索引替换预检失败可恢复历史映射并abort（消耗代次），成功后publish/构造任务/入队在同一锁事务内完成。每槽仅一个历史标签，2*N-1节点保证有容量；grow先准备全部表/新树、从规范历史重建索引，再无失败commit，后续栈分配保留原来的部分可用契约。生命周期dispatch仅在真正换入新worker时执行，finish_switch才detach；退出不会提前释放栈。historical_slot校验标签、slot、generation及实际Task.id，live_slot额外查生命周期live。boot标签0在未初始化树前有固定槽特例；其余查询最多64分支+1叶、无任务表扫描。显式演练标签可复用，旧的裸TaskId标签调用本身不携带代次；未来异步消息必须携带Token并验证，不声称此步已经实现跨核消息协议。

## KRN-2 有界单tick本核预约（保守子集）

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN2-TICK-01 | 本核最多延期一tick；全局事务在任何owner/QoS/组/亲和变更前排空原owner记账；不可重复收费或跨代次；未排空不得重发许可 | `tick_lease::TickLease`; `sched::{lock_state,StateGuard,on_local_timer}`; `Scheduler::{tick_lease_owner,drain_local_tick}` | 契约测试 + TLA+ | model-checked | `cargo test -p kernel-core tick_lease && bash verification/run-tick-lease-tlc.sh` | 56状态/63生成/深度23，单CPU两owner最多3次tick；未清pending负例破坏守恒。真实代码2组核心契约通过；仅非RT/非配额组、无竞争者、非BSP且距量子届满>1tick的任务。模型不证明全部Rust/hardware/弱内存或吞吐 |

对应：global→按CPU升序取得全部leaf，排空pending后才执行回调，持全部leaf至事务完成发布新许可；放所有leaf后才放global/恢复IRQ。fast入口只try_lock本核leaf，失败先释放再走global，绝不leaf→global。许可携带规范Token，排空assert原current/代次/live/无预算组后调用真实account(c)，不是减少收费或虚构统计。每次最多一tick使排空严格有界；无竞争者及量子余量保证不跳过必要抢占。BSP、RT、CPU组、迁移、到期处理、余额不足、IPI请求和锁忙均原严格路径。pending自愿yield时拒绝新fast tick，因此待归并tick总早于仍pending的yield，先account后Watchdog::yielded；非可交换复位不能直接按计数相加。单槽模型只覆盖记账/owner迁移/互斥协议，此Watchdog顺序及真实策略行为由契约分析与完整内核回归约束，不冒充模型覆盖。

## KRN-2 有界跨核唤醒消息

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN2-WAKE-MSG-01 | 入队不覆盖；同Token可合并而不同代次不合并；满队列走同步回退；消费前校验live Token，旧代次不能唤醒新任务 | `wake_mailbox::WakeMailbox`; `Scheduler::{wake,drain_wake_mailboxes}`; `sched::lock_state`; `scale_demo::remote_wake_contract` | TLA+ + 契约/参考差分 + 实际内核回归 | model-checked | `cargo test -p kernel-core wake_mailbox && bash verification/run-wake-mailbox-tlc.sh && bash scripts/s2.sh` | 96可达状态/195生成/深度8，容量1、两独立槽各两代次；去掉代次检查/满时丢弃各产生Safety反例；核心容量0/2边界与seed0x57414b454d534731的20000操作参考及失败删除收缩/最终排空；实际CPU0→CPU1阻塞唤醒通过。仅串行全局锁协议；17任务真实满时回退见KRN2-WAKE-FULL-01，不是lock-free、弱内存证明或延迟性能验收 |

对应：wake对远程Blocked任务取得规范Token，目标CPU有16项定容FIFO；Queued/Coalesced均登记放锁后IPI，Full不丢请求而立即make_runnable。每次全局事务先归并本核tick/yield，再排空各mailbox，验证epochs.live(token)后调用真实make_runnable并按最新亲和/归属放置；同一代次多次阻塞之间也先排空，防旧唤醒跨到后续等待。未来若改为独立消费者，必须额外引入等待轮次或等价排空协议，不能直接沿用此结论。原IPI/周期tick/idle检查提供进展后备，模型没有公平性或最终送达结论。Mailbox仍受全局调度锁串行化且所有事务会排空，并未完成每核消费者独立化/去全局锁或微秒级等待框架。

## KRN-2 每所有者到期堆基础算法（生产未接入）

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN2-FOREST-01 | 每槽至多位于一个所有者堆；迁移立即移除旧节点；改期/取消O(log N)、取最早O(1)；错代次/越界/存储形状失败不改原状态 | `deadline_forest::DeadlineForest`; `deadline::DeadlineHeap` | 固定种子参考差分与结构不变量 + 删除收缩 | tested | `cargo test -p kernel-core deadline_forest -- --nocapture` | C=3、N=8、20000步seed0x44454144464f5231，独立参考检查每CPU最早项/计数、每槽位置/归属、所有错误前后状态；实际u64末值/C=0/坏形状边界。调用者串行化且外部slice保持一致；未接生产，不证明并发/CPU进展/硬件或Kani |

空间契约：C个所有者、N任务槽，entries恰好C*N、positions/owners各N；乘法checked，形状不符拒绝，caller初始化positions/owners为ABSENT。每CPU最多N条，共享单槽位置/归属表禁止节点跨堆重复；set迁移前检查来源/代次/目标容量，remove通过owner定位旧堆。条目按(at,slot)排序，平手确定；pop_due只取选定CPU已到期项，无全表扫描或迟延旧节点积累。纯算法FV-B，本轮没有新增并发协议；未来生产接入必须另外建模归属迁移、停表/到期IPI与每核消费，不能由此条目推导。

## KRN-2 每核到期处理的生产接入

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN2-DEADLINE-OWNER-01 | 到期节点只属于一个CPU；迁移移除旧归属，消费只在owner本地timer/idle路径；BSP对停表远程owner到期只发请求；弱公平下最终消费 | `Scheduler::{grow,rehome,wake_due,refill_rt,tick,local_tick,idle_enter}`; `verification/deadline_owner.tla` | TLA+ + 实际内核契约回归 | model-checked | `bash verification/run-deadline-owner-tlc.sh && bash scripts/s2.sh` | 14状态/18生成/深度5，单事件/2CPU/至多1迁移；Spec安全，FairSpec需BSP Tick及目标CPU接收/消费弱公平，非硬件保证。旧节点保留/不通知到期/非owner消费三个负例。真实CPU1→2已登记睡眠迁移、CPU2到期/运行与资源守恒；停表64+本地timer延后注入关联轨迹见KRN2-NOHZ-IPI-01，不额外推断旧常规样本因果轨迹；无Rust/Kani/弱内存或性能证明 |
| KRN2-RT-LOCAL-01 | AP实际运行tick也扣RT预算；remaining0必须等owner真正补充才可选；补充保持周期相位且不积累多份预算 | `Scheduler::{charge_rt,local_tick,refill_rt}`; `eligible_in`; `scale_demo::local_rt_contract` | 实际内核契约回归 + 既有周期算法测试/模型 | tested | `bash scripts/s2.sh` | 实际CPU1预算耗尽于下周期前、CPU1到期补充、关闭RT后退出/资源守恒通过；沿用u128推进及235状态补充模型，不把该旧模型扩大成多核预算证明；定时器/进程强制抢占仍TCB |

实现对应：两个DeadlineForest按任务home登记规范SlotLifecycle.generation，不再用可复用裸TaskId作代次。缓存根按CPU保存，set/remove只刷新相关owner，rehome在同一全局锁事务移动wake和RT两类节点。grow检查C*N容量、先准备全部存储并按新stride重建新森林，才无失败commit；栈分配延续原部分可用契约。BSP tick只消费CPU0并检查其他CPU根发IPI，AP local_tick/idle_enter消费本核，idle plan使用本核最早期限，已到期根禁止单tick快路径。所有操作仍global串行，不是每CPU锁的最终结构。Consume(c)抽象本核中断/idle检查，Move抽象同锁归属更新，Tick抽象BSP推进与到期通知；模型不覆盖真实heap排序/代次算法（分别属性测试/生命周期模型）、RT分组准入或真实IPI丢失。零预算仅时间到期不自动可选，必须有真实owner refill。

## KRN-2 满邮箱与延后本地timer的真实故障验收

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN2-WAKE-FULL-01 | 17个真实阻塞任务在同一正常wake事务中使16项邮箱满，额外1个走正常同步回退；队列与回退任务全部提前返回且资源守恒 | `sched::fault_wake_batch`; `scale_demo::mailbox_full_contract`; `Scheduler::wake` | 实际QEMU故障注入 + 扩展TLA+ | tested | `bash scripts/s2.sh` | fault-inject专用有界批处理helper，不写伪造队列项；queued16/fallback1/returned17、<100tick而非1000tick自然到期。Mailbox模型扩成2槽各2代次共96状态/195生成/深度8，覆盖两个不同live槽的满时回退及旧代次拒绝；非真实代码证明/无限并发或硬件时限证明 |
| KRN2-NOHZ-IPI-01 | 目标已登记停表且本地timer被注入延后时，BSP对同一Token/期限到期发通知，实际Reschedule IPI接收计数增加，目标CPU消费该期限并恢复任务 | `Scheduler::{fault_delay_deadline_timer,tick,wake_due}`; `scale_demo::deadline_owner_contract` | 实际QEMU故障注入 + 既有owner模型 | tested | `bash scripts/s2.sh` | 实际slot1/gen90/at16342，BSP通知与CPU2消费同一全局tick，stopped=true、实际IPI增1、consumer2；原始样本值非固定验收门槛。仅fault-inject改变本地timer计划而不改BSP通知/消费逻辑，不证明自然timer路径全部因果或微秒p99、物理HLT指令轨迹/弱内存 |

实现/观察边界：fault_wake_batch仅feature开启时存在，输入≤容量+1，循环调用真实wake，没有直接操作FIFO内容或伪造回退计数。延期timer仅把owner idle plan的本地期限提示暂置未知，仍使用原停表divisor=64及原IRQ预算条件；不强制修改StopBoard状态。BSP在实际到期根上记录Token/at/已登记停表及IPI计数基线，wake_due在同Token/at记录真实this_cpu与IRQ接收计数，观察标记不改变生产唤醒裁决。三个故障helper及trace字段在普通构建不出现；无fault-inject默认内核也实际构建通过。模型仍只Safety，无公平性/最终送达结论，owner进展模型的公平性假设另列。

| KRN2-SHARED-CREDIT-01 | 单个共享余额发布的延期信用总数扣费后仍为正；查询不改余额，重配置采用当前余额 | sched/limit.rs::CpuLimit::deferred_tick_credits | 契约测试 | tested | cargo test -p kernel-core deferred_credit_tests | 仅信用计算；尚未接入调度器，不证明并发分配、PI 或跨核执行 |

| KRN2-SHARED-CREDIT-MODEL-01 | 两核单发布周期的总信用小于共享余额；扣费归并先于配置修改 | shared_tick_credit.tla；对应CpuLimit::deferred_tick_credits和未来global→leaf协议 | TLA+ | model-checked | bash verification/run-shared-tick-credit-tlc.sh | 13状态；单位tick成本、初始余额2、两核一次发布；非生产接入/弱内存/PI/RT证明；duplicate与undrained负例均破坏Safety |

| KRN2-BUDGET-TICK-01 | 每CPU至多单tick；共享组总信用来自单余额；RT余量保留；配置修改前归并 | Scheduler::tick_lease_owners/drain_local_tick；StateGuard | shared_tick_credit/tick_lease模型与实际预算演练 | tested | bash scripts/s2.sh | 真实双AP共享组900与RT4/16：rt7/shared7/used40；百万八核通过。模型有限，不证明Rust弱内存或PI；yield预算限制不变，PI任务走原路径 |

| KRN2-CHURN-BARRIER-01 | 全部参与者就绪后才开始原2000轮工作；AP先发布避免CPU0阻断创建 | scale_demo::churn/contention；churn_barrier.tla | TLA+与实际参与/完成/CPU mask断言 | tested / model-checked | bash verification/run-churn-barrier-tlc.sh；bash scripts/krn2-churn-sample.sh UNIQUE_LABEL 1 4 8 | 模型11状态、提前放行反例；实际1/4/8核全部就绪/完成/正确mask、各2000轮。两核单次发布SC模型，非Rust弱内存/公平性证明；新测量需相同补丁施于基线；失败创建释放已创建任务但不算成功 |

| KRN2-LEAF-MEMBERSHIP-01 | 事务覆盖全部在线叶及自注册当前CPU；排空先于改owner；离线从未授予许可 | lock_state/StateGuard；Scheduler::cpu_online | TLA+ / 真实内核回归 | tested / model-checked | bash verification/run-leaf-membership-tlc.sh；bash scripts/s2.sh | 两核单调online/SC/最多3已接受tick，147状态，漏当前注册叶反例；真实百万八核通过、原空闲断言不变；不支持CPU离线，不证明Rust弱内存 |

| KRN2-SYNC-WORK-01 | 可选诊断分别报告global事务和实际叶获取；拆锁后叶获取必须非空、不超过`online*transactions`，争用数不得超过实际获取数 | sched::SYNC_WORK / scale_demo::contention | 实际内核计数契约 | tested | `bash scripts/krn3-postsplit-sample.sh UNIQUE 4 8`（仅VM） | KRN-3后4核82/283/上界328、8核284/1999/上界2272，分别避免45/273次叶获取；仅观测、不参与许可，含控制面和观察事务；leaf_contended是叶锁非零自旋，不同于global try_lock失败；32位无回绕窗口，不含物理成本，默认关闭 |

| KRN1-WRAPPER-SNAPSHOT-01 | 长等待期间公开脚本字节偏移被修改后仍仅执行原命令一次 | tools/krn1/vm_run_fixture.sh / 外层vm-run.sh | 隔离Shell契约测试 | tested | python3 -m unittest discover -s tools/krn1 -p test_vm_run_snapshot.py -v | 暂停假的传输后原地修改公开夹具，实际Bash快照只执行一次；不验证SSH/内核；外层原子部署，夹具与部署脚本实测相同 |

| KRN2-RAW-TIMING-STORE-01 | 固定容量原始记录满时拒绝原样返回且不覆写历史；跨CPU或逆序counter不计算差值，保留身份及原值 | raw_timing::Samples / Sample::local_delta | 契约测试 | tested | cargo test -p kernel-core raw_timing | 容量0/1/3、满后98次拒绝、丢弃计数饱和、迁移/逆序/u64边界；调用者必须串行独占访问；未生产接入，不验证counter同步/序列化/校准、唤醒身份真实性或并发协议，无p99/物理时间结论 |

| KRN2-RAW-CALLBACK-01 | 可选真实with_mut回调原始记录保留进入时槽代次及同核端点，满时不覆写且报告丢弃 | Scheduler::raw_callbacks/raw_callback_identity；sched::with_mut/raw_callback_snapshot；scale_demo::contention | 真实内核契约与存储契约测试 | tested | KRN2_OBSERVE=1 bash scripts/krn2-churn-sample.sh UNIQUE 1 4 8 | 沿用同global IRQ锁串行，无新增锁或调度决策；实际1/4/8核4/50/64记录、0/0/133拒绝；8核complete=false故不可作全样本p99。path1仅回调，不含等待/归并/发布/解锁/IPI；wait_round0是非等待记录，idle代次0；非唤醒关联/校准/弱内存证明，默认关闭 |

| KRN2-WAKE-PAIR-01 | 串行诊断配对不覆写未消费起点；槽/代次/轮次不符不能消费；每轮最多完成一次且序号耗尽拒绝 | raw_timing::WakePair；wake_pair.tla | 契约测试 / TLA+ | tested / model-checked | cargo test -p kernel-core raw_timing；bash verification/run-wake-pair-tlc.sh | Rust实际覆盖100轮/重复begin与finish/旧代次/旧轮次/跨CPU原值/u64耗尽；模型只两轮单对象串行唯一完成，无Token数学或真实内核/弱内存/送达证明；未生产接入，未来每Task新建并按规范Token调用 |

| KRN2-RAW-WAKE-SELECTED-01 | 真实Blocked→Runnable到首次选择的诊断记录匹配规范Token与轮次且不重复消费 | Task::raw_wake/raw_wake_round；Scheduler::make_runnable/prepare_switch/mark_current_exited；scale_demo | WakePair模型/契约与真实内核记录审计 | tested / model-checked | KRN2_OBSERVE=1 bash scripts/krn2-churn-sample.sh UNIQUE 1 4 8 | 同global IRQ锁串行元数据，Task::new重置、begin/finish拒绝和退出未完成显式计数；实际每档64条唯一键，跨CPU0/40/37条，丢弃92/82/66，全部complete=false。模型只两轮唯一消费，非真实Rust/弱内存/第一指令或时钟同步证明；不含入邮箱前等待，窗口可能含重置前起点，不完整统计当前未完成起点，不能作全量p99 |

| KRN2-SLEEP-REGISTRATION-01 | 要求每次真实睡眠的演练必须原子取相对期限并登记阻塞，不让锁外期限提前过期变成空操作 | balance_demo::interactive；Scheduler::block_current_for；sleep_registration.tla | 有界TLA+与真实内核契约 | tested / model-checked | bash verification/run-sleep-registration-tlc.sh；KRN2_OBSERVE=1 bash scripts/krn2-churn-sample.sh UNIQUE 1 4 8 | 单次登记/clock0..2，无送达/弱内存证明；分开读期限与登记的负例能漏阻塞，现有sleep_ticks接口保持原20轮/20样本断言。原失败20调用19样本保留，不放宽门槛 |


## Main-side pre-integration scopes retained for review

The following complete main-side registry (including assumptions/tool versions) is retained as historical provenance, not new integrated acceptance or expanded proof scope.

# 形式化验证性质登记

> 本表是 jasper-os 的机器可读性质登记。每行只陈述一条可判定性质；状态只允许
> `proved / model-checked / tested / assumed / exempt`。`model-checked` 只对模型成立，
> 不等于代码级机器证明；`tested` 只表示指定验收在指定环境真实通过。

## 代码版本、工具与环境

- 代码基线：`dc2a150`（A64-U 审计完成时的 `main`/`oc/Q64`）；本轮 FV-0 只新增
  `verification/` 下的资产与登记表，不改内核功能代码。
- 模型：TLA+ 模块 `verification/tlb_shootdown.tla`，配置 `verification/tlb_shootdown.cfg`。
- 工具：TLC 2026.10.20.183001（`tla2tools.jar` 1.8.0），Java 21，4 个 worker。
- 环境：构建虚拟机（宿主命令一律经构建虚拟机转发执行）；QEMU 只验 x86_64。
- 复现命令均在构建虚拟机内、仓库根目录执行；宿主不直接运行 cargo / qemu。
- PDA-0 工具基线：`abfe0b8`（`oc/Q69`）；Python 3.14.4（构建虚拟机），仅标准库。

## 可信计算基（TCB）与全局假设

**TCB（被视为正确、不在模型内证明的部分）**

- x86_64 分页硬件：页表写入在 `invlpg` / 重写 CR3、清除并恢复 CR4.PGE 之后不再从 TLB
  返回旧转换；`invlpg` 只作用于本处理器。
- 核间中断（IPI）投递：只要目标核在线且未屏蔽该向量，中断最终被取走并执行处理函数；
  `send_ipi` 返回错误时由实现显式撤销请求，不依赖“错误后仍送达”。
- 自旋锁 `SpinLock` 提供互斥与临界区内的顺序一致可见性；`CpuSet` 位图操作不丢位。
- 页帧分配器不会把仍被任何地址空间引用的帧重新分配（KRN-0 的帧守恒由验收覆盖）。
- 编译器、链接器和 QEMU/硬件模拟器不改变 Rust 源码的语义。

**模型边界（明确未覆盖）**

- 只建模**一段页表范围**的一次版本推进与一次击落；不同范围的并发修改由同一全局公告板
  串行化，是比模型更强的约束，模型未展开多范围交错。
- 不建模页表并发写入的内存序、嵌套分页、PCID/ASID、用户态与内核态地址空间切换的细节。
- 不建模 IPI 发送失败路径、核上线/下线竞态、进程退出时的地址空间拆除；这些由实现分支和
  现有 QEMU 验收覆盖，不在本模型内证明。
- 不建模同一物理帧被两个地址空间别名映射的情形；帧所有权唯一由内存管理接口约束。
- `kernel::proc::unmap_range` 在击落超时后保持 `shootdown_pending`（失败即停，后续修改返回
  Busy），而模型允许公告板层在 `Timeout` 后重试；这是可用性边界，不是安全性质，本轮不改功能代码。
- `ShootdownBoard::is_complete(generation)` 对“代号不同”的新请求也返回完成；模型假设等待者
  在自己等待期间不会出现另一个请求（同一时刻至多一个在途请求 + 只有发起方等待），该假设在
  当前实现结构下成立。

## 实现与模型的对应

| 模型元素 | 代码符号 |
|---|---|
| `tableVersion` / `Publish` | 页表修改先于击落：`kernel::proc::unmap_range`、`kernel::proc::protect_range`、`kernel::mm::map::{unmap,unmap_pages,protect}`、`kernel::mmio::Mapping::drop` |
| `request`（owner/version/targets/acked/revoked） | `kernel_core::smp::ShootdownBoard` 的 `BoardState.request: Option<Shootdown>`；`Shootdown{pending,generation}`；`ShootdownBoard::{begin,begin_all,begin_request}` |
| `Respond`（本地作废 + 应答） | `kernel_core::smp::ShootdownBoard::service`；`kernel::smp::service_shootdown`；`kernel::arch::x86_64::smp::{tlb_flush_local,tlb_flush_all_local}` |
| `Complete`（全部应答） | `ShootdownBoard::service` 在 `pending` 清空时移除请求；`ShootdownBoard::is_complete` |
| `Timeout`（撤销等待） | `kernel::smp::tlb_shootdown_on` 的超时分支调用 `ShootdownBoard::abandon` |
| `Release`（归还帧） | `kernel::proc::unmap_range` 在击落后执行 `p.frames.retain(...)` 与 `crate::mm::pin::release`；`kernel::mm::map::unmap` 返回帧 |
| 目标集合 | `kernel::mm::space::VmSpace::active_cpus`；`kernel::smp::online_set` 与 `CpuSet::without` |

## 登记条目

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN-TLB-01 | 页表修改完成且所有目标核应答前，不归还任何可能仍被旧 TLB 引用的数据帧；释放版本的每个核视图都不旧于该版本 | `kernel::proc::unmap_range`; `kernel::mm::map::unmap`; `kernel::mm::map::unmap_pages`; `kernel::mmio::Mapping::drop` | TLA+ + QEMU | model-checked | `bash verification/run-tlc.sh`（性质 `ReleasedNoStale`）；`bash scripts/accept.sh`（QEMU 行 `TLB-KRN0`） | 模型只覆盖单范围；释放动作在模型中独立于超时，超时路径永不释放；QEMU 覆盖 x86_64 单核/4 核 |
| KRN-TLB-02 | 已加入应答集合的核，其本地视图等于请求版本；实现中“本地作废”和“从待应答集合移除”在同一临界区完成 | `kernel_core::smp::ShootdownBoard::service`; `kernel::smp::service_shootdown`; `kernel::arch::x86_64::smp::tlb_flush_local`; `kernel::arch::x86_64::smp::tlb_flush_all_local` | TLA+ | model-checked | `bash verification/run-tlc.sh`（性质 `AckedNoStale`） | 模型把作废与应答合并为一个原子动作；不建模 `invlpg` 本身的硬件延迟 |
| KRN-TLB-03 | 超时撤销后公告板没有在途请求，也没有核停在等待阶段；撤销路径不释放帧 | `kernel_core::smp::ShootdownBoard::abandon`; `kernel::smp::tlb_shootdown_on` | TLA+ | model-checked | `bash verification/run-tlc.sh`（性质 `NoResidualWait`） | 模型允许撤销后重试；`proc::unmap_range` 的失败即停路径未建模，见模型边界 |
| KRN-TLB-04 | 同一发起核针对同一页表版本的击落至多释放一次；并发发起者遇到在途请求返回 Busy，不能各自释放同一轮次 | `kernel_core::smp::ShootdownBoard::{begin,begin_request,service}`; `kernel::proc::unmap_range` 的帧归还 | TLA+ | model-checked | `bash verification/run-tlc.sh`（性质 `NoDoubleRelease`） | 释放计数按（发起核, 版本）登记；不建模两个地址空间别名到同一物理帧的重复释放 |
| KRN-TLB-05 | 超大页范围只登记一次击落，并在每个目标核上执行整表刷新（目标只收到一次核间中断） | `kernel_core::smp::ShootdownBoard::begin_all`; `kernel::smp::tlb_shootdown_on`; `kernel::arch::x86_64::smp::tlb_flush_all_local` | 单元测试 + QEMU | tested | `cargo test -p kernel-core shootdown && bash scripts/accept.sh` | 整表刷新通过临时清除 CR4.PGE 覆盖全局项；未在真机验证 |
| KRN-TLB-06 | 两个任务分别钉在 CPU 0/1，196 批共 100,352 页 map/写/并发读/批量 unmap，读者 0 次读到他人数据；击落后其他核读到新映射 | `kernel::krn0_tlb::run`; `kernel::smp::tlb_shootdown_on` | QEMU 压力测试 | tested | `bash scripts/accept.sh` | x86_64 两核、内核映射窗口；不是用户地址空间的故障注入测试 |
| KRN-MMIO-01 | MMIO 槽位只在空位比较交换成功后推进，映射丢弃后位图恢复且槽位耗尽安全拒绝 | `kernel::mmio::{allocate_slot,release_slot,Mapping}` | QEMU 压力测试 | tested | `bash scripts/accept.sh` | 10,000 轮单线程映射/丢弃；并发争用由 CAS 结构保证，未做独立宿主模型 |
| KRN0-WRAP-01 | 中断到达计数从 `u32::MAX-3` 起递增 6 次后，按模差读到 6；已绑定槽位计数不被清零 | `kernel_core::interrupt::arrivals_since`; `kernel::irq::count_arrival` | 单元测试 + QEMU | tested | `cargo test -p kernel-core interrupt && bash scripts/accept.sh` | 局部计数走与真实路径相同的递增和求差函数 |
| KRN0-DMA-01 | virtio 复位超时后，只有关闭总线主控并读回为关时才归还队列帧，否则永久隔离 | `kernel_core::dma_quiesce`; `kernel::virtio::quiesce_with` | 单元测试 + QEMU | tested | `cargo test -p kernel-core dma_quiesce && bash scripts/accept.sh` | 真实 virtio-rng 不可用时 QEMU 用例报告跳过 |
| L10N-01 | 接口登记表每条 `error`/`op` 的中英显示名齐全；构建期生成的错误渲染表条数、顺序、文本与登记表逐字一致；非错误与未登记错误码被拒 | `abi/system-ids.txt`; `kernel/src/syscall/table.rs::ENTRIES`; `kernel/src/l10n_demo.rs::run`; `kernel_core::l10n::{render_error,table_is_sorted_unique}` | QEMU + 单元测试 | tested | `cargo test -p kernel-core l10n && bash scripts/accept.sh` | 验收检查 x86_64 单核与 4 核；AArch64/RISC-V 冻结不跑 |

## BM-1 虚拟机引导与日志协议

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| BM1-DMA-01 | 发送描述符仍归设备所有时保留 DMA 帧，失败路径不归还帧，客户机复位才终止该生命周期 | `kernel::arch::x86_64::bm1::upload`; `verification/bm1_boot.tla` | TLA+ | model-checked | `bash verification/run-bm1-tlc.sh` | 3 分包的单次启动抽象，45 状态；设备 DMA/复位与锁序由实现和环境承担，未证明真实硬件内存序 |
| BM1-ACCEPT-01 | 模型只有在全部分包、校验、串口对应、屏幕检查及复位满足后才可接受 | `tools/bm1/run.py`; `verification/bm1_boot.tla` | TLA+ | model-checked | `bash verification/run-bm1-tlc.sh` | hash/串口/屏幕验证被抽象为可信步骤；不证明 Python 实现或截图文字，实际十次启动见 BM-1-VM.md 证据 |
| BM1-LOG-01 | 固定种子输入乱序仍还原原文；缺包不完成；损坏、重复、跨启动及截断输入被拒 | `tools/bm1/run.py::{decode,Assembly}` | 属性测试 | tested | `python3 -m unittest discover -s tools/bm1 -v` | seed=0xB001；边界最小用例1字节，随机最长20000字节；不是代码级证明，FNV1a 不抗恶意碰撞 |

实现对应：`Submit/Complete` 对应 `upload` 中写 TSD 后轮询 TX OK；DMA 帧没有回收调用，错误即保留到复位。`Receive/Verify/Reset/Accept` 对应接收器分包累计、校验与串口比较、QMP RESET 计数和最终汇总。模型无公平性或最终完成结论，模型不单独代表连续十次虚拟机验收；实际十次及四核日志另有逐字节回放证据。

| BM0-AGG-01 | 汇总只豁免明确标记的计时 TIME；功能 TIME、FAIL 与未知状态仍阻塞，说明中的 PASS 不改变状态 | `scripts/accept.sh::row_nonblocking` | 契约测试 | tested | `python3 -m unittest discover -s tools/bm1 -v` | 表驱动9个状态边界；不证明整个 shell 脚本 |

## PDA-0 启动链只读解析（os 车道 / FV-B）

本轮只新增 `docs/PDA-0-boot-chain.md`、`docs/PDA-0-inputs.md`、`tools/pda/`
与 `.gitignore` 的 dump 忽略项；不改内核/ABI 功能代码。工具只读设备 dump，
不刷写、不写分区；真实 C66 数据尚未提供，设计文档中的设备侧结论一律标
「待设备数据验证」。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| PDA-BOOTIMG-01 | 对 boot image v0–v4，解析器接受的镜像必满足：魔数 `ANDROID!`、`header_version∈0..4`、头长度与版本一致、页大小合法、kernel 非空、每个声明段在文件内且页对齐、按序不重叠；任意截断（切在最后声明段结束前）、非法魔数/版本/页大小/头长度均被拒绝 | `tools/pda/bootimg.py::{parse,build_synthetic_image}` | 属性测试 | tested | `python3 tools/pda/bootimg.py --self-test && python3 -m unittest discover -s tools/pda -v` | seed=0xB007；每版本 400 次 1–4 位突变，截断逐字节，失败时收缩；不是代码级证明；不覆盖 vendor_boot、v5+、厂商私有重打包；未用真实 C66 数据 |
| PDA-DTB-01 | 对 FDT 版本 16/17，解析器接受的 DTB 必满足：`totalsize≤文件长度`、结构块/字符串块/保留内存块在 totalsize 内且对齐、属性名偏移/长度/NUL 有界、节点嵌套≤64、根名空、兄弟节点与属性不重名；任意截断、越界偏移、缺失 `FDT_END`、版本不在 16/17 均被拒绝 | `tools/pda/dtbinfo.py::{parse,analyze,build_synthetic_fdt}` | 属性测试 | tested | `python3 tools/pda/dtbinfo.py --self-test && python3 -m unittest discover -s tools/pda -v` | seed=0xD7B0；800 次 1–4 位突变 + 80 棵随机树往返 + 逐字节截断；不解析 `interrupts-extended`、phandle 图、`interrupt-map` 与厂商私有属性语义；未用真实 C66 DTB |

工具边界：`bootimg.py` 只解析 boot.img，不解析 `vendor_boot`；`dtbinfo.py`
只对结构做严格边界检查，并把常见 binding 归纳成启动摘要，不声称完整 DTS
语义验证。属性测试的「通过」仅表示固定种子输入上真实通过，不等于 `proved`。

## PDA-1 arm64 Image 头与 DTB 启动摘要（os 车道 / FV-B）

本轮改动：AArch64 启动路径新增 Linux `Image` 头自校验、设备树严格结构校验与
`[JSR-DTB]` 结构化摘要；新增 `kernel-core::image_header` 与
`fdt::{validate_strict, boot_summary}`。x86_64 行为不变；AArch64 单核
真实 `qemu-system-aarch64 -M virt -kernel <Image>` 启动由
`scripts/pda1-aarch64.sh` 验收。真实 C66 的装载地址、GICv3、GENI 串口、
cont-splash 帧缓冲仍未验证（见 `docs/PDA-1-image-dtb.md`）。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| PDA-IMAGE-01 | `Image` 头只有在以下条件全部成立时才被接受：长度 ≥64；偏移 0x38 为 `ARM\x64`；`text_offset` 按 2 MiB 对齐且 ≤1 TiB；flags 的 bit0=0（小端）、无保留位、bit3=0（本内核非位置无关）；`image_size` ≥64 且与链接跨度 `__image_end - __image_start` 完全相等。任意截断、非法魔数或上述字段不符都返回带规范名的结构化错误，启动路径打印 `[JSR-IMG] reject=<name>` 并以 35 退出，不进入 `kmain` | `kernel_core::image_header::parse`; `kernel::arch::aarch64::boot::jsr_aarch64_boot`; `scripts/aarch64-image.sh` | 固定种子属性测试 + QEMU | tested | `cargo test -p kernel-core image_header && bash scripts/pda1-aarch64.sh` | 种子 0x504441494d4147，4000 次 1–4 位变异 + 逐字节截断；QEMU 10.2.1 / cortex-a72 / 256M，Image 经 `text_offset=0` 由 QEMU 放到 0x40200000；真实 C66 ABL 的装载地址与压缩格式未验证 |
| PDA-DTB-02 | 对 FDT 版本 16/17，严格校验只接受：所有结构块/字符串块/保留块在 `totalsize` 内且对齐、属性名偏移/NUL/长度有界、嵌套 ≤16、根名为空、同一节点内属性名唯一、同一父节点下子节点名唯一；`boot_summary` 从 memory、`/chosen/bootargs` 与 `linux,initrd-*`、psci、interrupt-controller、timer、serial、`simple-framebuffer` 提取启动信息，缺失项保持 `None`。截断、越界偏移、非法魔数、重复属性/节点都被拒绝 | `kernel_core::fdt::{Fdt::validate_strict,Fdt::boot_summary,Fdt::find_named}`; `kernel::arch::aarch64::boot::{configure_devices,print_dtb_summary}` | 固定种子属性测试 + QEMU | tested | `cargo test -p kernel-core fdt && bash scripts/pda1-aarch64.sh` | 种子 0x50444144544202，3000 次 1–4 位变异 + 逐字节截断；QEMU 自动生成 DTB（1 MiB），`[JSR-DTB]` 字段逐项核对；未覆盖 GICv3 实际驱动、Qualcomm cont-splash、真实 C66 的 bootargs/initrd/帧缓冲 |


## S-2 故障注入与随机回归

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| KRN1-FAULT-01 | 显式arm后选定第n次调用只触发一次；未arm/触发后不注入 | `kernel_core::fault::FaultPoint`; `verification/fault_countdown.tla` | 属性测试 + TLA+ | model-checked | `cargo test -p kernel-core --test krn1_fault && bash verification/run-fault-tlc.sh` | 测试256种子及8线程；模型25状态、两个调用者、n=3；假设CAS线性化、工作负载静止时arm/disarm，不证明硬件原子实现 |

故障倒计时模型映射：`Hit(w)`为`FaultPoint::hit`的成功原子更新线性化点；`remaining=0`时`checked_sub`失败、不改变状态；`remaining=1`时唯一返回true。CAS重试及线程调度不可见，未证明并发重新arm（契约禁止）。KRN1-FAULT-01状态只对模型成立；实际帧/堆/复位/IPI挂钩需单独QEMU证据，不能由该小模型推导。

| KRN1-HOOK-01 | 显式注入帧/堆失败不扣资源，复位与IPI超时返回错误且下次重试可恢复 | `kernel::fault_inject::selftest`; `mm::frame`; `mm::heap`; `virtio::VirtioPci::reset`; `smp::tlb_shootdown_on` | QEMU契约测试 | tested | `bash scripts/s2.sh` | 4核TCG指令时钟，4站点一次触发；不覆盖全部调用者回滚或DMA在飞拆除；不作性能结论 |

## S-2 健壮性回归

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| S2-SEED-01 | 8个有效工作者使用互不相同固定种子、总探测数1000000，越界工作者被拒绝 | `kernel_core::argcase::{s2_seed,S2_PROBES,S2_WORKERS}`; `user/robust::_start` | 契约测试 | tested | `cargo test -p kernel-core --test s2_streams` | PRNG非密码学，输入流固定而调度不固定；测试不等于系统调用压力通过 |
| S2-MMIO-01 | 部分映射回滚未确认时槽位不允许复用 | `kernel::mmio::Mapping::map`; `verification/mmio_rollback.tla` | TLA+ | model-checked | `bash verification/run-mmio-tlc.sh` | 正例3状态无违例，旧行为negative配置出现NoStaleReuse反例；单槽位抽象，假设成功unmap包括远程TLB确认，不证明硬件内存序 |

| S2-CALL-01 | 8进程各125000次有界探测返回值符合预期、8核有实际调用且回收后资源回基线 | `kernel::s2::run`; `user/robust::{probe,_start}` | QEMU健壮性回归 | tested | `bash scripts/s2.sh` | 一轮8固定种子、1000528实际调用、每核125066；22探测类别不是全部系统调用全集；非弱内存证明，错误路径审计尚未全覆盖 |

## S-2 错误路径与启动屏障

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| S2-ERROR-01 | OOM/部分帧失败/击落超时的预期错误不导致进程退出回收后资源漂移 | `kernel::s2::process_error_tests` | QEMU契约测试 | tested | `bash scripts/s2.sh` | 4用例、无运行线程的测试进程；不覆盖故障核继续执行旧用户空间 |
| S2-MMIO-LIVE-01 | 实际回滚超时保留槽位，成功回滚及后续正常映射可回收 | `kernel::s2::mmio_rollback_test`; `kernel::mmio::Mapping::map` | QEMU故障注入 | tested | `bash scripts/s2.sh` | 单个实际BAR的2页映射；明确隔离1槽，未访问设备寄存器 |
| S2-DMA-NONE-01 | 读回未知时真实关主控后仍隔离队列，隔离数与未归还帧数相同 | `kernel::s2::dma_missing_readback_test`; `virtio::quiesce_with` | QEMU故障注入 | tested | `bash scripts/s2.sh` | 注入观测None；真实设备仍按规范运行；明确隔离4帧 |
| S2-START-01 | TLB自检writer只在双方登记后开始内存批次，等待时让出boot创建机会 | `kernel::krn0_tlb::{writer,reader}`; `verification/tlb_test_start.tla` | TLA+ + QEMU | model-checked | `bash verification/run-tlb-start-tlc.sh && bash scripts/s2.sh` | 模型检查启动安全性，不证明调度公平或原停滞唯一根因 |
| S2-ARM-01 | 同一真实机制库及集成契约在ARM用户态三轮全部通过 | `kernel-core`; `scripts/s2-pda.sh` | ARM宿主测试 | tested | `bash scripts/s2-pda.sh` | 405项×3轮，8线程；Android用户态musl，不是Jasper原生启动证明 |

## 复现说明

- 模型检查（构建虚拟机内）：
  `bash verification/run-tlc.sh`；脚本在缺少 `tla2tools.jar` 时从官方发布页下载 1.8.0，
  用临时元数据目录运行 TLC，结束后清理。期望输出包含 `Model checking completed. No error has been found.`
  与 `0 states left on queue`。
- 宿主经构建虚拟机转发的同一命令（在构建虚拟机内、仓库根目录执行）：
  `bash verification/run-tlc.sh`
- 全量 x86_64 验收：`bash scripts/accept.sh`（单核、4 核、8 核与 q35；AArch64/RISC-V 记 N/A）。
- 机械闸门：形式化验证闸门（仓库外工具），在仓库根目录以 `--base origin/main` 运行。


## Additional bm1 contract scopes

| KRN3-LEAF-RUNSTATE-01 | 每核 current、时间片与切换在途状态由对应 leaf 独占；切换发布原子写入 current/from，完成精确消费一次 from | kernel::sched::scheduler::RunLeaf/prepare_switch/finish_switch | 默认内核编译 + 受控4核定点guest | tested | `bash scripts/krn3-inbox-sample.sh runstate-20261026`（仅VM） | 脚本整批0、guest35；remote wake、16+1邮箱、lists_ok和资源回收通过。CPU cap50下既有两项时序失败，非默认套件PASS；Task热状态仍在全局锁内，未证明热路径已去全局化 |
| KRN3-LEAF-LINKS-01 | 每核 leaf 同时拥有运行列表表头与槽位链接；跨核迁移同时持源/目标 leaf 后原子摘链/入链；启动扩容在全部 leaf 链接表准备成功后才提交 | `kernel_core::sched::RunLists::{first,next}`; `kernel::sched::scheduler::{RunLeaf,LeafSlots,rehome,relist}` | 运行链契约 + 默认内核编译 + 受控4核定点guest | tested | `cargo test -p kernel-core sched::runlist`; `bash scripts/krn3-inbox-sample.sh leaf-links-20261026`（仅VM） | core 6项通过；脚本整批0、guest35、source前后同，remote wake、16+1邮箱、lists_ok和资源回收通过。CPU cap50既有时序项不计默认PASS；Task热状态仍在全局锁内 |
| KRN3-TASK-HOT-IDENTITY-01 | 分槽热状态只接受完整槽号与代次匹配的读取、修改和退役；槽位复用后旧命令不能修改新任务 | `kernel_core::task_hot::Slot` | Verus+Z3 / Proptest / Miri / cargo-fuzz / Kani / Loom | tested / bounded Kani | `bash verification/toolbox/run-krn3-task-hot-suite.sh`（仅VM） | Verus 3项、Proptest/Loom 3项、Miri 1项、fuzz 10000次、Kani 2 harness 全过。Loom使用外部Mutex，Verus为身份逻辑伴随；尚未接入生产Task字段或证明IRQ/生产锁，不能据此标记KRN-3完成 |
| KRN3-TASK-HOT-WIRE-01 | 每个历史任务的代次热状态恰好由其home CPU leaf持有；跨核迁移退役源后发布目标，状态转换保持镜像一致 | `kernel::sched::scheduler::{RunLeaf,publish_hot,sync_hot,retire_hot,rehome,queue_audit}` | 默认内核编译 + 受控4核定点guest | tested | `bash scripts/krn3-inbox-sample.sh task-hot-fixed-20261026`（仅VM） | 首轮boot代次0/1不一致在tick25真panic并保留；修复后脚本0、guest35、source前后同，remote wake、16+1邮箱、lists_ok与资源基线过。当前为生产镜像，Task仍是权威状态且热路径仍取全局锁；CPU cap50既有预算/时序失败不计默认PASS |
| KRN3-LEAF-SCHED-ENTITY-01 | `SchedEntity`由完整任务代次绑定的home leaf权威持有；所有队列/策略写在leaf锁内与队列计数同事务，冷表镜像及审计不得分叉 | `kernel::sched::scheduler::{LeafTaskHot,with_leaf_hot,update_hot_sched,rehome,queue_audit}` | 六工具热槽切片 + 默认编译 + 受控4核定点guest | tested | `bash verification/toolbox/run-krn3-task-hot-suite.sh`; `bash scripts/krn3-inbox-sample.sh sched-hot-canonical-20261026`（仅VM） | Verus3/Proptest+Loom3/Miri1/fuzz10000/Kani2通过；默认编译过；guest脚本0/guest35/source同，remote wake、16+1邮箱、lists_ok与资源回收过。CPU cap50既有NOHZ/规模时序失败不计默认PASS；choose/decide及facade仍先取全局锁，KRN-3未完成 |
| KRN3-LEAF-CHOOSE-01 | waiting/抢占/普通策略选择在单个本核leaf锁内遍历运行链并读取完整代次热槽；实体引用不跨锁且策略不回调全局锁 | `kernel::sched::scheduler::{waiting,decide,prepare_switch}` | 默认内核编译 + 受控4核定点guest | tested | `bash scripts/krn3-inbox-sample.sh leaf-choose-fixed-20261026`（仅VM） | 首轮真实发现迁移后旧CPU缺本地hot而漏home检查，亲和任务仍跑旧核；修复后脚本0/guest35/source同，CPU3→1→2准确、remote wake、满邮箱、lists_ok与资源回收过。CPUcap50既有时序/预算失败不计默认PASS；facade仍先取KERNEL_SCHED |
| KRN3-FAST-LEAF-TICK-01 | 已授权AP tick持本CPU lease时在本leaf精确推进实体/策略/时间片一次；global drain只镜像并结算冷账，不重复实体tick | `tick_lease::try_tick_owner`; `scheduler::fast_leaf_tick/drain_local_tick`; `sched::on_local_timer` | core契约 + release编译 + 受控双核定点guest | tested | `cargo test -p kernel-core tick_lease`; `bash scripts/krn3-fast-tick-sample.sh UNIQUE`（仅VM） | core2项过；首轮仅hit1暴露quantum重复门槛并保留，修复后fast-leaf-tick-pass2整批0/guest33/source同，真实hits4且entity_ticks=busy_ticks=4、列表/热槽/资源过。仅无RT/无共享组单AP运行者；BSP/复杂AP路径保留global，不证明KRN-3完成或物理性能 |
| KRN3-LEAF-FINISH-01 | 上下文保存后由恢复CPU在本leaf精确消费一次switching_from并清除旧执行者热on_cpu；冷生命周期随后核对同代次历史再detach | `scheduler::{finish_leaf_switch,finish_switch}`; `sched::finish_switch` | 默认编译 + 受控双核真实切入/切出guest | tested | `bash scripts/krn3-fast-tick-sample.sh UNIQUE`（仅VM） | 首轮错误要求Exited任务仍live而真panic，失败保留；leaf-finish-fixed整批0/guest33/source同，leaf_finishes=2、列表/热槽/资源过。槽位复用/迁移仍由后续global冷事务串行化，prepare_switch尚未去global，非弱内存或完整KRN-3证明 |

| KRN1-SOAK-01 | 单客户机中每批1500轮用户IPC/Ring/线程/映射负载后，帧/对象/清理队列/固定帧及堆计数回到预热基线 | `kernel::soak::run`; `kernel::longrun_demo::run`; `tools/krn1/soak.py` | QEMU契约测试 | tested | `bash scripts/krn1-soak.sh` | 短时8核验证通过3000轮；8小时正式结果须另查status.json，当前不能宣称完成；不代表所有核持续满载或裸机性能 |
| KRN1-SOAK-02 | 控制器只在时长足够、已请求停止、客户机批次完成且健康终态后接受 | `tools/krn1/soak.py`; `verification/soak_accept.tla` | TLA+ | model-checked | `bash verification/run-soak-tlc.sh` | TLC13可达状态、深度7、无违例；把宿主单调时钟、串口标记及客户机计数器视为可信；不证明工作负载内部 |

## Latest resumed-execution diagnostic contracts

| KRN2-RAW-RESUME-01 | 同Token/round唤醒记录仅在恢复执行钩子消费，快照显式报告重置前和当前pending | sched::finish_switch/yield_with_cause；Scheduler::note_raw_resume/raw_pending_count | WakePair模型/契约与真实内核记录 | tested / model-checked | KRN2_OBSERVE=1 bash scripts/krn2-churn-sample.sh UNIQUE 1 4 8 | path3为切换返回/新入口Rust钩子，path4为未切换继续；IRQ屏蔽下钩子先读counter再拿原global锁。不是架构第一指令、未含邮箱排队、截断不能作p99；状态沿原锁串行，非弱内存证明 |
| KRN2-RT-TEARDOWN-01 | 实时工作任务配置完成前不得发布可使其退出的STOP | scale_demo::local_rt_contract；rt_worker_teardown.tla | 有界TLA+与真实内核契约 | tested / model-checked | bash verification/run-rt-worker-teardown-tlc.sh；KRN2_OBSERVE=1 bash scripts/krn2-churn-sample.sh UNIQUE 1 4 8 | 单worker单配置；早发STOP负例可先exit导致disable找不到任务；保持原实际耗尽/本核补充/disabled及资源断言。无完整RT调度/硬件/弱内存证明 |

| KRN2-PUBLICATION-COUNT-01 | Per-group publication count matches repeated accepted-owner scan; refusal is unchanged and reset starts a new publication | kernel-core/src/publication_credit.rs; kernel/src/sched/scheduler.rs::tick_lease_owners | Fixed-seed reference property with shrinking; shared_tick_credit model correspondence | tested | VM cargo test -p kernel-core publication_credit | Two tests passed (fixed-seed20000 requests and bounds/reset); production build and million-probe eight-CPU runtime regression passed; default1/4/8 runtime samples passed; no performance improvement claim; serialized under existing global and held leaves, no new delivery/weak-memory proof; O(C) only the count allocation/reset work, not all scheduler decisions |

| KRN2-GROUP-MEMBERSHIP-01 | Live group index has exactly positive-reference slots with no duplicates; last release removes before slot reuse | verification/group_membership.tla; scheduler.rs create_group/unref_group/charge_groups | TLA+ membership model and real RunLists/CpuLimit reference property | model-checked | VM bash verification/run-group-membership-tlc.sh | 807 states/depth13, stale-last-release negative fails; serial3slots/ref0..2/two creates, not pointer or weak-memory proof; fixed-seed20000 reference and default build/full local CI passed; million eight-CPU/default1/4/8 and large-capacity full x86 acceptance passed; no performance acceptance |

| KRN2-PI-WORK-01 | Measured and default full PI recompute retain prior QoS outputs; work counts saturate explicitly and actual walks include defensive stops | kernel-core/src/sched/inherit.rs::resolve_impl; pi_work.rs; tests/pi_work_reference.rs | Fixed seed20000 graph reference with prefix shrinking; exact-count and saturation contracts | tested | VM cargo test -p kernel-core --test pi_work_reference; cargo test -p kernel-core pi_work | Four tests and observe/default builds passed; full CI and diagnostic/default1/4/8 runtime passed; semantic slot visits and actual propagation steps, not cycles or elapsed/WCET; serial existing global guard, diagnostic window includes teardown before snapshot |

| KRN2-PI-ISOLATED-EXIT-01 | Removing a node with no incoming or outgoing wait edge leaves every survivor's effective QoS unchanged | scheduler.rs::mark_current_exited; verification/pi_isolated_exit.tla; tests/pi_work_reference.rs | TLA+ noninterference lemma and fixed-seed real resolver reference | model-checked | VM bash verification/run-pi-isolated-exit-tlc.sh; cargo test -p kernel-core --test pi_work_reference | 432 states/depth2, three nodes/two priorities/single exit; missing-outgoing negative fails; real resolver four-priority random graphs tested, complete CI and diagnostic/default1/4/8 runtime passed; precondition current effective classes reflect the original graph, no claim for a general incremental PI protocol |

| KRN2-GLOBAL-ORIGIN-01 | Serialized origin counts saturate explicitly, window reset leaves boot total unchanged, and snapshot source sums reconcile to the same-guard aggregate | kernel-core/src/sync_origin.rs; sched/mod.rs lock_state_from/global_origin_stats; scale_demo.rs | Exact source/reset/overflow contracts; explicit facade call-site audit and runtime reconciliation | tested | VM cargo test -p kernel-core sync_origin | Two core contracts, observe/default builds, full CI and diagnostic/default1/4/8 runtime passed; interrupted first diagnostic campaign and resumed8 recorded separately; source identities matched; six coarse entry categories, Read includes read diagnostics; same existing global guard, no new protocol or scheduling input; finite non-wrapping old u32 aggregate window, counts are not elapsed time or contention attribution |

| EVT1-ENROLL-01 | Atomic condition check plus registration prevents a terminal event leaving a parked waiter without a pending wake | verification/ring_wait_enroll.tla; event_wait.rs registration boundary | TLA+ one-wait abstract enrollment model and split-enrollment negative | model-checked | VM bash verification/run-ring-wait-enroll-tlc.sh | 16 distinct states/33 generated/depth5, Safety and weak-fair Settles passed; split-check negative violates Safety; no Token/round, concrete queue, weak-memory or real IPI proof; production Ring integration pending |
| EVT1-WAIT-KEY-01 | Only matching task-generation and wait-round can consume once; deadline/ready priority and checked round exhaustion are explicit | kernel-core/src/event_wait.rs | Exact stale-identity, repeated-round, timeout/finish and exhaustion contracts | tested | VM cargo test -p kernel-core event_wait | Three actual core contracts passed (20000 repeated rounds, identity, deadline and u64 exhaustion); full CI 091d8ae3 passed; core component only; serialized caller must atomically check/register/block under established object-to-scheduler lock order; no production integration or delivery proof |

| EVT1-WAIT-LIFECYCLE-01 | Late old-round messages cannot wake a new wait; blocked/awake waiters retain exactly their abstract Ring references until cleanup | verification/ring_wait_lifecycle.tla | Two-waiter/two-round finite lifecycle model, stale-message and missing-release negatives | model-checked | VM bash verification/run-ring-wait-lifecycle-tlc.sh | 765 states/2809 generated/depth17, Safety passed; both negatives violate Safety; refs are abstract ownership, not real ObjTable counts, task teardown, weak memory or IPI progress |

| EVT1-WAIT-SET-01 | Bounded broadcast wait-set insert/remove/pop matches reference, duplicate task refuses unchanged and zero capacity fails explicitly | kernel-core/src/event_wait.rs::WaitSet; tests/event_wait_set.rs | Fixed-seed20000 Vec reference with deletion shrinking and zero-capacity contract | tested | VM cargo test -p kernel-core --test event_wait_set | Two actual contracts and full CI 091d8ae3 passed; unordered broadcast set, no FIFO claim; N must match admitted task capacity in future integration; core candidate not production wait queue or delivery proof |

| EVT1-IRQ-BINDING-01 | Pending IRQ captured under an old binding cannot notify a new binding after close/rebind | verification/irq_event_binding.tla | One-vector/two-generation finite model plus missing-generation negative | model-checked | VM bash verification/run-irq-event-binding-tlc.sh | 35 distinct/42 generated/depth8 Safety passed; missing-generation negative violates Safety; abstract pending set, no atomic implementation, IRQ lock order, real delivery or liveness proof; production IRQ integration pending |

| EVT1-PRODUCTION-WAIT-01 | Real Ring waiter enrollment, completion-before-yield, close/exit and deadline paths conserve object references; 1000 concurrent idle waiters do not resume without an event | ring.rs::wait_ready_for; evt1_demo.rs; sched Task event_wait | Existing enrollment/lifecycle models plus dedicated actual guest with default-independent 1024-slot profile | tested | VM bash scripts/evt1-mechanism-sample.sh UNIQUE_LABEL | Actual1/4/8 CPU guest exit33, four cases each, 1000 concurrent registrations/1000 ticks at100Hz/zero invalid resumes, full cleanup and conserved objects/pending/frames; nohz divisor4; singleCPU aligned icount5 and multicore icount0; kernel workers share production wait function, not 1000 CPL3 processes; earlier clock5 eightCPU broadcast timeout remains open, not fixed; opt-in guest; no claim for user deadline ABI or calibrated physical latency; guest tick window and raw host elapsed recorded separately; production default task ceiling unchanged |

| EVT1-DEADLINE-DESC-01 | Separate versioned deadline descriptor preserves the frozen legacy56-byte encoding and rejects unknown version/length/reserved bits | kernel-core/src/ring_abi.rs::EnterUntilArgs | Byte-layout and rejection contracts | tested | VM cargo test -p kernel-core until_contract | Two actual layout/rejection contracts passed; core descriptor candidate only; no syscall registered, no production deadline waiting or timeout result contract yet |

| EVT1-DEADLINE-OUTCOME-01 | Final locked observation prefers available completion over simultaneous timeout, close wins, and terminal cleanup releases the wait reference | verification/ring_wait_deadline.tla | One-wait/tick1 outcome model and timeout-first negative | model-checked | VM bash verification/run-ring-wait-deadline-tlc.sh | 35 distinct/60 generated/depth6 Safety and weak-fair Settles passed; timeout-first negative violates Safety; abstract final observations only; no concrete Token/queue/ABI or weak-memory proof; production integration exercised by CPL3 contracts and FULL accept-20261023-201909; model scope remains abstract |

| EVT1-DEADLINE-ENTRY-01 | Versioned deadline syscall reports submitted/reaped before timeout, preserves pending requests, prioritizes ready and waits until minimum caller/backend deadline | ring.rs::sys_enter_until/enter_args_for/wait_ready_until; user/ring/src/main.rs | Deadline outcome model plus real CPL3 contracts | tested | VM bash scripts/accept.sh (FULL, accept-20261023-201909) | Five real CPL3 deadline cases passed; FULL 454 core and single/4/8/q35/S2 functional checks passed, guest37 timing-only, batch0; new op33/error4132 append only, frozen legacy IDs/layout unchanged; finite model is not full Rust/weak-memory proof |

| SHM1-PAGE-LIFETIME-01 | A shared page cannot be recycled while mapped, pinned, awaiting TLB acknowledgement, or quarantined | verification/shm_page_lifetime.tla | One-page/two-process lifecycle model, missing-ack and missing-pin negatives | model-checked | VM bash verification/run-shm-page-lifetime-tlc.sh | 166 distinct/500 generated/depth10 Safety passed; both missing-ack and missing-pin negatives violate Safety; atomic metadata and truthful hardware acknowledgements assumed; no production Memory/Arc/page-table or weak-memory proof |

| SHM1-MAP-ADMISSION-01 | Checked object subranges and READ/WRITE/MAP permissions reject overflow and excess authority; mapped/pinned quota failures are atomic | kernel-core/src/memory_object.rs | Exhaustive permission masks, boundary contracts, 20k fixed-seed u128 reference with deletion shrinking | tested | VM cargo test -p kernel-core --test memory_object | 82158 batch0: exhaustive 256 permission masks/read-write cases, range boundaries and 20k quota reference/shrinking passed; core admission only; no production mapping, page ownership or real allocation failure coverage |

| SHM1-BACKING-INTEGRATION-01 | Shared mappings retain page backing after handle transfer/closure and pins survive both mapping removals; legacy unmap/protect cannot bypass shared ownership | proc::{create_memory,map_memory,unmap_memory,pin_user_in}; mm/pin.rs; shm_demo.rs | Actual kernel fixture plus page lifetime model projection in docs/SHM-1-status.md | tested | VM bash scripts/shm1-backing-sample.sh UNIQUE_LABEL | 7281 batch0/guest33/source unchanged, shared bytes, rights, direct handle transfer, PTE removal, pin-only lifetime and resource baseline passed; single CPU kernel callers only, no CPL3/channel transfer/cross-CPU revocation/full quotas/private-frame migration coverage |

| SHM1-PAGE-CHARGES-01 | Backing allocation charges follow retained pages across creator exit; pin charges are RAII and refused reservations do not mutate usage | mm/memory_quota.rs; mm/memory_object.rs; proc::{create_memory,pin_user_in}; shm_demo.rs | Core Usage reference plus actual kernel quota/creator-exit fixture | tested | VM bash scripts/shm1-backing-sample.sh UNIQUE_LABEL | 8802 batch0/guest33/source unchanged: actual total allocation rejection and one real pin charged; small real Account mixed charge split/refusal/drop passed; no 8192 simultaneous real pin exhaustion, user ABI, weak-memory or full Rust proof; private frames not yet object-backed |

| SHM1-MAP-DESCRIPTOR-01 | Object-map descriptors have fixed explicit LE layout and reject unknown versions, lengths, flags and reserved bits | kernel-core/src/memory_abi.rs | Layout/boundary roundtrip and malformed field contracts | tested | VM cargo test -p kernel-core --test memory_abi | 17300 batch0: layout/offset/roundtrip and unknown-field contracts passed; format only; semantic address/range/rights/quota checks remain separate, no new public syscall yet |

| SHM1-OBJECT-ABI-01 | New memory-object calls enforce caller process, strict descriptor, handle rights and checked ranges without altering legacy anonymous map ABI | syscall::{memory_object_create,memory_object_map,memory_object_unmap} | Descriptor and admission contracts plus planned CPL3 tests | tested | VM JASPER_ACCEPT=spot JASPER_CHECKS="m32 m43 m44" bash scripts/accept.sh | 79008/45076 batch0, real CPL3 alias/rights/handle lifetime/unmap and two-process Channel Memory handle roundtrip/shared atomic RW passed; op34/35/36 appended, frozen IDs unchanged; SPOT single CPU is not FULL or whole Rust proof |

| SHM1-REMOTE-REVOKE-01 | A CPU1 CPL3 load after CPU0 revokes its shared view and receives TLB acknowledgements raises PageFault, with backing resources reclaimed | proc::unmap_memory; shm_demo::{cross_cpu_revoke,revoke_controller}; user/ipc::revoke_probe | Real 4/8-CPU opt-in guest plus SHM lifecycle model | tested | VM bash scripts/shm1-backing-sample.sh UNIQUE_LABEL | 86882 batch0/1,4,8 guest33/source unchanged; 4/8 actual target set includes CPU1, post-ack fault at revoked VA and process -1, exact one fault/resources baseline; single CPU remote case explicitly skipped; CPU affinity constrained fixture, TCG functional evidence, no weak-memory/full Rust or physical performance proof |

| SHM1-UNIFIED-RAM-01 | Anonymous, ELF and stack RAM use canonical Memory pages; pin references outlive mapping and process destruction and are the sole retention path | proc::{map_new,map_anon,unmap_range,protect_range,pin_user_in,destroy}; mm/{memory_object,pin}.rs | SHM lifecycle model projection and actual 1/4/8-CPU fixtures | tested | VM bash scripts/shm1-backing-sample.sh UNIQUE_LABEL | 14723 batch0/guest33 in all three configurations/source unchanged: anonymous+loader ownership, pin-after-process-exit, legacy detached-pin witness, 8192 real live pins/8193rd refusal atomicity/return, metadata OOM no partial publication+retry, remote revoke passed; one exact-shape heap warmup precedes strict baseline pass; Arc/page tables/TLB hardware assumptions, not complete Rust/weak-memory proof |
| SHM1-FAILURE-ISOLATION-01 | Unconfirmed shared revocation/partial-map rollback never recycles published backing, while confirmed rollback reclaims all resources | proc::{map_memory,unmap_memory}; mm/memory_object.rs; shm_demo::shared_failure_isolation | Fault-injected actual 1/4/8-CPU fixture plus lifecycle model | tested | VM bash scripts/shm1-backing-sample.sh UNIQUE_LABEL | 14723: shared unmap IPI failure isolates1, actual one-page partial publication+map allocation failure with confirmed rollback isolates0, same rollback IPI failure isolates1; exact frame delta and object/pin baselines passed; isolated pages retain live creator charge without leaking account Arc metadata; no guarantee of hardware acknowledgement truth outside stated TCB |

| SHM1-USAGE-KANI-01 | reserve失败不变、成功精确记账且release恢复 | kernel-core/src/memory_object.rs::proofs | Kani | proved | cargo kani -p kernel-core --harness shm_usage_reserve_is_atomic_and_reversible | 任意u64、无assume；不含锁/Arc/页表 |

| SHM1-USAGE-TOOLBOX-01 | 真实Usage算术对u128参考；序列化准入仅一成功 | verification/toolbox/tests/usage.rs | Proptest/Loom | tested | cargo test --manifest-path verification/toolbox/Cargo.toml | Loom mutex替代生产锁，仅验证临界区准入组合，不证明生产锁/Arc/TLB |

| ABIR-SHAPE-01 | header拒未知版本长度、segment区分句柄与虚拟地址且拒溢出 | kernel-core/src/extension_abi.rs | 契约测试 | tested | cargo test -p kernel-core --test extension_abi | 仅线格式；不验证权限/固定/硬件，无生产操作启用 |

| S3-SHM-SEQUENCE-01 | 共享映射/低权限/转移/固定/退出随机序列无越权且回基线 | kernel/src/shm_demo.rs::randomized_lifetimes | QEMU | tested | bash scripts/shm1-backing-sample.sh UNIQUE | 64x16固定seed、预热与实测同形；串行实际API，非并发Channel/CPL3证明 |

| S3-SHM-CONCURRENT-01 | 受控CPU0 map/transfer与CPU1 pin/unmap/exit竞争，保活且资源回基线 | kernel/src/shm_demo.rs::concurrent_lifetimes | QEMU | tested | bash scripts/shm1-backing-sample.sh UNIQUE | 4/8核固定CPU0/1、64/128尝试非全成功计数，1核明确skip；不穷举弱内存 |
| S3-CPL3-CHANNEL-01 | 共享Memory经真实Channel32轮传递，撤销/降权拒绝/退出回收 | user/ipc/src/main.rs::s3_channel_ping/s3_channel_pong; kernel/src/ipc_demo.rs::s3_channel_roundtrip | QEMU | tested | bash scripts/shm1-backing-sample.sh UNIQUE | 33983 1/4/8各33、固定CPU角色；非恶意任意调度穷举 |
| S3-HANDLE-SEQUENCE-01 | 唯一所有者、restrict失败不变、stale句柄无效；去权限检查负例必败 | verification/toolbox/tests/handle_sequence.rs; negative/transfer.rs | Proptest/Miri/Loom/fuzz/负例 | tested | cargo test --manifest-path verification/toolbox/Cargo.toml --test handle_sequence; bash verification/toolbox/run-negative-transfer.sh | Miri禁磁盘失败记录不关闭隔离；Loom替代生产锁，Verus仅权限交集伴随，Kani旧生产rights/transfer范围不扩大 |

| S3-CPU-REFERENCE-TIME-01 | 同一单调参考时钟驻留busy+idle精确覆盖区间，快照不消费/逆时拒绝 | kernel-core/src/cpu_time.rs | 参考/契约测试 | tested | cargo test -p kernel-core --test cpu_time | 纯Ledger，尚未证明scheduler全部状态转换接入；不把本地IRQ计数当全局时间 |

| EVT2-SNAPSHOT-01 | 原子快照登记无缺口，有界队列溢出必须显式重同步 | verification/subscription_snapshot.tla | TLA+正/负例 | model-checked | bash verification/run-subscription-snapshot-tlc.sh | 70states/135generated/depth9；split与silent-overflow均Safety反例；单订阅/4发布/容量2，无生产实现或活性证明 |

| EVT2-QUEUE-CONTRACT-01 | 每订阅有界、溢出显式重同步、序号拒绝不变、合并跨度保留 | kernel-core/src/subscription.rs | 契约测试 | tested | cargo test -p kernel-core --test subscription | 55861两项过；固定1000发布双订阅，非并发/随机穷举或内核集成；合并协议模型仍待 |

| EVT2-SOURCE-LIFETIME-01 | source内部引用随订阅保留，关闭不提前销毁；关闭重复不释放两次 | verification/subscription_lifetime.tla; kernel/src/subscription.rs | TLA+正负例/QEMU | model-checked | bash verification/run-subscription-lifetime-tlc.sh | 8states/17gen/深4；提前释放负例真违例；19590核内1/4/8回归过，非Ring/CPL3或所有错误路径证明 |

| EVT2-USER-SOURCE-01 | 公开创建的Process/Task cap可按权限订阅，初始快照与退出事件无缺口；手工最小 ELF 携带与内核一致的程序 ABI 章 | kernel/src/subscription.rs; proc/spawn.rs; syscall/mod.rs; user/ring/src/main.rs | CPL3/QEMU | tested | bash scripts/evt2-object-sample.sh UNIQUE | 当前 4 核 plan guest 1073 行、exit33，公开 task/process.spawn 退出49/51 和 ABI note 均通过；历史 1/4/8 证据绑定旧 fixture；最小 ELF 为 x86 专用，非全 ISA/任意调度证明 |
| EVT2-PRESSURE-DIRTY-01 | 清dirty在采样之前，静止且无dirty时无漏最终状态 | verification/pressure_event_dirty.tla | TLA+正负例 | model-checked | bash verification/run-pressure-event-dirty-tlc.sh | 18states/21gen/深8；clear-after负例真违例；模型不证明硬件/内存序，实际压力State合并中间态 |
| EVT2-PUBLISHER-ANCHOR-01 | 活publisher保留anchor，用户cap全关后仍可重发放，结束后不复活 | verification/subscription_publisher_anchor.tla; kernel-core/src/objtable.rs; kernel/src/subscription.rs | TLA+/真实ObjectTable/QEMU | tested | cargo test -p kernel-core --lib publisher_anchor_keeps_source_regrantable_until_publisher_finishes | anchor正负模型/实际契约/80060全源三档过；不改ObjectTable Closing规则，非全图无环证明 |


## CPU budget observation-window correction

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| BUDGET-WINDOW-OBS-01 | 单观察者在调度器事务内arm/start，第一次BSP截止事务只捕获一次，finish区分固定窗口/完整生命周期/尾段并检查守恒，原160tick上界52不增大 | Scheduler::budget_window_arm/tick/budget_window_finish; balance_demo::limit | 实际八核隔离契约 | tested | VM CPU cap50且仅经vm-run执行 bash scripts/budget-window-sample.sh UNIQUE | budget-window-split-20261025整批0/guest33：window51<=52、life51<=60(elapsed190)、tail0、原资源断言过，source前后/host同。仅记账事务边界：pending已drain、当前BSP扣费前；不是硬件IRQ发生时间/弱内存/全调度证明。前置诊断cutoff49/life62的旧断言失败保留；原FULL54未逐tick还原。默认完整回归及纯窗口状态机/六工具覆盖仍待，不标proved |
| KRN3-TCG-WINDOW-01 | 全部负载参与者到达屏障后才清统计并发布窗口；窗口外睡眠者显式回收；85%忙碌、空闲等待2tick、交互延迟2tick原界不变 | scale_demo::{prepare_load,arrive_load,start_load,scale,overload} | CPU-cap50 TCG 4/8核定点guest | tested | VM `bash scripts/krn3-postsplit-sample.sh UNIQUE 4 8` | cap50-aligned-window-final-20261026整批0/guest33：4核最少忙60/119、等待0/1；8核59/119、等待2/2；failed0/timing_failed0、列表与资源守恒。证明夹具窗口在该配置稳定，不证明物理延迟、deadline→wake或整个Rust并发实现。主动yield与引导者开门两次失败保留。 |

| BUDGET-WINDOW-MODEL-01 | 截止快照一次捕获且尾段不能改写，finish保持窗口/尾段分账守恒 | verification/budget_observation.tla | TLC正模型+改写cutoff负例 | model-checked | bash verification/run-budget-observation-tlc.sh; bash verification/run-budget-observation-tlc.sh budget_observation_rewrite.cfg（预期Safety反例） | 50753整批0，71distinct/85generated/depth10；负例真Safety违例。仅单观察者、最多4次charge/3tick原子状态；不证明Rust/IRQ时刻/预算准入，Busy/溢出/迟截止尚未包含 |

| BUDGET-CORE-TOOLS-01 | 单CPU按eligible准入的CpuLimit保持窗口界与使用次数；分账整数恒等式成立 | kernel_core::sched::limit::CpuLimit; toolbox/tests/budget.rs; toolbox/src/lib.rs::budget_admitted_eight_steps | Verus伴随/Proptest/Miri/fuzz/Kani/Loom适配 | tested / bounded Kani | 见docs/EVT-2-status.md budget-tools-20261025 | 实际Verus8总proof/Miri8/Proptest128/fuzz10000/Kani8步1harness/Loom1；Kani显式合法rate/burst域假设，不证明多核准入/硬件时间/生产锁。Loom为Mutex适配，主FV1的15项不变；raw证据PASS不推断已丢失host session的总退出码 |

| RT1-PARTITION-FOUNDATION-01 | 每核准入不超容量，拒绝不删除原预留，纯算法只返回可容纳的允许核且不修改输入 | rt_partition::place; rt_partition_admission.tla; Scheduler::set_rt | 有限正负模型/两契约/六工具切片/真实4核fixture | tested / model-checked | bash scripts/rt1-admission-sample.sh UNIQUE（仅VM） | 模型128states/1741gen/depth7，negative真Safety；实际rt1-scheduler-admission-stable-20261025整批0/33。setup断言期间BSP IRQ屏蔽、之后正常运行，非CPL3/EDF/任意重配置并发证明；原跨时间快照失败保留。legacy RtSet与用户安全重配仍未迁移 |
| RT1-EDF-ENTRY-01 | 分区内最早绝对期末派发，用户RT声明需调用授权与Task CONTROL，取消不刷新本期预算 | Scheduler::prepare_switch/decide/set_rt; task_control; rt_partition_edf.tla; rt_reentry_debt.tla; rt_control_authority.tla | 有限正负模型/实际CPL3与kernelguest/纯选择六工具 | tested / model-checked | bash scripts/rt1-admission-sample.sh UNIQUE | 正EDF15state/debt126state/authority20state，负例真Safety；canonical-migration guest33，非用户第一指令/弱内存证明；Verus仅比较伴随，LoomMutex适配；时间单位ticks |
| RT1-CANONICAL-CAPACITY-01 | 仅Task预算计费；启动容量外拒绝原子，同声明幂等，退出释放容量，子线程继承CPU允许集 | rt::install; Scheduler::set_rt; syscall::task_spawn; rtclass_demo; arbiter_demo | 真实4核guest | tested | bash scripts/rt1-admission-sample.sh UNIQUE | rt1-canonical-migration-20261025整批0/33，RTCLASS14/0与ARB7/0；不含10000周期报告/所有Profile运行；bootcapacity配置原子不是第二份预留表 |
| RT1-PROFILE-RUNTIME-01 | 缺少sched.realtime的真实Profile拒绝获rt.set调用授权的用户进程，退出后无预留/资源泄漏 | profile::ACTIVE; task_control::rt_set; rt1_demo::profile_denial | CPL3契约guest | tested | RT1_FEATURES=rt1-no-realtime bash scripts/rt1-admission-sample.sh UNIQUE | rt1-profile-disabled-20261025整批0/33，HEADLESS_MIN双进程/资源；仅拒绝场景，非全Profile交叉组合证明 |
| RT2-TIMER-COUNTS-01 | 单次计数ceil且至少1，未知频率/超u32拒绝，不截断或饱和伪装有效延时 | timer_units::oneshot_counts | core契约/Proptest/Miri/fuzz/Verus伴随 | tested | cargo test -p kernel-core timer_units; toolbox timer_units | 纯换算，不含校准准确度/硬件期限；宽域Kani求解中止未证明 |

| RT2-ELAPSED-CREDIT-01 | 重复IRQ时间戳不铸造tick，累积小段保持floor总经过量，倒退拒绝不修改 | timer_units::PeriodicCredit; elapsed_irq_credit.tla | 正负模型/Proptest/Miri/fuzz/限定Kani/Verus伴随/Loom适配 | tested / model-checked / bounded Kani | run-elapsed-irq-credit-tlc.sh；toolbox timer_units | 模型21states/37gen/depth7；Kani仅period2/u8timestamps；不含跨owner分摊/真实时钟校准/弱内存锁证明 |
| RT2-LAPIC-PRIMITIVE-01 | ns单次定时写寄存器前验证，拒绝溢出无修改；诊断IRQ不算整tick且恢复周期 | apic::arm_after_ns; rt2_demo; irq::LocalTimer | opt-in真实4CPUguest | tested | RT1_FEATURES=rt2-verify bash scripts/rt1-admission-sample.sh UNIQUE | rt2-lapic-irq-20261026 whole0/33，MMIO/路由/资源；旧pendingIRQ未辨来源，非无早唤醒/物理延迟或RT2完整调度 |
| RT2-NS-INTEGRATION-01 | ns任务预算按执行owner区间扣费；新纳秒等待不早返回且退出可打断，旧ABI保留ticks | ns_budget::Budget; hrtime; Scheduler::settle_highres/refresh_ns_events/highres_event; syscall::time_wait_ns | owner正负模型/契约/属性/限定Kani/实际CPL3与kernelguest/默认旧功能定点回归 | tested / model-checked / bounded Kani | run-ns-owner-accounting-tlc.sh；RT1_FEATURES=rt2-verify scripts/rt1-admission-sample.sh UNIQUE；accept-20261026-113555 | rt2-production-routed-20261026整批0/4CPUguest33/source同，ns等待、BSP/AP、CPL3、预算、退出取消及资源全真；默认九项旧功能PASS、功能失败0，QEMU37仅TCG采样15/20。模型不证明真实TSC跨核校准/锁/弱内存/物理抖动；宽域换算Kani仍未证明，CPU纳秒值以校准域为准 |

| KRN3-LEAF-COMPLETION-01 | 恢复执行流在本核叶精确释放一次旧执行者并延迟冷detach；再次调度前必须消费且槽位不可提前复用，run返回等待远端最终completion | sched::scheduler::{finish_leaf_switch,take_leaf_switch_completion,workers_settled}; sched::lock_state_from | 代次热槽六工具切片复跑 + 默认编译 + 真实双核切换夹具 | tested | bash verification/toolbox/run-krn3-task-hot-suite.sh; bash scripts/krn3-fast-tick-sample.sh leaf-cold-deferred-final2-20261026 | guest33/整批0/source同，切入切出2次、fast tick4次精确、列表/资源通过；首轮run提前返回guest35保留；冷生命周期仍由全局事务结算，未证明prepare选择去全局锁、完整Rust弱内存或物理性能 |

| MAIN-GREEN-01 | 校准计数→纳秒换算（补链：自 hrtime::now 既有换算抽出）：hz=0 ⇒ None；否则结果 = floor(elapsed·10⁹/hz)，不落入 u64 ⇒ None（不回绕、不截断）；同一 hz 下对 elapsed 单调 | kernel_core::timer_units::counter_ns；kernel::hrtime::now | Verus伴随(下取整夹逼 n·hz ≤ e·10⁹ < (n+1)·hz、单调引理)/Proptest(对 u128 参考全域差分 512 例)/Miri固定序列/fuzz 100万(夹逼+单调+溢出判定)/Kani(hz=0 全域；夹逼与单调 8 位有界 + cadical)/Loom N/A：纯函数无共享状态，替代证据为 QEMU 定点 M1.1/T-2 走同一路径 | verified(model) / tested / bounded Kani | VERUS=… bash verification/toolbox/run-drill-time-suite.sh | Verus 0.2026.10.18 + Z3：9 verified/0 errors，负例 drill_time_bad.rs postcondition not satisfied；kernel-core timer_units 3 passed；Proptest 4 passed；Miri 1 passed；fuzz 100万 0崩溃 cov99；Kani 0.68 uncalibrated_is_none、floor_is_exact_and_monotone_bounded（474 s）SUCCESSFUL。全域 128 位除法 Kani 仍未证明（同 RT2-NS-INTEGRATION-01），全域由 Verus 伴随模型 + 差分覆盖；不证明物理 TSC 校准精度 |
| MAIN-GREEN-02 | M1.1 补充判据：观测到新周期时，剩余额度 ∈ [1, quota] 且已扣额度 ≤ 新周期起点以来流逝的 tick；在补充的同一 tick 观测（流逝 0）⇔ 恰为满额。观测滞后（TCG vCPU 停顿）不改变结论，补充不足在零滞后下必被拒 | kernel_core::drill::refill_consistent；kernel::rtclass_demo::rt_body | Verus伴随(三条后置；负例去掉上界必败)/Proptest(正确补充×任意滞后必收、短补充零滞后必拒)/Miri/fuzz/Kani 全域 refill_judgement_full_domain/Loom N/A：纯函数 | verified(model+Kani) / tested | 同上 | Kani 全域 SUCCESSFUL；QEMU 定点 accept-20261028-202147/202500/202901/203221/203653/205827 M1.1 六次 PASS，串口 refill remaining=3 elapsed_ticks=0；修复前同提交基线 201646 M1.1 FAIL（rtclass_failed=1） |
| MAIN-GREEN-03 | M1.4 抢占演练有界且判别力不变：走满 8 步后继续到 tick 切换 ≥12 或截止（2000 tick）；未走满步数必继续；停止 ⇒ 已走满步数；抢占失效时按截止结束、切换数为 0 判 FAIL 而非挂起 | kernel_core::drill::preempt_step_continues；kernel::sched::demo::busy_task | Verus伴随/Proptest 参考差分/Miri 固定序列(24 步 12 切换)/fuzz/Kani 全域 preempt_loop_terminates_full_domain/Loom N/A：TICK_SWITCHES 为单调计数器，任务只读比较，替代证据为 QEMU 定点 | verified(model+Kani) / tested | 同上 | Kani 全域 SUCCESSFUL；定点 202901/203221/203653/205827 M1.4 四次 PASS（tick 切换=12，交错=14）；修复前 202500 tick=8 FAIL |
| MAIN-GREEN-04 | 高精度模式下非计时处理器由空闲切入任务前，空闲期间流逝的 tick 结算为空闲、随下一次事件交付：切入任务（及其 CPU 组）只被记切入后的 tick（charge·周期 < (t−s)+周期）；结算 + 事件记账 = 交付 + 待交付 = 自起点折算的总 tick（不铸造、不丢失）；时间倒退 / 溢出被拒且不改动；补链 PeriodicCredit::advance 结果不截断 | kernel_core::timer_units::CreditLedger；kernel::sched::scheduler（prepare_switch→settle_idle_credits、highres_event 交付 delivered） | Verus伴随(advance 守恒与 q≤u64::MAX、settle_idle/event 失败不改动、switch_in_then_event 记账上界)/Proptest(任意操作序列守恒、切入后记账有界、倒退被拒 3×512)/Miri固定序列(含修复前行为对照：空闲 15 tick 后切入被记 16)/fuzz 100万(任意序列守恒+切入后有界+倒退不改动)/Kani(结算守恒与记账上界 8 位有界 + cadical；失败不改动全域)/Loom N/A：每核状态只在调度器全局锁内读写，替代证据为 QEMU 4 处理器 SMP-2 跨核上限 | verified(model) / tested / bounded Kani | VERUS=… bash verification/toolbox/run-idle-credit-suite.sh | Verus 0.2026.10.18 + Z3：9 verified/0 errors，负例 idle_credit_bad.rs（切入前不结算）requires not satisfied；kernel-core timer_units 4 passed；Proptest 3 passed；Miri 1 passed；fuzz 100万 0崩溃 cov41；Kani 0.68 idle_settle_conserves_and_bounds_charge_bounded（21.5 s）、failures_leave_ledger_unchanged（1.4 s）SUCCESSFUL。不证明宿主 vCPU 停顿下的计时；全域 128 位除法 Kani 未证明，由 Verus 伴随模型覆盖 |
| MAIN-GREEN-05 | SMP-2 吃满任务的覆盖延长有界且判别力不变：窗口未到必继续；窗口后仅当到过的处理器数 < 所需且未到截止（窗口末 + 1200 tick）才继续；到截止或覆盖够数即停；所需为 0 时与「窗口一到即停」等价。铺满/窃取所需 = N（跨核上限用例所需 = 0，窗口一到即停：其 S-2 下「有扣费却未进入循环」的异常须保持可见）；放置或均衡失效时按截止结束、cores_covered=false 判 FAIL 而非挂起。宿主 vCPU 停顿使某核整个窗口未轮到时不再误判 | kernel_core::drill::hog_continues；kernel::balance_demo::hog / arm_hogs_until | Verus伴随(五条后置 + 循环模型 decreases 证终止且停止时刻 ≤ max(起点, 窗口末, 截止)；负例去掉截止 decreases not satisfied)/Proptest(任意各核到达时刻下逐 tick 与参考一致、停止时刻 = max(窗口末, min(截止, 首次覆盖够数)) 512 例)/Miri 固定序列(第 8 核窗口后 100 tick 才到 ⇒ 160 停；永不到 ⇒ 1260 停)/fuzz 100万/Kani 全域 hog_loop_bounded_full_domain（含 popcount）/Loom N/A：HOG_CPUS 只做 fetch_or 并集、HOG_WANT/HOG_CUTOFF 在任务创建前写定，判据为纯函数，替代证据为 QEMU 4/8 处理器全量 | verified(model+Kani) / tested | VERUS=… bash verification/toolbox/run-drill-time-suite.sh | Verus 0.2026.10.18 + Z3：12 verified/0 errors，负例 drill_hog_bad.rs decreases not satisfied；kernel-core drill 3 passed；Proptest 5 passed；Miri 1 passed；fuzz 100万 0崩溃 cov104；Kani 0.68 hog_loop_bounded_full_domain 全域 SUCCESSFUL（0.1 s）。QEMU：全量 accept-20261029-001545 中 S-2（8 核单线程 icount）spread cores_covered 由 false 转 true（第 8 核窗口后才轮到，min_task_cpu=0 仍记计时）；4/8 核 spread 覆盖 PASS。不证明宿主 vCPU 停顿下的计时 |
| MAIN-GREEN-06 | SMP-2 跨核上限「组成员分散到多个核」按调度器分派判：dispatch_mask 的第 i 位置位当且仅当 i < 处理器数、i < 32 且该核在本场景内运行任务的 tick > 0；被分派核数 ≤ min(处理器数, 32)，前 32 核总运行量为正当且仅当位图非空。任务体自报的核（loop_cores）只作参考：单线程 TCG 下持调度锁的 vCPU 被宿主轮转换下时，已上核的成员整段时间片都在等锁、未执行到任务体，但已在该核上运行并计费 | kernel_core::drill::dispatch_mask；kernel::balance_demo::limit | Verus伴随(逐位后置，循环不变式 + bit_vector；负例把 busy=0 也算作分派 postcondition not satisfied)/Proptest(任意长度 0..40、含 0 的各核运行量与逐核参考一致、计数与非空性 512 例)/Miri 固定序列(S-2 实测 8 核各核运行量 ⇒ 8；[0,0,5,0] ⇒ 0b100)/fuzz 100万(长度 0..40 逐位差分)/Kani dispatch_mask_exact_up_to_eight（任意 8 元数组、任意长度 ≤ 8，逐位精确、高位为 0、计数 ≤ 长度）/Loom N/A：纯函数，各核运行量在 sched::run() 返回后读取（场景内的工作任务已全部退出），无并发访问；替代证据为 QEMU S-2 | verified(model+Kani) / tested | VERUS=… bash verification/toolbox/run-drill-time-suite.sh | Verus 0.2026.10.18 + Z3：16 verified/0 errors，负例 drill_dispatch_bad.rs postcondition not satisfied；kernel-core drill 4 passed；Proptest 6 passed；Miri 1 passed；fuzz 100万 0崩溃 cov157；Kani 0.68 dispatch_mask_exact_up_to_eight SUCCESSFUL（2.2 s）。QEMU S-2（8 核单线程 icount）：诊断运行 s2-limit-diag-20261029-013938 各核运行 tick 14/19/23/19/17/15/14/8 全为正、合计 129 = 组生命周期计费 129，而任务体自报仅 3 核；改判后 s2-limit-dispatch-20261029-020207 cores_used=8、loop_cores=4、busy_sum=194 = 生命周期计费 194。不证明窗口用量上界（同次 used=54 > 界 52，另案） |
| MAIN-GREEN-07 | 验收演练的两处判据竞态。DEADLINE-IPI：目标核被推迟后的本地 tick 叫醒时可由空闲路径消费到期事件，这一轮未走到被测路径，最多换 8 轮；要求至少一轮「停表 + BSP 通知 + 消费前已收到核间中断 + owner 消费」全部成立，判据不放宽，owner 消费本身不成立仍立即判失败。COUNTER64：读取次数上限只是兜底（5000 万→20 亿），tick 确实不前进时仍判失败 | `kernel/src/scale_demo.rs::deadline_owner_contract`；`kernel/src/counter_demo.rs::MAX_READS` | Verus/Proptest/Miri/cargo-fuzz/Kani/Loom 均 N/A：只改内核内演练的重试与上限，依赖真实 tick、核间中断与串口输出，没有可抽出的纯函数；替代证据为 8 核 fault-scale 客户机 | 客户机 10/10 通过（其中 2 次走重试，`late_ipis=2`，确认中断晚于消费到达）；修改前 6 次里 COUNTER64 失败 2 次（tick 6/9，已到 5000 万上限），修改后 10 次 0 失败 | `scripts/s2.sh`（仅 VM）；全量 accept | 根因证据来自日志 `late_ipis`；未在目标核上记录每次唤醒来源，叫醒者是推迟的本地 tick 属由代码路径推断 |
| MAIN-GREEN-07 | 高精度模式下处理器事件被推迟（中断晚到、vCPU 被宿主换下）时一次补交 ticks 个 tick：CpuLimit::charge_batch 与逐个扣费逐位等价（余额、用量、可选中性），返回的迟到数 = 第一个之后扣费前余额已不为正的个数 = ticks − min(⌈tokens/1000⌉ 或 1, ticks)，≤ ticks−1；不限速的组与准时事件（每次 1 个 tick）迟到恒为 0；余额饱和于 i32::MIN、计数饱和于 u64::MAX、O(1)。SMP-2/S-2 跨核上限：窗口与生命周期用量扣除迟到后 ≤ 原界为功能判据，未扣除的原界改记计时（迟到计数只是下界：推迟期间全局时钟的补充已先入账，余额被高估） | kernel_core::sched::limit::CpuLimit::charge_batch/late_ticks；kernel::sched::scheduler::highres_event/budget_window_*；kernel::balance_demo::limit；scripts/accept.sh SMP-2 行 | Verus伴随(迟到按逐个扣费递归定义，闭式由归纳 + nonlinear_arith 证；负例把第一个 tick 也按余额判 postcondition not satisfied)/Proptest(任意上限含不限速、桶 1..64、前序操作 0..64 步、补交 0..200 与逐个扣费差分 512 例；准时事件迟到恒 0 512 例)/Miri 固定序列(250‰ 桶 4 补交 6 ⇒ 迟到 2；再补交 3 ⇒ 2；不限速 1000 ⇒ 0；u64::MAX 饱和)/fuzz 100万(前序 32 步、补交 ≤255 差分 + 任意 64 位补交不 panic)/Kani batch_charge_total_full_domain（任意余额/用量/计数/tick 数不溢出、界与饱和）+ batch_charge_equals_single_charges（ticks ≤ 8 与逐个扣费逐位相等）/Loom N/A：调度器锁内纯值计算，替代证据 QEMU S-2 | verified(model+Kani) / tested | VERUS=… bash verification/toolbox/run-limit-batch-suite.sh | Verus 0.2026.10.18 + Z3：12 verified/0 errors，负例 limit_batch_bad.rs postcondition not satisfied；kernel-core sched::limit 9 passed；Proptest 2 passed；Miri 1 passed；fuzz 100万 0崩溃 cov115；Kani batch_charge_total_full_domain SUCCESSFUL（1.0 s）、batch_charge_equals_single_charges SUCCESSFUL（2.5 s）。QEMU S-2（8 核单线程 icount，s2-late-20261029-022131）：窗口 used=47 bound=52 late=4，生命周期 used=131 bound=140 late=16，SMP-2 汇总 checks=38 failed=0 |
| MAIN-GREEN-08 | 分时策略最低份额保护：补给最低份额的档（欠账满一个 tick 的低档就是当前实体所在档）在本片第一个 tick 记账之前（used = 0）不被抢占；其余输入下 preempt_rule 与修正前规则逐位一致；记过 tick 后更高档在等必然抢占（保护至多一个 tick）。修正前补给派发后、第一个 tick 前的任何重新判定（重新调度请求等）都会因「更高档在等」立即换下它，欠账只在 tick 记到它身上时减少、从未偿还，S-2 QoS 用例后台档 150 tick 无进展（s2-late-20261029-022131/023257，忙等期补给切换约 120 次、每次立即被换下） | kernel_core::sched::timeshare::preempt_rule/Owed；TimeSharePolicy::should_preempt | Verus伴随(保护、与原规则一致、used≥1 时 Higher、无他者不按时间片换下；负例保护两个 tick postcondition not satisfied)/Proptest(规则差分 512 例；用户发起+后台两个吃满任务、0..4000 个 tick/重新判定任意交错：后台 tick 数 ×51+51 ≥ 总 tick、后台从不连续运行 2 tick，512 例)/Miri 固定序列(每个 tick 后插一次重新判定，600 tick)/fuzz 100万(规则差分 + 任意事件位序列份额与连续运行界)/Kani preempt_rule_guard_full_domain（全域 u32 used/quantum）/Loom N/A：纯函数、每核队列锁内的值，替代证据 QEMU S-2 | verified(model+Kani) / tested | VERUS=… bash verification/toolbox/run-share-guard-suite.sh | Verus 0.2026.10.18 + Z3：2 verified/0 errors，负例 share_guard_bad.rs postcondition not satisfied；kernel-core sched::tests 23 passed（新增 rescued_dispatch_is_not_preempted_before_its_tick 在修正前代码上失败：Some(Higher) ≠ None）；Proptest 2 passed；Miri 1 passed；fuzz 100万 0崩溃 cov88；Kani SUCCESSFUL（0.09 s）。QEMU S-2（8 核单线程 icount，s2-share-20261029-115304）：schedtest busy_ticks=150 background_progressed=true、ok checks=70，忙等期补给切换 2 次 |
| KOBJ-TYPE-01 | 对象类型登记表良构（表位置=种类、名字/句柄类型互异、无句柄⇒空上限不可转移无closing、可转移⇔上限含TRANSFER⇔v1可转移类型、强边指向更靠后种类⇒类型层面无环、持有⇒有释放动作、可转移⇒叶子）；内核 const 断言良构且 CLOSE_HOOKS 与 closing 声明一致 | kernel_core::kobj_type::{REGISTRY,registry_well_formed,edge_ordered}; kernel::kobj::{KObject::kind,close_hook,CLOSE_HOOKS,release_owner_in} | Verus伴随(有序路径无环引理)/Proptest差分(变异表×512，良构⇒DFS无环)/Miri/Kani(路径≤4)/fuzz N/A→由check_grant目标覆盖同表/Loom N/A | verified(model) / tested / bounded Kani / const-asserted | VERUS=… bash verification/toolbox/run-kobj-type-suite.sh | Verus 0.2026.10.18 + Z3：10 verified/0 errors；Proptest 3×512；Miri 1（9×12 变异）；Kani 0.68 ordered_edges_admit_no_cycle SUCCESSFUL（路径长≤4）；Loom N/A：常量表+纯函数，替代证据为编译期断言；伴随模型不直接验证Rust源，一致性靠差分；定点 accept-20261028-151918 m11/m34/m41/m42/m43/m44/drv1c/drv2c1/sched2/fix PASS |
| KOBJ-TYPE-02 | 句柄创建检查 check_grant：允许⇔类型一致∧权限⊆上限∧(含TRANSFER⇒可转移)，检查顺序类型→可转移→上限；通过后任意降权仍通过；kind_for_handle 与登记表一致；内核全部句柄创建路径经 admit_handle | kernel_core::kobj_type::{check_grant,kind_for_handle}; kernel::proc::{admit_handle,grant_in,grant_new_in,put_task_handle}, kernel::proc::spawn | Verus伴随(位向量；负例漏可转移检查postcondition失败)/Proptest差分/Miri/fuzz差分100万/Kani全域(12种×13类型×任意u32)/Loom N/A | verified(model+Kani全域) / tested | 同上 | Kani grant_check_matches_spec_for_all_inputs SUCCESSFUL；fuzz 100万0崩溃 cov57；Loom N/A：纯函数，只在对象表锁内调用 |
| RIGHTS-ALG-01 | 既有 Rights 位运算（补链：原无验证链）：from_bits_truncate/union/intersect/difference/contains/is_empty 等于 u32 位运算并截断到 ALL；交集被两边包含；降权保持在上限内 | kernel_core::object::Rights | Verus伴随(位向量引理 intersect⊆、restrict 传递)/Proptest差分全域u32/Miri/fuzz差分/Kani(经 check_grant 全域 harness 覆盖 contains)/Loom N/A | verified(model) / tested | 同上 | Loom N/A：Copy 值类型纯函数，无共享可变状态 |
| DL-SYNC-01 | 增量期限同步：同所有者同时刻同代次或两边都不存在 ⇒ Unchanged 且存储逐字不变；否则恰一次 set/remove，成功后槽位按目标发布于唯一所有者堆；代次不同/越界一律拒绝且不改状态 | deadline_forest::DeadlineForest::sync; SyncOutcome; Scheduler::refresh_ns_events | Verus 决策模型（5 verified）+ 负例（只比时刻）必败 / Proptest 参考差分 3×512 / Miri 固定序列 / fuzz 100 万 / Kani 两核两槽、时刻与代次 8 位有界（10 harness：前置 5 例 × 2 性质，每例枚举目标槽 0..=2 与目标核 不要/0/1/2，位置取具体值）/ Loom 全局锁下两核 | verified / tested / bounded Kani | VERUS=… bash verification/toolbox/run-deadline-sync-suite.sh（仅VM） | 调用方串行化（全局调度锁）；本片仍逐槽检查（全表扫描未去除），只去掉无变化的堆写入 |
| DL-SYNC-02 | SyncStats 计数守恒：synced = unchanged + inserted + rescheduled + moved + removed | deadline_forest::SyncStats; kmain [JSR-NS-SYNC] | 单元测试 / Proptest / Loom / 内核启动自检（不守恒计入失败） | tested | 同上 + 定点验收串口 | 饱和后不再判定守恒（u64 计数实际不可达） |
| KRN2-FOREST-02 | 既有 set 拒绝错代次改期/迁移且不改状态；pop_due 只在到期时弹出 (at,slot) 最小项（补链） | deadline_forest::DeadlineForest::{set,pop_due} | Kani 两核两槽、8 位有界 / Proptest 混合 set/remove/pop 差分 / fuzz | bounded Kani / tested | 同上 | 补链只覆盖森林层；内核 wake/rt 两个森林的调用路径未单独建模 |
| TIMER-EVT-01 | 每核仲裁取各事件源最晚处理时刻的最小值：不晚于任何源、不晚于任何精确请求、且等于某一源 | timer_event::Arbiter; Scheduler::program_ns_local | Verus 序列模型 + 负例 / Proptest 暴力最小值 / Kani 三源全值域 | verified / tested / bounded Kani | VERUS=… bash verification/toolbox/run-timer-event-suite.sh（仅VM） | 现有调度器来源全部按 Precise 提交，行为与改动前一致；未证明硬件定时器物理精度 |
| TIMER-EVT-02 | TimerId=(slot,generation)：创建代数严格递增，关闭后旧身份对装填/取消/到期无效，代数用尽槽位永久退役 | timer_event::TimerTable | Verus 代数引理 / Proptest 参考模型差分 / Miri / fuzz / Kani | verified / tested / bounded Kani | 同上 | 调用方串行化（每表一把锁）；身份表尚未接入系统调用 |
| TIMER-EVT-03 | 一次性到期至多交付一次；取消与到期竞争恰有一方生效；关闭撤下请求并恰好归还一次预算 | timer_event::TimerTable::{cancel,expire,close}; OwnerBudget | Proptest / Miri / fuzz / Kani / Loom 锁下竞争 | tested / bounded Kani | 同上 | Loom 覆盖调用方 Mutex 适配，不含内核真实锁 |
| TIMER-EVT-04 | 周期边界是严格晚于 now 的第一个相位点，溢出拒绝；deadline::next_period 复用同一实现 | timer_event::next_boundary; deadline::next_period | Verus 整数模型 / Proptest 全值域与步进参考 / 有界 Kani（previous/差/周期均 8 位） / fuzz | verified / tested / bounded Kani | 同上 | 纯函数，Loom 不适用（由 TIMER-EVT-03 的周期竞争覆盖调用路径） |

## 合入批次 1：验收演练与脚本改动（六步链逐步登记）

源码身份：`125c5f0`（`scripts/s2.sh`、`scripts/accept.sh`、`kernel/src/kmain.rs` 的 `s2-only` 分支、`kernel/src/s2.rs` 发布工作线程时关中断）、`0bc6d34`（`kernel/src/sched/demo.rs` 发布对等任务时关中断、`user/schedtest` 恢复延迟转为计时类记录）、`8fcab89` 与 `66fa91b`（`kernel/src/irq_demo.rs` 演练等待 tick、`scripts/accept.sh`）、`c34f197`（`scripts/s2.sh` 恢复 7 项调度判据）。这些改动只在验收客户机或自检演练路径生效，不改系统调用、调度算法或内核数据结构。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| MB1-STEP-1 | Verus/Z3 | 同上 | N/A：只有等待时长、关中断发布窗口与 shell 判据，没有可写前后条件的纯算法；替代证据为全量 accept 的 M1.4、M1.2-IRQ、S-2、QoS 判据 | N/A | `bash scripts/accept.sh`（仅VM） | 未对演练路径做机器证明 |
| MB1-STEP-2 | Proptest | 同上 | N/A：无可在宿主构造的输入空间，发布窗口依赖真实中断；替代证据为 S-2 八个固定种子各 125000 次探测 | N/A | `bash scripts/s2.sh`（仅VM） | 固定种子，不是随机输入全集 |
| MB1-STEP-3 | Miri | 同上 | N/A：涉及内核 `no_std` 目标、关中断内联汇编、QEMU 设备与 shell，Miri 无法执行；未新增 unsafe 数据访问 | N/A | 不适用 | 关中断与恢复的配对由代码审阅确认 |
| MB1-STEP-4 | cargo-fuzz | 同上 | N/A：没有解析或编码入口可喂字节；替代证据为 S-2 系统调用健壮性探测 | N/A | `bash scripts/s2.sh`（仅VM） | 同 MB1-STEP-2 |
| MB1-STEP-5 | Kani | 同上 | N/A：等待 tick、IPI 与客户机串口输出不是可有界建模的纯函数；替代证据为 fault-scale 客户机 `failed=0` | N/A | `bash scripts/s2.sh`（仅VM） | QEMU 只判正确性，不证明硬件时序 |
| MB1-STEP-6 | Loom | 同上 | N/A：发布窗口用真实关中断而不是 std 同步原语，Loom 无法替换；替代证据为 8 核 fault-scale 客户机 `[JSR-TASK-INDEX]`、`[JSR-WAKE-MSG]`、`[JSR-WAKE-FULL]`、`[JSR-DEADLINE-OWNER]`、`[JSR-DEADLINE-IPI]`、`[JSR-RT-LOCAL]`、`[JSR-BUDGET-TICK]` 七项判据与 `checks=39 failed=0` | N/A | `bash scripts/s2.sh`（仅VM） | 单次 8 核运行，不是穷举交错 |

## 原生 ABI 世代（issue #8 第一片）

范围：`Major.Minor.Patch` 声明与盖章、同主版本兼容、跨主版本/次版本过新拒绝、装载前检查与查询通道。
发布快照/轮换与能力要求不在本切片内。六个步骤的命令均在仓库根目录执行，并经 VM 运行；`VERUS` 由环境变量给出。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| ABI-GEN-01 | 加载被接受当且仅当主版本相同且程序最低次版本不高于内核次版本；Patch 不参与门槛 | `kernel_core::abi_version::compatible`; `verification/toolbox/verus/abi_version.rs` | Verus/Z3 | proved（仅规格模型） | `VERUS=<verus> bash verification/toolbox/run-abi-suite.sh`（步骤 1） | 7 条 proof 通过；模型是自然数抽象，不证明 Rust 编译产物、ELF 解析或装载器调用顺序 |
| ABI-GEN-02 | 28 字节章编码/解析逐字节往返；被接受的任意 28 字节输入必须恰为规范编码；任意其它长度拒绝 | `kernel_core::abi_version::{encode_note,parse_note}`; `verification/toolbox/tests/abi_version.rs` | Proptest | tested | `cargo test --manifest-path verification/toolbox/Cargo.toml --test abi_version` | 512 例/性质、固定种子可复现；覆盖全部 u16 字段域与随机字节，不替代代码级证明 |
| ABI-GEN-03 | 章解析与打包/解包在 Miri 下无未定义行为，少一字节明确拒绝 | `verification/toolbox/tests/abi_version.rs::note_roundtrip_under_miri` | Miri | tested | `cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test abi_version note_roundtrip_under_miri` | 1 项确定性用例；Miri 不执行 Rust 内核目标与内联汇编，硬件路径由 QEMU 证据承担 |
| ABI-GEN-04 | 任意长度输入不让章解析 panic；成功解析的输入重新编码与原文逐字节一致 | `verification/toolbox/fuzz/fuzz_targets/abi_note.rs` | cargo-fuzz | tested | `(cd verification/toolbox/fuzz && cargo fuzz run abi_note -- -runs=10000)` | 10000 次、空语料起步、最长 4096 字节；覆盖引导 fuzz 不等于穷举 |
| ABI-GEN-05 | 兼容性判定与 `check_image` 分类对任意 u16 输入满足规格；章编解码往返；打包保留高位拒绝 | `kernel-core/src/abi_version.rs`（`abi-fv` 特性下的 3 个 harness） | Kani | proved（有界） | `cargo kani -p kernel-core --features abi-fv --harness abi_compatibility_is_exactly_same_major_and_minor_bound` | 3 个 harness 全部 SUCCESSFUL；默认 Kani 套件计数不变（harness 只在 `abi-fv` 下编译）；ELF 节头解析见 ABI-GEN-11；不覆盖真实页表 |
| ABI-GEN-06 | —（无并发状态可枚举） | `kernel_core::abi_version` 的纯函数 | Loom | N/A：纯函数，无锁/原子/线程交错；不能记为 PASS | 替代证据：`bash scripts/accept.sh` 的 `ABI` 检查（真实 QEMU 中缺章/损坏/跨主版本/次版本过新均在映射前拒绝，页帧回基线） | Loom 不适用；QEMU 演练证明装载器集成与拒绝顺序，不证明任意恶意 ELF 或硬件内存序 |
| ABI-GEN-07 | ELF 节头表项地址算术：整表在文件内 ⇒ 任一表内下标的表项在文件内；u64 机器整数下溢出必拒且不误拒；章字节区间在文件内；off-by-one 下标上界的负例必须验证失败 | `kernel_core::elf::{section_at,abi_note_bytes}`; `verification/toolbox/verus/elf_section_bounds.rs`（负例 `elf_section_bounds_bad.rs`） | Verus/Z3 | proved（仅地址算术模型） | `VERUS=<verus> bash verification/toolbox/run-abi-suite.sh`（步骤 1） | 正例 7 verified / 0 errors，负例 1 error（断言失败）；只证明地址算术，不证明字节解码与名字比较 |
| ABI-GEN-08 | 任意合法章经 ELF 往返一致；改写节头表/字符串表/章区域任意字节不 panic，被接受的要求必在文件中以规范编码出现，错误只为 BadSection/BadAbiNote；任意 shoff/shentsize/shnum/shstrndx 越界即 BadSection；章区间任意时越界即 BadAbiNote | `kernel_core::elf::parse`; `verification/toolbox/tests/elf_abi_section.rs`（夹具 `tests/fixture/elf_abi.rs`） | Proptest | tested | `cargo test --manifest-path verification/toolbox/Cargo.toml --test elf_abi_section` | 4 个性质 × 512 例 + 1 个确定性用例；只用 ELF64/x86_64 夹具 |
| ABI-GEN-09 | 缺节头表 / 改名 / 重复章 / SHT_NOBITS / 字符串表越界 / 名字偏移越界 / 名字无 NUL / SHN_XINDEX / 章少一字节逐项精确分类，Miri 下无未定义行为 | `verification/toolbox/tests/elf_abi_section.rs::section_rejections_under_miri` | Miri | tested | `cargo +nightly miri test --manifest-path verification/toolbox/Cargo.toml --test elf_abi_section section_rejections_under_miri` | 1 项确定性用例（9 种拒绝/接受情形） |
| ABI-GEN-10 | 任意字节映像或「合法夹具 + 任意 (偏移, 字节) 改写」下 `elf::parse` 不 panic；被接受的 ABI 要求必在映像中规范出现 | `verification/toolbox/fuzz/fuzz_targets/elf_abi_section.rs` | cargo-fuzz | tested | `(cd verification/toolbox/fuzz && cargo fuzz run elf_abi_section -- -runs=1000000 -max_len=16384)` | 100 万次、空语料起步、0 崩溃，cov 264 / ft 438；覆盖引导 fuzz 不等于穷举 |
| ABI-GEN-11 | 节名读取对任意 ≤8 字节字符串表与任意偏移不 panic，接受时名字在表内、无 NUL、紧跟 NUL；节头读取对任意偏移/表项大小/下标不 panic 不溢出，接受时表项整体在 ≤160 字节映像内 | `kernel-core/src/elf.rs`（`abi-fv` 特性下 `elf_section_name_is_bounded_and_terminated`、`elf_section_at_stays_inside_image`） | Kani | proved（有界） | `cargo kani -p kernel-core --features abi-fv --harness elf_section_name_is_bounded_and_terminated`（另一 harness 同） | 2 个 harness SUCCESSFUL（3.1 s / 121.8 s）；界限为字符串表 8 字节、映像 160 字节 |
| ABI-GEN-12 | —（无并发状态可枚举） | `kernel_core::elf` 的节头 / 章定位纯函数 | Loom | N/A：纯函数，无锁/原子/线程交错；不能记为 PASS | 替代证据：ABI-GEN-08/10 的畸形输入覆盖 + `scripts/accept.sh` 的 `ABI`、`m51pre` 检查（真实 QEMU 装载） | Loom 不适用 |

## JB-OS1 `.jaso` format 1 结构读取（六步链，2026-10-28）

源码身份：提交 2b217b3..a2564ab（rebase 到 ABI 世代合入后的 main，a2564ab 上两套件复跑 PASS）；`jaso/src/{lib,platform,manifest,code,build,migrate}.rs`。复现：VM `bash verification/toolbox/run-jb-os1-jaso-suite.sh`（证据 `evidence/jb-os1/jaso-suite/`，含 `source.sha256`）。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| JB-OS1-BOUNDS-VERUS-01 | 区间判定 `off+len ≤ total` 精确且不回绕；扩展内容起点按 8 对齐、在名字后 <8 字节且不越段；段页末端 `vaddr+roundup(mem,PAGE) ≤ image_size` 全程检查式；平台/镜像表定长 `8+rec×count` 不回绕；u32 回绕加法负例必败 | `jaso::range_within`；`extension_layout`；`ImageRef::check_segment`；`check_platforms`/`check_images` 的定长式；伴随 `verification/toolbox/verus/jaso_bounds{,_bad}.rs` | Verus 0.2026.10.18.7d82994 + Z3 | proved（伴随） | 套件第 1 步 | 正例 6 verified/0 errors、负例 1 error；伴随与生产逐式对应但是独立可执行 Verus 代码，不是对生产函数本身的证明 |
| JB-OS1-PARSE-PROPTEST-01 | 随机合格原生模块构建→读取往返（段/导出/重定位数、映像大小一致，还原再写逐字节相同）；任意改写并回填长度与摘要后只给 Ok 或静态错误码；版本区间与参考求值一致；依赖列表切分与生成结构一致 | `verification/toolbox/tests/jaso.rs` → `jaso::{Jaso::parse,build::Builder,VersionRange,Manifest::depends}` | Proptest 1.12.0（每性质 256 例，固定配置，收缩） | tested | 套件第 2 步 | 6 passed；另有 crate 内宿主测试 45 passed（每个错误码的构造用例、四类种子的 4 万次随机变异不 panic） |
| JB-OS1-PARSE-MIRI-01 | 解析、选择、扩展、托管、多镜像、迁移、版本区间路径无未定义行为与泄漏 | `jaso/src/tests.rs` 中 roundtrip / platform_rejections / extensions / managed_images / multiple_images_and_selection / migrate_format0 / version_ranges_and_dependencies | Miri 0.1.0 (19833af722 2026-10-20) | tested | 套件第 3 步 | 7 passed；首次运行发现测试自身的 `Box::leak` 泄漏，已改写测试；不覆盖签名（Ed25519）路径 |
| JB-OS1-PARSE-FUZZ-01 | 任意字节及「回填长度与摘要」的副本读取不 panic；接受的文件全部访问器不越界、错误码不是 load 类、按镜像 0 重写后仍合格；清单解析不 panic | `verification/toolbox/fuzz/fuzz_targets/jaso_parse.rs`；种子 `fuzz/seeds/jaso_parse/`（native / hybrid / managed 入库） | cargo-fuzz 0.13.2 / libFuzzer | tested | 套件第 4 步 | 200 万次（82 s）、seed=1、0 崩溃，cov 2055 / ft 6705；覆盖引导 fuzz 不是证明 |
| JB-OS1-LAYOUT-KANI-01 | 对任意输入：`range_within` 与 u128 数学定义一致；扩展段数值布局（≤24 字节）不 panic 且内容起点对齐在段内；平台记录数值字段满足托管一致性与指针宽度规则；导出名范围非空、≤128、在表内 | `jaso/src/kani_proofs.rs` → `range_within`、`extension_layout`、`platform::numeric_fields`、`export_name_range` | Kani 0.68.0 / CBMC 6.11.0 | bounded Kani | 套件第 5 步 | 4 harness SUCCESSFUL；名字字段的 UTF-8 / 字符集判定与 SHA-256 不在范围内（符号化展开代价过高，首次把 from_utf8 纳入的 harness 23 分钟未结束、占 4 GB，已改为数值部分），由 Proptest / fuzz 覆盖 |
| JB-OS1-LOOM-NA | — | `jaso` 核心层 | Loom | N/A | — | N/A：读取器是纯函数（只借用输入、无原子量 / 锁 / 共享可变状态），`Jaso` / `ImageRef` 为 `Copy` 视图；装载器里唯一的并发状态（槽位位图、未签名放行计数）本切片未改动。替代证据：QEMU 定点 J-3 两实例并存装入/卸载、J-6 隔离进程装载（accept-20261027-232528） |

## JB-OS1 `.jaso` 一致性判定与向量（SPEC §14，六步链，2026-10-28）

源码身份：提交 d027a19（rebase 后 a2564ab 上复跑 PASS）；`jaso/src/{conformance,vectors,vector_tests}.rs`、`tools/jasopack/src/main.rs`（`vectors` / `conform`）、`jaso/vectors/`（69 个向量 + 开发用公钥）。复现：VM `bash verification/toolbox/run-jb-os1-conformance-suite.sh`（证据 `evidence/jb-os1/conformance-suite/`，含 `source.sha256`、`vectors.sha256`）。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| JB-OS1-CONF-VERUS-01 | 判定按六步（结构、信任、平台、运行时、依赖、能力）依次进行：结果 ok 当且仅当每步通过，否则报告的恰是第一处失败步骤；能力步「每个请求都在授予表中」的全称判定精确；「报告最后一处失败」的负例必败 | `jaso::conformance::check` 的步骤顺序与 `requires().any(…)`；伴随 `verification/toolbox/verus/jaso_conformance{,_bad}.rs` | Verus 0.2026.10.18.7d82994 + Z3 | proved（伴随） | 套件第 1 步 | 正例 6 verified/0 errors，负例 2 verified/1 error；伴随是独立可执行 Verus 代码，不是对生产函数本身的证明；各步内部判定由 JB-OS1 结构读取一节与信任层测试覆盖 |
| JB-OS1-CONF-PROPTEST-01 | 对四个合法签名向量做 1–3 处任意改写并回填摘要：字节有变就绝不放行；任意字节：判定不 panic，结构读取失败时结果即读取错误码，否则只能是 ok 或 load 类码 | `verification/toolbox/tests/jaso.rs` → `jaso::conformance::check` | Proptest 1.12.0（每性质 256 例） | tested | 套件第 2 步 | 8 passed（含前一节 6 项）；crate 内宿主 49 passed：仓库向量与生成器逐字节一致、69 个向量判定与 `.expect` 一致、51 个错误码与 ok 全覆盖、非法/他人公钥一律 `trust.key` |
| JB-OS1-CONF-MIRI-01 | 69 个向量的读取与判定（含 Ed25519 验签与 SHA-256）、错误公钥配置路径无未定义行为与泄漏 | `vector_tests::{every_vector_yields_its_expected_line,a_bad_trust_key_never_admits}` | Miri 0.1.0 (19833af722 2026-10-20)，`-Zmiri-disable-isolation`（读向量文件） | tested | 套件第 3 步 | 2 passed（446 s）；生成器（签名路径）由宿主测试覆盖，未在 Miri 下跑 |
| JB-OS1-CONF-FUZZ-01 | 任意字节及「回填魔数/版本/长度/摘要」的副本：判定不 panic；结构读取失败时结果等于读取错误码；结构合格时只能被 load 类码拒绝；放行的文件必须由受信公钥签名 | `verification/toolbox/fuzz/fuzz_targets/jaso_conformance.rs`；种子 `fuzz/seeds/jaso_conformance/`（7 个向量入库） | cargo-fuzz 0.13.2 / libFuzzer | tested | 套件第 4 步 | 100 万次（94 s）、seed=1、0 崩溃，cov 2185 / ft 5702；覆盖引导 fuzz 不是证明 |
| JB-OS1-CONF-KANI-NA | — | `jaso::conformance::check` | Kani | N/A | — | N/A：判定是结构读取 + Ed25519 验签 + SHA-256 + 平台选择的组合，新增的只有步骤顺序与表查找；其中数值部分已有 Kani（JB-OS1-LAYOUT-KANI-01），而 Ed25519/SHA-256 的符号化展开超出 CBMC 可行范围（前一节 from_utf8 一项已 23 分钟未结束）。替代证据：步骤顺序 Verus 伴随（JB-OS1-CONF-VERUS-01）、Proptest、100 万次 fuzz、69 个固定向量 |
| JB-OS1-CONF-LOOM-NA | — | `jaso::conformance` / `jaso::vectors` / `jasopack vectors` | Loom | N/A | — | N/A：纯函数，上下文为编译期常量，无原子量 / 锁 / 共享可变状态；`jasopack vectors` 单线程顺序写文件。替代证据：同上 |

## JB-OS2 `.jaso` L1 全流程装载（六步链，2026-11-03）

源码身份：提交 ba02cb8..f5db1cc；`jaso/src/{binding,lifecycle,kernel_gate,conformance}.rs`、`user/rt/src/{loader,module}.rs`、`user/jasodemo`、`modules/l1demo`。复现：VM `bash verification/toolbox/run-jb-os2-loader-suite.sh`（证据 `evidence/jb-os2/loader-suite/`，含 `source.sha256`）。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| JB-OS2-VERUS-01 | stop 前提「没有运行中的依赖者」与装入前提「依赖都在运行中」都保持不变量「运行中模块的依赖都在运行中」；绑定判定「两个方向的包含都成立」⇔ 两集合相等；去掉 stop 前提的负例必败 | `jaso::lifecycle::Registry::{begin_stop,satisfies}`、`jaso::binding::check` 的集合判定；伴随 `verification/toolbox/verus/jaso_l1{,_bad}.rs` | Verus 0.2026.10.18.7d82994 + Z3 | proved（伴随） | 套件第 1 步 | 正例 8 verified/0 errors，负例 1 verified/1 error；伴随是独立可执行 Verus 代码，不是对生产函数本身的证明；语法解析不在范围内 |
| JB-OS2-PROPTEST-01 | 任意 load/stop/unload 序列下模块表与参考模型一致、不变量始终成立、stop 被拒当且仅当有运行中的依赖者、卸载请求不改变状态；合法绑定（打乱顺序、注释）被接受，删 fn / 多 fn / 超出清单的 cap / 破坏语法都被拒；任意文本不 panic | `verification/toolbox/tests/jaso_l1.rs` → `jaso::{lifecycle::Registry,binding::check}` | Proptest 1.12.0（每性质 512 例，固定配置，收缩） | tested | 套件第 2 步 | 3 passed；另有 crate 内宿主测试 56 passed（语法负例 30 条、限额、内核态准入门） |
| JB-OS2-MIRI-01 | 绑定判定与模块表路径无未定义行为与泄漏 | `jaso/src/l1_tests.rs` 中 binding_accepts_the_grammar / binding_rejects_bad_syntax / binding_must_agree_with_the_manifest / dependencies_are_satisfied_only_by_running_modules_in_range / unload_is_never_reported_as_done | Miri 0.1.0 (19833af722 2026-10-20) | tested | 套件第 3 步 | 5 passed（18 s）；不覆盖 binding_limits（1024 行两两比较，Miri 下 19 分钟未结束，已中止）与内核态准入门（Ed25519 签名与验签路径），二者由宿主测试覆盖 |
| JB-OS2-FUZZ-01 | 任意字节判定不 panic；放行时导出与 fn 行一一对应、cap 都在清单里、绑定里没有裸指针 | `verification/toolbox/fuzz/fuzz_targets/jaso_binding.rs`；种子 `fuzz/seeds/jaso_binding/`（2 个入库） | cargo-fuzz 0.13.2 / libFuzzer | tested | 套件第 4 步 | 200 万次（137 s）、seed=1、0 崩溃，cov 621 / ft 2471；覆盖引导 fuzz 不是证明 |
| JB-OS2-KANI-01 | 任意 4 字节名字：游标不越界、接受时首字节合法；超过嵌套深度上限的类型直接拒绝且不读输入（递归因此有界） | `jaso/src/binding.rs` `kani_proofs` → `Cursor::{dotted,ty}` | Kani 0.68.0 / CBMC 6.11.0 | bounded Kani | 套件第 5 步 | 2 harness SUCCESSFUL；**未覆盖**：完整签名与类型的递归主体——4 字节签名 harness 12 分钟、2 字节类型 harness 7 分钟均未结束（`starts_with` 的 memcmp 符号化展开不收敛），已中止并收窄，这部分只由 Proptest 与 fuzz 覆盖 |
| JB-OS2-LOOM-NA | — | `jaso::lifecycle`、`jasper_rt::loader` | Loom | N/A | — | N/A：模块表没有原子量或锁；`Function` 借用 `Loader`、`stop` 要 `&mut Loader`，活动中的调用与 stop 由借用检查在编译期互斥；`Module` 的活动计数本轮未改动。替代证据：QEMU J-3、JB-OS2、J-6（isohost 静默判定）；未测多线程共享 `Loader`（需要调用者自行加锁，本切片没有这种调用者） |
| JB-OS2-QEMU-01 | 运行时装入签名的 Native 与 Hybrid 并调用导出；依赖、服务发现；篡改（摘要 / 代码 / 绑定）、错误平台、缺能力、缺依赖、版本不符、绑定 4 类、启动失败被拒且无残留；stop 被依赖者阻止、停止后不再服务、重复 stop 被拒且钩子只调用一次；卸载只答复推迟 / 拒绝且模块仍映射；内核态准入门 | `user/jasodemo/src/main.rs` `l1` / `kernel_gate`；`scripts/accept.sh` `check_jb_os2` | QEMU 用户态 | tested | 定点与全量 accept | 内核自身没有运行期装载路径（系统调用表无此项、内核不依赖 `jaso`，由 check_jb_os2 检查）；准入门在用户态验收程序中执行，不是内核路径上的负向用例。隔离运行不经 `Loader`：容器内模块会 `start`，但没有 `stop`，随容器进程结束 |

更正：JB-OS1 记录与 README 写的「69 个向量」有误，当时实际是 68 个（`git ls-files` 与生成器一致）；本轮新增 8 个后为 76 个。一致性判定新增第 6a 步，`run-jb-os1-conformance-suite.sh` 在新代码上复跑；`run-jb-os1-jaso-suite.sh` 未复跑，读取器代码（`jaso/src/lib.rs` 除模块声明外）未改。

## `core.depends` 线性查重（六步链，2026-11-04）

`Manifest::parse` 在验签之前运行，输入未经验证；原实现对每一项重扫此前全部行，一行百万项要跑数小时。改为只在前 32 项内查重（SPEC §12.1 写明），超出上限的项仍校验取值。接受与拒绝的集合不变；只有「超过上限、且重名只出现在第 33 项及之后」的清单错误码由 `manifest.duplicate` 变为 `manifest.limit`。`jaso/src/manifest.rs` sha256 前缀 69a6b67caac7，基于 1cb6c48 的工作树。

| ID | 性质 | 源码 | 工具 | 级别 | 命令 | 范围、假设与结果 |
|---|---|---|---|---|---|---|
| JASO-DEPENDS-VERUS-01 | 接受的列表 ≤32 项、取值全合法、无重名；报上限时前 32 项无重名且取值全合法；≤32 项且合法不重名必接受；比较次数 ≤1024，与项数无关；去掉窗口的负例必败 | 模型 `verification/toolbox/verus/jaso_depends.rs`（对应 `Manifest::parse` 的 `core.depends` 分支），负例 `jaso_depends_bad.rs` | Verus + Z3 | model | `bash verification/toolbox/run-jaso-depends-suite.sh` 第 1 步 | 4 verified / 0 errors；负例 1 error（循环不变式不成立）。**假设**：模型用整数表示名字，字符串切分与逐行扫描不在模型内 |
| JASO-DEPENDS-PROPTEST-01 | 多行、含重名与坏项的随机依赖列表，判定与按规则写的参考实现一致 | `verification/toolbox/tests/jaso.rs` `depends_scan_matches_reference` | Proptest | tested | 套件第 2 步 | 通过；套件 9 passed，jaso 宿主 57 passed（含百万项回归 `depends_scan_is_linear_in_entries`，未设时间断言，退化时表现为测试长时间不结束） |
| JASO-DEPENDS-MIRI-01 | 清单规则与依赖路径无未定义行为 | `tests::{manifest_rules,version_ranges_and_dependencies}` | Miri | tested | 套件第 3 步 | 2 passed；百万项回归不在 Miri 内 |
| JASO-DEPENDS-FUZZ-01 | 任意字节不 panic；接受的清单依赖 ≤32 项且无重名（本轮新增断言） | `verification/toolbox/fuzz/fuzz_targets/jaso_parse.rs` | cargo-fuzz / libFuzzer | tested | 套件第 4 步 | 100 万次、seed=1、0 崩溃，cov 1981 |
| JASO-DEPENDS-KANI-NA | — | `Manifest::parse` | Kani | N/A | — | N/A：试过两个单字节符号名字的完整解析 harness（unwind 70），约 16 分钟仍停在符号执行阶段（UTF-8 校验循环第 59 轮，CBMC 2.4 GB），已中止，未得到结论；窗口判断本身只是一次整数比较。替代证据：上面的 Verus 模型与 Proptest 参考对照。**未覆盖**：实际字符串解析的有界证明 |
| JASO-DEPENDS-LOOM-NA | — | `Manifest::parse` | Loom | N/A | — | N/A：纯函数，只借用输入，无原子量、锁或共享可变状态。替代证据：同上 |

## issue #5 第一片：Ring 后端登记表（六步链）

| ID | 性质 | 源码 | 工具 | 级别 | 命令 | 范围、假设与结果 |
|---|---|---|---|---|---|---|
| RING-BACKEND-01 | Ring 后端路由查找：返回第一条同编号路由的后端，无匹配⇔None；良构表（编号非零互异、每后端至少一条）中结果唯一；内核 ROUTES 编译期断言良构 | kernel_core::ring_backend::{route,routes_well_formed}; kernel::ring::{ROUTES,check_sqe,prepare_user_work,submit_in} | Verus伴随模型/Proptest差分/Miri/fuzz差分/Kani(8条符号路由)/Loom N/A | verified(model) / tested / bounded Kani | VERUS=… bash verification/toolbox/run-ring-backend-suite.sh | Verus 0.2026.10.18 + Z3 4.16.0：7 verified/0 errors，负例(漏查首条)postcondition失败；Proptest 2×512；Miri 1；fuzz 100万0崩溃 cov184；Kani 0.68 SUCCESSFUL(表长8)；Loom N/A：常量表+纯函数无共享可变状态，替代证据为 const 断言与对象表锁内串行调用；伴随模型不直接验证Rust源，一致性靠差分 |
| RING-BACKEND-02 | 后端静态契约一致：持用户缓冲⇒可中止且非瞬时；瞬时⇒不可中止；Kind::index 与 ALL 顺序一致 | kernel_core::ring_backend::Kind::{contract,index} | 单元/Miri/Kani全域(7种)/Loom N/A | verified(Kani全域) / tested | 同上 | Kani对全部7种后端穷举；Verus N/A：有限枚举由Kani全域覆盖、无算术；契约是否符合各后端真实行为由定点 M4.3/M4.4/M5.1/J-1/DRV2C1 回归覆盖(accept-20261028-141327) |
| QUOTA-ADMIT-02 | quota::reserve_u32/usize 不回绕不越限且等于数学和（既有AI代码补链：原只有Kani） | kernel_core::quota::{reserve_u32,reserve_usize} | Verus伴随(减法守卫)/Proptest差分(全域u32/usize)/Miri/fuzz/Kani既有/Loom N/A | verified(model) / tested / Kani | 同上 | Verus伴随式与生产checked_add+filter等价性由Proptest/fuzz差分覆盖；Kani quota_admission_never_wraps_or_exceeds_limit SUCCESSFUL；Loom N/A：纯函数，调用方在对象表锁内串行 |
| BOOT-STAGE-01 | 启动阶段图良构（表位置=阶段、名字非空互异、依赖只指向更靠前阶段⇒无环无自环、无越界位）；closure 等于传递依赖且不含自身 | kernel_core::boot_stage::{GRAPH,graph_well_formed,closure}（const 断言） | Verus伴随(依赖后向引理)/Proptest差分(变异图×512 对照 DFS 闭包)/Miri/Kani(任意阶段闭包)/fuzz 经跟踪器目标覆盖同表/Loom N/A | verified(model) / tested / Kani / const-asserted | VERUS=… bash verification/toolbox/run-boot-stage-suite.sh | Verus 0.2026.10.18 + Z3：33 verified/0 errors（含跟踪器与容量引理）；Kani 0.68 graph_and_closure_are_consistent SUCCESSFUL（unwind 12）；伴随模型不直接验证 Rust 源，一致性靠差分 |
| BOOT-STAGE-02 | 阶段跟踪器：begin 成功⇒未失败、无运行中阶段、此前未开始、直接依赖全部完成；失败之后 begin 一律被拒且不改状态；done⊆started⊆全集；每个已完成阶段的直接依赖都已完成；被阻断集合=传递依赖失败阶段的阶段；kmain 十六个全局初始化阶段全部经跟踪器执行，失败即停止启动 | kernel_core::boot_stage::Tracker; kernel::kmain::{stage,run_stage,start}; kernel::mm::demo::{run,run_map,run_heap} | Verus伴随(begin/complete/fail 保持不变量；负例漏依赖检查 postcondition 失败)/Proptest差分(任意≤64步×512)/Miri 固定序列/fuzz差分100万/Kani(任意≤12步)/Loom N/A | verified(model) / tested / Kani：发版时验证 | VERUS=… bash verification/toolbox/run-boot-stage-suite.sh；spot-accept.sh "m11 boot_stage" | Verus 43/0 + 负例失败，kernel-core 7，Proptest 5，Miri 1，fuzz 100万 0崩溃 cov197/ft796；BOOT-STAGE 定点通过 done_mask=0xffff；Loom N/A：跟踪器是 BSP 局部值，不跨核共享；内核内阶段失败注入与回滚未覆盖（第三片） |
| BOOT-PLAN-01 | `plan_check` 接受⇔阶段不重复且直接依赖已出现、用例声明的阶段已完成、用例名非空且计划内唯一、恰好一个收尾步且在最后；良构计划按序执行时不会被跟踪器以重复或缺失依赖拒绝 | kernel_core::boot_stage::{CaseSpec,PlanItem,PlanError,PlanSummary,plan_check,plan_well_formed}; kernel::kmain::{PLAN_SUMMARY,start}; kernel::acceptance::{PLAN,SUMMARIES}; kernel::production::PLAN | Verus伴随阶段/用例步前条件 + Proptest差分(任意≤40步×512，分片不改变结论) + Miri固定序列 + fuzz差分100万 + 编译期const断言；Kani：发版时验证；Loom N/A：纯局部状态机与常量计划 | verified(model) / tested / const-asserted | VERUS=… bash verification/toolbox/run-boot-stage-suite.sh | 全量计划编译期 stages=0xffff cases=53，生产 stages=0xffff cases=1，各专项计划同样经 const 检查；Verus 43/0、Proptest 5、Miri 1、fuzz 100万；模型检查计划结构，不证明各执行体的副作用，也尚未注入失败阶段验证回滚 |
| BOOT-PRODUCTION-01 | 生产计划按声明顺序跑完 16 个阶段，运行首个用户程序后进入服务等待，成功不退出模拟器；生产阶段失败关闭中断停机；损坏容量记录在 capacity 阶段拒绝且后续阶段不开始 | kernel::production::{PLAN,first_program,wait_for_services,stop}; kernel::kmain::{run_stage,start,stop_boot}; kernel::bootcap::reject | 真实 QEMU：scripts/production-check.sh（单核 + 4 核，另有损坏记录负例） | tested | VM `CPUS='1 4' LIMIT=30 bash scripts/production-check.sh` | 两次均完成 16 阶段，`first-program` 退出码 0、页帧全部归还、进入 alive 等待后到时 QEMU 未退出；损坏记录输出 bad_version 与失败标记后停机；没有常驻服务，等待内容的 future 服务路径未覆盖 |
| BOOT-PLAN-02 | 原专项 feature 不再增加 kmain 分支，而由构建期选择的静态计划执行；计划公共段在地址空间和 SMP 就绪后才运行专项用例；故障注入在 SMP 后执行 | kernel::acceptance::{PREFIX,CLASSES,SMP_UP,HIGHRES,FULL,dedicated}; kernel::kmain::start; kernel/Cargo.toml features; user/ring/src/main.rs::public_process_spawn_event | 构建矩阵 + 真实 QEMU：scripts/plan-guests-check.sh（QEMU串行）；各专项原有判据 | tested | VM `MATRIX=1 LIMIT=300 SMP=4 bash scripts/plan-guests-check.sh` | 构建矩阵及三类非法组合全部通过；12/12 专项计划到各自收尾并 exit33：rt1/rt2/rt3、budget-window（8核/icount5）、fast-tick、post-split（4核/icount5）、p999（8核/icount0，样本完整）、evt1、evt2、broadcast（8核/icount0，七个订阅者各100万）、s3-nohz、shm1；s2-fuzz与 soak 仅完成构建验证，长跑由专用入口负责 |
| CAP-RECORD-01 | 既有启动容量记录 encode/parse（补链：原无验证链；capacity 阶段读取的不可信输入）：任意 32 字节 parse 不 panic，成功⇒标记/版本/保留字正确且 encode(parse(r))==r（规范形、单射）；不含 Some(0) 的覆盖值 parse(encode(ov))==Ok(ov) | kernel_core::capacity::{encode,parse} | Verus伴随(小端字段往返、0=不覆盖编码引理)/Proptest全域差分/Miri 损坏记录序列/fuzz差分/Kani全域(任意32字节；任意覆盖值)/Loom N/A | verified(model+Kani全域) / tested | 同上 | Kani parse_accepts_only_canonical_records、encode_parse_round_trip SUCCESSFUL（unwind 34）；Loom N/A：纯函数，无共享可变状态 |
| ACCEPT-TOOL-01 | 验收工具（Python/Bash，不进内核）：撞时限且串口没有任何第四阶段引导输出时重跑一次，第二次结果即最终结果，判据不变；现场工具与文件系统卡顿探针只读取或写入证据目录，不影响判定 | `scripts/accept.sh::boot_qemu`; `scripts/qemu-hang-dump.py`; `scripts/fs-stall-probe.py`; `scripts/s2.sh` | Verus N/A：验证链针对 Rust 代码，脚本无对应规格 / Proptest N/A / Miri N/A / cargo-fuzz N/A / Kani N/A / Loom N/A；替代证据：时限 2 秒的定点启动走到重跑分支并保留第一次日志、最终仍判 FAIL（accept-20261104-101653）；时限 125 秒的定点启动写出线程阻塞点（accept-20261104-101751）；全量 accept-20261104-113129 写出卡顿记录 | N/A（替代证据） | 见左列证据目录 | 重跑只覆盖未进内核的启动；VGA 文本屏在引导切换图形模式后读到 0xff，只有文本模式下的 panic 能读到；固件读盘报错的根因未查清 |
| ASSEMBLY-01 | 服务装配：启动顺序为能力依赖的稳定拓扑序（成环构造时拒）；模块就绪 ⇔ 自身激活成功 ∧ 依赖全部就绪；依赖未就绪 ⇒ Blocked 且不调用激活；全有全无下首个失败按就绪逆序回滚、什么都不发布、未尝试者保持 Declared；重复启动被拒且不调用激活；缺/重复绑定构造时拒 | kernel_core::assembly::{Assembly::new,order_by_dependencies,start,rollback} | Verus伴随(就绪集合依赖闭包在激活/回滚下保持)/Proptest差分(随机DAG≤8模块×随机声明顺序×随机成败×两种策略，512例)/Miri固定序列/fuzz差分100万/Kani(3模块任意成败×两策略)/Loom见ASSEMBLY-03 | verified(model) / tested / bounded Kani | VERUS=… bash verification/toolbox/run-assembly-suite.sh | Verus 0.2026.10.18 + Z3：13 verified/0 errors，负例（停用缺「无就绪依赖者」前置）precondition not satisfied；kernel-core 单元 5 passed；Proptest 3 passed（含成环拒绝）；Miri 1 passed；fuzz 100万 0崩溃 cov417（LeakSanitizer 开）；Kani 0.68 published_mask_never_reports_unready SUCCESSFUL（unwind 10，3 模块）；伴随模型不直接验证 Rust 源，一致性靠差分 |
| ASSEMBLY-02 | 能力发布真实性：发布掩码位 b 置位 ⇔ 声明能力 b 的提供者 Ready；audit 拒绝任何偏离（发布未就绪、就绪未发布、未知位、就绪模块依赖未就绪）；停用仅在无就绪依赖者且非常驻时成功，停用后撤回能力并按就绪逆序调用停用函数；内核 has_capability 只读发布掩码，装配前恒假 | kernel_core::assembly::{published_mask,audit,availability,mask_has,stop,stop_all}; kernel::assembly::{boot,available}; kernel::profile::has_capability | Verus伴随(停用保持闭包；负例)/Proptest(全部≤255种翻转均被拒)/Miri/fuzz(随机翻转)/Kani全域翻转(audit_rejects_any_divergent_mask)/Loom见ASSEMBLY-03 | verified(model+Kani) / tested | 同上 | Kani audit_rejects_any_divergent_mask SUCCESSFUL（任意非零 u32 翻转）；定点 ASM1：headless 8 模块全部 ready、declared=9 published=9 pre_publish=0 audit=ok、restart=already_started、stop_core=in_use |
| ASSEMBLY-03 | 内核发布协议：激活建立的状态（Relaxed）→ 发布掩码 Release 写；任意核 Acquire 读到位为 1 ⇒ 必然看见激活建立的状态；读到 0 ⇒ 不可用 | kernel::assembly::{PUBLISHED,boot,available} | Loom 模型(写者/读者两线程穷举交错)/替代：装配只在启动期单处理器执行、掩码本切片只写一次 | model-checked(Loom) | 同上 | Loom 1 passed；模型复刻内核协议而非直接运行内核代码；运行时撤回（第三片）未覆盖 |
| MODULE-MGR-01 | 既有 ModuleManager（补链：原无验证链）：load 检查顺序 重名→依赖→容量→init，init 失败不装载；unload 被依赖时拒（InUse）；unload_all 逆序；已装载集合恒对 requires 闭包且依赖排在前面 | kernel_core::module::ModuleManager::{load,load_all,unload,unload_all} | Verus伴随(同 ASSEMBLY-01 闭包引理：load=activate_step，unload=stop_step，unload_all=rollback)/Proptest差分(随机 load/unload/unload_all 序列≤24步×512，容量3，含 init 失败)/Miri固定序列/fuzz module_mgr 100万（任意≤64步序列）/Kani loaded_set_stays_dependency_closed（任意3步，容量2）/Loom N/A：&mut 单所有者无共享可变状态，替代证据为调用方独占（mech_demo 局部变量） | verified(model) / tested / bounded Kani | 同上 | kernel-core module::tests 4 passed；Proptest 序列差分 512 例通过；fuzz module_mgr 100万 0崩溃 cov100；Kani 0.68 loaded_set_stays_dependency_closed SUCCESSFUL（618 s，unwind 6）；Miri 固定序列含 ModuleManager 8 步 |
| ASSEMBLY-KANI-BIND | ASSEMBLY-01/02 与 MODULE-MGR-01：Kani：发版时验证。旧证据绑定提交 d0e7bc9（无内存上限，3 个 SUCCESSFUL）；bf9b1a0、6753a67 在 10 分钟 / 3.5 GB 上限下未判定（内存），0 个 Status: FAILURE，那个上限不作为发版时的配置 | kernel_core::assembly::proofs、kernel_core::module::proofs | Kani | Kani：发版时验证 | 发版时 `JASPER_RUN_KANI=1 verification/toolbox/run-assembly-suite.sh` | 同段代码的实质覆盖：Verus 13/0 + 负例、Proptest 3、fuzz 200 万（48cd76f）。d0e7bc9 至 48cd76f 只改测试模块，非测试代码未变 |
| BOOT-STAGE-REBIND | 阶段图加入 Stage::Assembly（COUNT=10，全集 0x3ff，requires=timer+capacity+profile）后复跑 BOOT-STAGE-01/02、CAP-RECORD-01 | kernel_core::boot_stage；verification/toolbox/verus/boot_stage.rs | Verus / Proptest / Miri / fuzz / Kani；Loom N/A：BSP 局部值，无共享状态 | verified(model) / tested / bounded Kani | VERUS=… bash verification/toolbox/run-boot-stage-suite.sh | 提交 06569ae：Verus 34/0 + 负例、kernel-core 5、Proptest 3、Miri 1、fuzz 100万 cov82、Kani 4 个 SUCCESSFUL（现行上限内）|
| TIMER-PROGRESS-01 | 定时器前进保证：连续短窗口的完整事务不超过 GRACE=2；宽限用尽后下一次完整事务之前至少留出 min(开销, cap)；时钟单调时最多等 cap 就放行；时钟倒退时放行；一次结算的欠账不超过 64 | kernel_core::timer_progress::Progress::{remaining,admit,record,defer,take_deferred} | Verus 伴随模型 11/0 + 负例 / Proptest 3（参照实现差分、事件序列模拟）+ core 4 / Miri 1 / fuzz 100 万 cov42 / Loom N/A：状态只由所属处理器关中断时访问，无线程交错，替代证据为 TIMER-PROGRESS-02 / Kani：发版时验证 | verified（模型）/ tested | VERUS=… bash verification/toolbox/run-timer-progress-suite.sh（仅VM） | 模型不直接验证 Rust 源码，一致性靠差分；时钟单调是假设 |
| TIMER-PROGRESS-02 | 接入路径：时钟相对指令很密时启动仍能前进（修复前 shift=8 卡第 552 行、shift=10 卡第 64 行）；正常启动几乎不推迟 | kernel::irq::on_hardware_irq；kernel::sched::{timer_admit,on_timer_interrupt,on_highres_timer,defer_timer_tick,rearm_after_defer}；Scheduler::settle_deferred_ticks | 真实 QEMU：scripts/timer-progress-check.sh（单处理器 shift 5–10）；accept 检查 TIMER-PROGRESS | tested | spot-accept 检查名 timer_progress | 只覆盖启动前 1200 行；不证明历史单处理器卡顿就是此活锁 |
| TIMER-PROGRESS-03 | 其他处理器进入高精度模式前的周期定时器接入前进保证：事务窗口不足时只记欠账，欠账在全局锁内补记且记账内容与正常 tick 相同；有欠账时不走租约快路径（修复前 4 处理器 shift=9 稳定卡第 437 行，各处理器定时器事务排满调度器锁） | kernel::irq::on_hardware_irq；kernel::sched::{on_local_timer,defer_local_tick}；Scheduler::{settle_deferred_local_ticks,charge_local_tick} | Verus/Z3 N/A：内核接入代码依赖全局调度器与中断上下文，判定逻辑本身由 TIMER-PROGRESS-01 覆盖，替代证据为真实 QEMU / Proptest N/A：同上，无可独立运行的纯函数 / Miri N/A：no_std 内核入口，无宿主可执行路径 / cargo-fuzz N/A：同上 / Loom N/A：欠账只由所属处理器关中断时访问 / Kani：发版时验证。真实 QEMU：timer-progress-check.sh（4:9、8:9）；不带 icount 的 4、8 处理器完整启动退出码 37、0 个功能失败 | tested | spot-accept 检查名 timer_progress | 只覆盖启动前 1200 行；icount 下继续运行到后段仍有演练超限（irqring 等待、irqstorm 延迟），未全部走完 |
| ARB-BATCH-01 | 仲裁演练：窗口内批处理任务确实得到处理器（started > 0）是功能断言；窗口内走到计数循环（ticks > 0）改记计时。2 处理器 shift=9 实测 batch_started=3、batch_ticks=0，切换日志显示 arb-load 被多次选中，原判据「被饿死」是误报 | kernel::arbiter_demo::{batch_task,run} | Verus/Z3、Proptest、Miri、cargo-fuzz、Loom 均 N/A：演练代码，只在客户机内运行，替代证据为真实 QEMU / Kani：发版时验证 | tested | boot-trace.py --smp 2 --icount 9 --stop-at-lines 700 | 真实饿死（整个窗口从未被选中）才判失败；窗口只有 80 tick，极慢时可能同样超出 |
| NS-BUDGET-01 | 纳秒预算结算：成功后 next 严格大于 end、相位不变、不超过 end + period，剩余不超过配额，同周期内减少量等于运行区间，跳过周期不累积配额；错误不改状态；千分比向上取整且不超过 1000。补链时发现周期数 +1 在 period=1、next=0、end=MAX 可溢出（经 new 构造时 next ≥ period，到不了），已改 checked_add | kernel_core::ns_budget::{Budget::new,Budget::settle,utilisation} | Verus 伴随模型 10/0 + 负例 / Proptest 4（128 位参照差分，全宽度）+ core 2 / Miri 1 / fuzz 100 万 cov50 / Loom N/A：调用方串行化的值类型，模块内无原子与共享状态，替代证据为 RT2 真实启动 / Kani：发版时验证 | verified（模型）/ tested | VERUS=… bash verification/toolbox/run-ns-budget-suite.sh（仅VM） | 模型不直接验证 Rust 源码，一致性靠差分；disable 与未启用分支只由 Proptest 覆盖 |
| NS-DIRTY-01 | 脏槽位位图：标记后可查、取走后不再有标记，按升序取走且不漏不重；越界标记不改状态并返回 false；只同步脏槽位与全表扫描在期限森林上结果相同（已发布事件与各处理器的根） | kernel_core::dirty_slots::{words_for,mark,mark_first,is_marked,take_next} | Verus 伴随模型 19/0 + 负例 / Proptest 2（参照实现差分、与全表扫描等价）+ Miri 1 / fuzz 100 万 cov349 / Loom N/A：位图只在全局调度器锁内访问，无线程交错，替代证据为 NS-DIRTY-02 / Kani：发版时验证 | verified（模型）/ tested | VERUS=… bash verification/toolbox/run-dirty-slots-suite.sh（仅VM） | 模型不直接验证 Rust 源码；等价性只针对期限森林，不覆盖调度器接入 |
| NS-DIRTY-02 | 接入路径：没有待同步标记的槽位，已发布节点等于应发布事件；没有待重读标记的在线处理器，缓存的根等于堆顶。任务表没有绕开标记的可变入口 | kernel::sched::slots::TrackedSlots；Scheduler::{refresh_ns_events,ns_audit,settle_highres,enable_highres,mark_current_exited} | Verus/Z3 N/A：接入代码依赖全局调度器与中断上下文，替代证据为每轮全表校验 / Proptest N/A：同上 / Miri N/A：no_std 内核入口，无宿主可执行路径 / cargo-fuzz N/A：同上 / Loom N/A：全局调度器锁内访问 / Kani：发版时验证；真实 QEMU：ns-dirty-audit 内核 1、4、8 处理器默认启动与 4 处理器 RT2 专项，每轮刷新后全表校验 | tested | spot-accept 检查名 ns_dirty | 变异 8 项抓到 4 项（到期弹出的根、IndexMut、写入后的新旧所有者的根）；到期弹出的槽位、退出移除的槽位、启用时全部标脏 3 项按代码推断为冗余，未用组合变异证实；get_mut 的标脏未抓到且未解释。只证明走到的路径；settle_highres 的全表结算仍在（第四片） |
