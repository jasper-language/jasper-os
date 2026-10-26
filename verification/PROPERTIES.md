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


## FV-1 真实代码有界验证（V2）

机器可读逐性质规格、工具/版本、输入位宽、容量/步数、TCB、复现和最新记录统一登记于`verification/FV1.toml`。12项Kani harness实际通过，0失败，无assume/stub；不是测试结果的改名。

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| FV1-V2-SUITE | 权限不提升/未授权拒绝、代次/引用、真实跨表转移、Ring唯一性及配额/索引边界 | `kernel-core/src/{fv1,object,objtable,quota}.rs` | Kani | proved | `bash verification/run-kani.sh` | 各有界范围见FV1.toml；容量1/2、Ring4步、64位目标；锁/硬件/完整Channel队列不在代码证明内 |
| FV1-RING-LIVE | 一个执行中请求在显式弱公平后端完成/发布/回收假设下最终回收，始终保持唯一性与缓冲静止约束 | `verification/ring_fv1.tla`; `async_ring::{finish,cancel,close,quiesce}` | TLA+ | model-checked | `bash verification/run-ring-fv1-tlc.sh` | 54可达状态；公平性是假设，不证明真实调度器/驱动最终进展 |

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

| KRN2-SYNC-WORK-01 | 可选诊断分别报告global事务和全部在线叶获取，固定拓扑下leaf=online*transactions | sched::SYNC_WORK / scale_demo::contention | 实际内核计数契约 | tested | KRN2_OBSERVE=1 bash scripts/krn2-churn-sample.sh UNIQUE 1 4 8 | 实际事务/叶获取7/7、57/228、210/1680均覆盖；仅观测、不参与许可，global下更新/reset/snapshot，含观察事务；leaf_contended是非零自旋观测，不同于global try_lock失败；32位无回绕窗口；不含fast try_lock/发布周期或物理成本，诊断改变执行成本；默认关闭 |

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
- 环境：构建虚拟机；QEMU 只验 x86_64。
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
- 宿主经构建虚拟机执行同一命令：
  `bash verification/run-tlc.sh`
- 全量 x86_64 验收：`bash scripts/accept.sh`（单核、4 核、8 核与 q35；AArch64/RISC-V 记 N/A）。
- 公开复验入口：`bash verification/run-tlc.sh`；具体性质与适用范围见本表。


## Additional bm1 contract scopes

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

| EVT2-USER-SOURCE-01 | 公开创建的Process/Task cap可按权限订阅，初始快照与退出事件无缺口 | kernel/src/subscription.rs; proc/spawn.rs; syscall/mod.rs; user/ring/src/main.rs | CPL3/QEMU | tested | bash scripts/evt2-object-sample.sh UNIQUE | 4489 1/4/8各33；公开task/process.spawn退出49/51；process最小ELF为x86专用，非全ISA/任意调度证明 |
| EVT2-PRESSURE-DIRTY-01 | 清dirty在采样之前，静止且无dirty时无漏最终状态 | verification/pressure_event_dirty.tla | TLA+正负例 | model-checked | bash verification/run-pressure-event-dirty-tlc.sh | 18states/21gen/深8；clear-after负例真违例；模型不证明硬件/内存序，实际压力State合并中间态 |
| EVT2-PUBLISHER-ANCHOR-01 | 活publisher保留anchor，用户cap全关后仍可重发放，结束后不复活 | verification/subscription_publisher_anchor.tla; kernel-core/src/objtable.rs; kernel/src/subscription.rs | TLA+/真实ObjectTable/QEMU | tested | cargo test -p kernel-core --lib publisher_anchor_keeps_source_regrantable_until_publisher_finishes | anchor正负模型/实际契约/80060全源三档过；不改ObjectTable Closing规则，非全图无环证明 |


## CPU limit observation-window correction

| ID | 性质 | 代码位置 | 方法 | 状态 | 复现 | 假设/未覆盖 |
|---|---|---|---|---|---|---|
| BUDGET-WINDOW-OBS-01 | 单观察者在调度器事务内arm/start，第一次BSP截止事务只捕获一次，finish区分固定窗口/完整生命周期/尾段并检查守恒，原160tick上界52不增大 | Scheduler::limit_window_arm/tick/limit_window_finish; balance_demo::limit | 实际八核隔离契约 | tested | VM CPU cap50且仅经vm-run执行 bash scripts/limit-window-sample.sh UNIQUE | limit-window-split-20261025整批0/guest33：window51<=52、life51<=60(elapsed190)、tail0、原资源断言过，source前后/host同。仅记账事务边界：pending已drain、当前BSP扣费前；不是硬件IRQ发生时间/弱内存/全调度证明。前置诊断cutoff49/life62的旧断言失败保留；原FULL54未逐tick还原。默认完整回归及纯窗口状态机/六工具覆盖仍待，不标proved |

| BUDGET-WINDOW-MODEL-01 | 截止快照一次捕获且尾段不能改写，finish保持窗口/尾段分账守恒 | verification/limit_observation.tla | TLC正模型+改写cutoff负例 | model-checked | bash verification/run-limit-observation-tlc.sh; bash verification/run-limit-observation-tlc.sh limit_observation_rewrite.cfg（预期Safety反例） | 50753整批0，71distinct/85generated/depth10；负例真Safety违例。仅单观察者、最多4次charge/3tick原子状态；不证明Rust/IRQ时刻/预算准入，Busy/溢出/迟截止尚未包含 |

| BUDGET-CORE-TOOLS-01 | 单CPU按eligible准入的CpuLimit保持窗口界与使用次数；分账整数恒等式成立 | kernel_core::sched::limit::CpuLimit; toolbox/tests/limit.rs; toolbox/src/lib.rs::limit_admitted_eight_steps | Verus伴随/Proptest/Miri/fuzz/Kani/Loom适配 | tested / bounded Kani | 见docs/EVT-2-status.md limit-tools-20261025 | 实际Verus8总proof/Miri8/Proptest128/fuzz10000/Kani8步1harness/Loom1；Kani显式合法rate/burst域假设，不证明多核准入/硬件时间/生产锁。Loom为Mutex适配，主FV1的15项不变；raw证据PASS不推断已丢失host session的总退出码 |
