# Issue #35 硬编码存量分类账

更新时间：2026-11-21。

状态：**全部 202 个基线命中已聚合为 184 个唯一指纹，并按消费者、规范或明确
安全策略完成首轮分类；`unclassified=0`。**

## 为什么不是 347 个 Bug

规则扫描只能指出“需要裁决的常量、平台名称或发现路径回退”。同一个数值可能是
协议字段宽度、安全解析上限、真实运行时预算、测试夹具或已确认缺陷。分类账要求
每个基线指纹具有唯一类别和非空理由，但不会把启发式类别自动升级为“已修复”。

分类由“路径 + 规则 + 完整规范化源码行”的 SHA-256 指纹绑定。当前 202 个命中聚合
为 184 个唯一指纹；相同源码行出现多次时保留 `count`。此前指纹解析在源码的类型
冒号处截断，曾把不同标识符但相同尾部类型的常量错误合并；修复后独立候选全部
重新分类，`unclassified=0`。

## 当前分类

| 类别 | 唯一指纹 | 基线命中 | 含义 |
| --- | ---: | ---: | --- |
| `explicit-safety-policy` | 103 | 104 | 有界工作、解析/等待上限、fail-closed 或诊断哨兵、明确策略默认 |
| `runtime-resource-capacity` | 0 | 0 | 运行期集合/容量，应由资源预算和准入决定 |
| `platform-adapter` | 28 | 44 | QEMU/Pixel 等架构特定选择，需保留显式 Profile 边界 |
| `protocol-abi` | 42 | 43 | Wire、FDT/PCI、Linux UAPI、磁盘格式、地址宽度或内部位域契约 |
| `confirmed-defect` | 0 | 0 | 当前分类账中尚无新增的已证实未修缺陷 |
| `test-demo-fixture` | 11 | 11 | 显式 benchmark、probe、capacity 或 PCI 模型夹具 |
| `unclassified` | 0 | 0 | 所有基线指纹均已有可核查理由 |

`confirmed-defect` 和 `unclassified` 同时为空不代表 Issue #35 全量完成。当前基线
已全部归类，但运行时容量、安全策略和平台矩阵仍需真实预算、负例和资源回收证据。

`compat-core/src/native.rs` 的 futex 已删除 `MAX_FUTEX_WAITERS=8` 隐藏默认值；
`Futex<N, W>` 现在要求调用方同时显式声明 word 与 waiter 容量，现有调用方已逐项
选择预算，避免默认值在消费者不知情时成为运行期容量。

`compat-graphics` 删除了固定的 32 槽 `MAX_IMPORTS`。缓冲区与图像导入容量现在由调用方
通过类型参数分别选择，33 个导入跨过旧上限的回归同时验证配额累计与撤销回收。

`kernel-core::elf` 删除了固定的 16 个 PT_LOAD 段实现上限。段元数据按程序头实际
数量执行可失败分配，并按页地址排序后检查相邻区间；33 个乱序段、默认无分配构建和
内核完整检查均有回归证据。

ACPI DMAR 删除了固定的 8 个 hardware unit、32 个 device scope 与 8 级 bridge
path 实现上限。三级拓扑都按固件表长度执行可失败分配；10 units、40 scopes 和
12 级 path 的宿主回归及内核构建均通过。

x86_64 ECAM 不再叠加 256 MiB 软件夹取。窗口长度直接来自 ACPI `Ecam` 的
`u8` 起止总线范围，映射仍检查基址、页对齐和地址溢出。

Linux/Android 兼容状态中的行内槽位检查也完成了一轮消费链审计。Binder、
inotify/fanotify、userfaultfd、消息队列、fs-context、Landlock、ION、dma-heap、
dmabuf、sync_file、AIO 与 sealed-range 不再使用 8/16/32/64 的私有实例上限；
进程内元数据使用已验证的 `handles_per_process`，全局消息队列名使用
`max_objects`，分配仍通过 `try_reserve` 失败关闭。该审计覆盖的是常量扫描器无法
识别的 `len() >= N` 行内容量，不能把扫描器 `runtime-resource-capacity=0` 当作
整个问题的唯一证据。

增量门禁已新增 `HC-G9`，未来出现 `if/while ... len()/count() >= 数字` 会直接失败；
该轮行内整改没有把固定阈值移到另一处来绕过扫描。

启用 `HC-G9` 后新增识别出 5 个既有命中：4 个是 JASO/FUSE 记录宽度、登记表字段数
和 u32 发布掩码边界，保留为 `protocol-abi`；AArch64 UEFI 控制台原有的 256 字节
文本上限已改为逐字符输出，不再拒绝合法长行。

AF_UNIX `listen` backlog 也改为使用同一进程对象预算；Linux ABI 的零值仍按规范
折算为一个等待连接。

原生 CLI 的 `echo` 输出也删除了 256 字节输入上限和 300 字节拼接缓冲，改为按
前缀、调用方文本、后缀分段写入；容量由终端会话和实际输入长度决定。

统一授权的 MAC 策略包不再固定为 32 条规则。策略类型改为由已验证包的
`Vec<MacRule>` 驱动，64 条规则回归通过；内核显式启用 `mac-dynamic`，普通无堆用户
程序仍只看到不分配内存的标签类型，不会因此要求全局分配器。
首个生产程序会在记录页帧/堆回收基线之前显式安装 MAC 策略，避免持久策略分配被
误计为程序泄漏；真实 OVMF/virtio-blk 复现达到 `reclaimed=true`。

`compat-loader` 删除 17 个实现包络：program-header/PT_LOAD 数、重定位数、
Android packed-relocation 字节、动态库名数量与长度、TLS/生命周期/COPY 大小、
模块与 lifecycle 数、入口调用数、初始栈字节/项数和 auxv 项数。段、重定位和
符号元数据改由实际 ELF 表、布局范围及可失败 `try_reserve` 决定；47 位用户地址
仍是明确登记的 x86_64 canonical 平台事实。

Linux 兼容适配器进一步把 iovec、`sendmmsg`/`recvmmsg`、`process_madvise`
统一到 UAPI `UIO_MAXIOV=1024`，把 `futex_waitv` 统一到
`FUTEX_WAITV_MAX=128`，而不是原先自造的 16/64。`io_uring` 的 SQ/CQ/SQE
偏移、ring 大小和可失败容量现在由请求 entries 动态生成，支持协议上限 32768，
并删除每进程 8 ring 的实现上限。

同时删除 `write/pwrite`、buffered cache、`fallocate`、`remap_file_pages`、
`mlock`、匿名映射、fs-verity、socket control、legacy AIO 输出、LSM 上下文和
`poll` 的私有字节/条数包络；复制和输出仅由调用方长度、用户地址范围、进程
预算及可失败内存准入决定。

`kernel/src/arch/x86_64/bm1.rs` 明确是 QEMU-only BM-1 验收 Profile，且对默认
内核无影响；其 8 MiB trace buffer 与相关固定值按测试夹具登记，不冒充生产运行期
容量。

PIT 通道 2 的忙等不再保留独立的 50,000 微秒实现包络，而是由 16 位计数器上限与
PIT 输入时钟推导完整计数周期；来源登记为 Intel 8254 硬件契约。该值只决定单次
硬件计数的最大范围，多段等待继续由调用方实际时长驱动。

capacity 派生、Linux 映射批次、console v1 单次调用帧与隔离服务 wire 帧的
`.min` 也已完成来源登记。它们分别引用已验证的 `KernelConfig` 准入值、版本化
单次调用边界和版本化 wire 数组宽度；登记只豁免扫描器的“无来源固定值”，不把
这些边界冒充为可无限扩展的运行期容量。

FS-0 entry name、Sandbox launch v1 display path 和 USI v1 module version 也已
绑定到版本化记录字段和边界负例：三者分别接受完整 64/64/8 字节字段，并对
65/65/9 字节输入失败关闭。存量因此降至 222 次 / 202 指纹。

`KernelConfig` 的 20 个 bounds 与 Standard/Compact Profile 参数现已逐行绑定
到同一 `kernel-config-policy-v1` 来源。这些值不是硬件事实：`KernelConfig::validate`
在发布容量前按字段检查上下界、时钟/QoS/内存/IPC 一致性，失败返回具体字段；
负例覆盖 timer、tasks、RT、objects、kernel stack、guest frames、mapping pages、
endpoints 与 IPC 字节关系。分类账因此再降至 202 次 / 184 指纹。

Linux robust-list 的 64 节点上限属于故障进程退出时的有界遍历与环检测保护；该路径
不能依赖堆分配成功，因此按显式安全策略登记。

`kernel-core/config.rs` 的 Task/Object/RT/timer/stack 上下限由
`KernelConfig::validate` 在发布容量前逐项校验并拒绝越界值，属于声明式产品验证
策略，而不是硬件发现事实或运行期集合容量。

`BootSpec` 的 256 区域上限发生在堆和页帧分配器之前；溢出被计数，且
`has_complete_regions` 会在内存图不完整时阻止帧分配，因此属于引导期安全策略。

调度器 wake/PI mailbox 的满队列行为返回 `Full`，要求调用方同步完成或重试，
不会覆盖或丢弃请求；对应满队列负例已存在，因此登记为中断安全背压策略。

SysV `msgmni`、`semmni`、`semume` 会通过 `IPC_INFO` 回传给用户态，是兼容 Profile
的公开配额；超限创建或 undo 注册被结构化拒绝，当前按显式兼容策略登记。

分类器同时纠正了三类误报：进程内存常量只是已验证 `KernelConfig` 的编译期别名；
`MIN_CPU_LIMIT` 是公开准入下界；用户运行时栈/模块槽位是冻结的虚拟地址布局。
IRQ probe 与隔离宿主容量属于确定性验收夹具。订阅队列的 64 订阅者、16 条队列和
每进程 512 slot 都是有界背压策略：满队列交付一次权威 Resync，准入失败原子拒绝，
因此不登记为隐藏运行期容量。

## 校验

```text
python3 scripts/check-hardcode-inventory-ledger.py --self-test
python3 scripts/check-hardcode-inventory-ledger.py --check \
  docs/hardcode-inventory-ledger.json
```

检查器验证：

- 每个基线指纹恰好出现一次；
- 不允许额外指纹或缺少指纹；
- 路径、规则、出现次数与 baseline 一致；
- 类别属于固定集合，理由非空；
- 声明的唯一指纹计数、基线命中权重和逐项条目一致，权重总和必须等于 202；
- 当前源码扫描与 baseline 没有漂移。

修改生产代码清除条目后，应先用 `--write-inventory-baseline` 更新基线，再重新生成
分类账；禁止手工修改指纹或把未知项批量标为安全策略。

## 后续清零顺序

1. `runtime-resource-capacity` 已清零；后续仍以真实消费者压力补拒绝、回收和
   多实例证据；
2. 将 103 个 `explicit-safety-policy` 指纹逐项绑定到规范、策略或负例证据；
3. 把 28 个 `platform-adapter` 收敛到经验证的平台 Profile；
4. 审核 42 个协议条目和 11 个夹具，确认冻结边界不会泄漏到生产；
5. 只有调用链、负例和资源回收证据完整后才允许清除基线条目。
