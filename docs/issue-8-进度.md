# issue #8 进度：原生 ABI 世代（第一片）

- 日期：2026-10-27
- 分支：`dev/issue8-s1`（第一片初版 + 2026-10-28 节头解析补链）
- 范围：第一片可独立验收的切片；x86_64 为唯一运行目标，AArch64 / RISC-V 仅保持编译，不新增运行验收。
- 结论：第一片已实现并通过真实启动与六步验证链；发布快照、轮换与能力要求留待后续切片。

## 1. 本片目标

为 `jasper-os` 建立原生 ABI 的 `Major.Minor.Patch` 版本契约：

1. 版本只能有一个真源，构建期生成常量，不允许各调用者各写一份。
2. 每个用户程序携带可审计的 ABI 章。
3. 同一 `Major` 内，内核向后兼容此前稳定 `Minor`：程序要求的最低次版本不得高于内核次版本。
4. 跨 `Major` 不承担兼容义务，装载器必须在执行任何用户代码、映射任何页之前明确拒绝。
5. 提供运行期查询通道，供程序发现内核世代；查询不能替代装载门槛。
6. 错误分类稳定：元数据缺失/损坏与世代不兼容可被机器区分。

## 2. 已交付

### 2.1 单一真源与生成常量

- `abi/abi-version.txt`：`major=1`、`minor=0`、`patch=0`，是唯一手写版本声明。
- `kernel-core/build.rs`：解析该文件并生成 `kernel_core::abi_version::NATIVE`。
- `kernel-core::abi_version::{AbiVersion, ProgramAbi, AbiReject, NoteError}`：版本值、章编解码、兼容性判定与拒绝分类。
- 内核构建脚本再次解析真源，并与生成常量比对；两边解析器分歧会直接使构建失败。

### 2.2 用户程序 ABI 章

- 章固定 28 字节，节名 `.note.jasper.abi`，内容为：

  | 字段 | 宽度 | 值 |
  |---|---:|---|
  | `namesz` | 4 | 8 |
  | `descsz` | 4 | 8 |
  | `type` | 4 | 1（程序 ABI 要求） |
  | `name` | 8 | `JASPER\0\0` |
  | `major` | 2 | 主版本 |
  | `min_minor` | 2 | 程序需要的最低次版本 |
  | `patch` | 2 | 编译期修订版本（只记录） |
  | `flags` | 2 | 0（保留） |

- 15 个用户程序的链接脚本写入该章，构建脚本以 `--defsym=JSR_ABI_MAJOR/MINOR/PATCH` 传入版本。
- 章独占一页，与 `.text` 分属不同装载段，避免页粒度重叠。
- 内核构建脚本逐个解析内嵌用户 ELF，任何程序缺少章或章与真源不一致都会让构建失败。

### 2.3 装载前检查

- `kernel-core::elf` 在解析阶段读取节头表并提取 ABI 章；章格式非法、节头表损坏都返回明确错误。
- `kernel::proc::load_elf` 在映射任何页之前调用 `abi_version::check_image`。
- 拒绝分类：
  - 缺章 / 章损坏：`system.error.abi_metadata`（4136）
  - 跨主版本 / 次版本过新：`system.error.abi_mismatch`（4135）
- `kernel::proc::spawn` 同样把 ABI 拒绝映射为上述稳定错误码。

### 2.4 查询通道

- 登记 `system.abi.get`（ID 56），返回 `major << 32 | minor << 16 | patch`；保留高位必须为 0。
- `user/hello` 启动时查询内核世代，与编译期盖章值逐位比对，输出 `abi=1.0.0` 与 `abi_query=true`。
- 查询只用于发现；装载准入仍由内核查章完成。

### 2.5 冻结世代

- `abi/system-ids.lock` 增加 `# abi-generation: 1.0.0`。
- 冻结检查拒绝同一主版本的锁被复用到另一个次版本/修订版本，也拒绝跨主版本复用旧锁。
- 本片新增的两个错误码与 `system.abi.get` 尚未写入冻结锁，留给发布切片统一冻结。

## 3. 验收证据

### 3.1 真实启动（x86_64，单处理器）

定点验收实际运行了 `m11`、`abi`、`m51pre` 三项，结果均为 PASS。ABI 关键输出：

```text
[JSR-USERTEXT] task=user-hello bytes=9 text=abi=1.0.0
[JSR-USERTEXT] task=user-hello bytes=14 text=abi_query=true
[JSR-ABI] native=1.0.0 packed=0x100000000 single_source=true
[JSR-ABI] case=stamp major=1 min_minor=0 patch=0 matches_native=true
[JSR-ABI] case=accepted entry=0x100000401000 mapped=8
[JSR-ABI] case=missing reject=system.error.abi_metadata mapped=0
[JSR-ABI] case=malformed reject=system.error.abi_metadata mapped=0
[JSR-ABI] case=major_mismatch reject=system.error.abi_mismatch mapped=0
[JSR-ABI] case=minor_too_new reject=system.error.abi_mismatch mapped=0
[JSR-ABI] summary checks=19 failed=0 reclaimed=true
```

四类负例的 `mapped=0` 由页帧基线直接测得，证明拒绝发生在映射之前。演练结束后页帧回到基线。

QEMU 退出码为 37（仅计时类超界；功能失败数为 0），这是指令翻译型仿真的预期分类，不是功能失败。

### 3.2 六步验证链

登记条目见 `verification/PROPERTIES.md` 的 `ABI-GEN-01` 至 `ABI-GEN-06`。本片实际结果：

| 步骤 | 结果 |
|---|---|
| Verus/Z3 | 7 条 proof 通过，0 error |
| Proptest | 7 项测试通过（6 个性质 + 1 个确定性 Miri 用例） |
| Miri | 1 项确定性用例通过 |
| cargo-fuzz | 10000 次运行完成，无 panic / 无违例 |
| Kani | 3 个 `abi-fv` harness 全部 SUCCESSFUL |
| Loom | N/A：纯函数，无锁、原子或线程交错；替代证据为真实 QEMU 装载演练 |

### 3.2.1 ELF 节头 / ABI 章定位补链（2026-10-28）

第一片初版的验证只覆盖 28 字节章本身；`elf::parse` 新增的节头表与章节定位同样处理不可信映像，本次补齐全链（登记 `ABI-GEN-07`～`ABI-GEN-12`）：

| 步骤 | 结果 |
|---|---|
| Verus/Z3 | 地址算术模型 7 verified / 0 errors；off-by-one 负例必须失败，实测 1 error |
| Proptest | 4 个性质 × 512 例 + 1 个确定性用例，5 passed |
| Miri | 9 种拒绝/接受情形的确定性用例通过 |
| cargo-fuzz | 两种模式（任意字节 / 合法夹具改写）100 万次，0 崩溃 |
| Kani | 节名读取、节头读取 2 个 harness SUCCESSFUL |
| Loom | N/A：纯函数；替代证据为畸形输入覆盖 + QEMU `ABI`/`m51pre` 检查 |

同一脚本 `verification/toolbox/run-abi-suite.sh` 一次跑完 ABI 章与节头两部分；定点 `m11 abi m51pre` 复跑 PASS。

Kani harness 只在 `abi-fv` 特性下编译，默认 Kani 套件的 harness 计数保持不变。

工具版本：rustc `1.101.0-nightly`、Kani `0.68.0`、CBMC `6.11.0`、Z3 `4.16.0`、Verus `0.2026.10.18.7d82994`。

### 3.3 复现

```bash
cargo test -p kernel-core
cargo build --release --target x86_64-unknown-none -p jasper-kernel
bash scripts/accept.sh          # 定点模式可只选 m11 abi m51pre
VERUS=<verus> bash verification/toolbox/run-abi-suite.sh
```

## 4. 明确未完成（后续切片）

1. **发布快照与轮换**：尚未生成不可变的 ABI 快照、未实现快照目录与轮换流程。
2. **能力要求**：本片只做版本门槛，尚未把 ABI 世代与 Profile/能力声明绑定。
3. **冻结登记**：新增错误码与 `system.abi.get` 还未进入 `abi/system-ids.lock`，需要随发布决定统一冻结。
4. **其它指令集**：AArch64 / RISC-V 只保证编译与章生成，未新增运行验收；按冻结要求不扩大验收面。
5. **全量验收**：本片只做定点验收，未运行全量验收，也不把定点 PASS 表述为全量通过。

## 5. 结论

第一片已经形成闭环：版本有唯一真源，用户程序有可审计的章，构建期拒绝失配，装载器在映射前拒绝缺失/损坏/跨主版本/次版本过新，运行期查询与编译期声明一致。后续切片应在不改写本片语义的前提下补齐发布快照、轮换与能力绑定。

## 合入记录（2026-11-03）

第一片已变基到含 issue #1/#2/#3/#4 第一切片的主线后合入：`system.abi.get` 改接主线的宏分发表（登记表与分发表的编译期相等断言同样覆盖它）。变基后重新通过 ABI 六步链（`verification/toolbox/run-abi-suite.sh`，Loom 仍为 N/A）、定点 ABI 检查与全量验收（100 项通过、0 失败、6 行计时类仅作参考）。

## 第二片：不可变完整契约快照与发布门槛（2026-11-07）

- 分支：`dev/issue8-s2`
- 基线：Wave 4 合入后的 `dc3f7ba`
- 状态：实现完成，等待批次集成全量；本片不把定点结果表述成全量通过。

### 1. 本片解决的问题

第一片的 `abi/system-ids.lock` 只比较 ID、种类和名字，`abi-version.txt` 只声明版本号；两者都不能证明参数形状、Rights、Ring/Channel/Spawn 记录、取消/完成语义没有在同一主版本内被悄悄改变。本片新增按 ABI 版本独立保存的完整契约快照，并把快照与真实源码常量、登记表、构建脚本和 CI 连通。

### 2. 已交付

| 项 | 内容 |
|---|---|
| 契约导出 | `kernel_core::abi_contract::render_current` 从 `abi/system-ids.txt` 与源码权威常量生成确定性快照。接口按 ID 排序，改变登记表顺序不会造成无关差异。 |
| syscall 覆盖 | 57 个登记操作都有一条参数/返回形状记录；全部操作和错误接口同时记录 ID、种类、单项版本与副作用。缺失、重复或额外签名都会使生成/构建失败。 |
| Rights 覆盖 | `READ/WRITE/EXECUTE/WAIT/CONTROL/DUPLICATE/TRANSFER/MAP/SUBSCRIBE` 的名称与位值进入快照。 |
| 定长布局 | 快照登记 Program ABI 章、256 位 syscall set、Ring SQE/CQE/enter/deadline-enter/MsgDesc、SpawnDesc v2、内存映射、RT/亲和、订阅、ABI-R 扩展描述符与设备记录/描述/能力记录的尺寸、版本、magic 和字段偏移。 |
| 语义契约 | 明确记录 syscall 返回编码、能力检查顺序、Handle 世代、Rights 只降不升、异步请求单终态/发布顺序/取消线性化、spawn 子集与失败原子性、模块能力发布/撤回，以及未来跨域对象所需的身份、取消、服务死亡、回滚和同口径性能门槛。 |
| 不可变快照 | 每个 ABI 版本对应 `abi/snapshots/<Major.Minor.Patch>.contract`。当前为 `abi/snapshots/1.0.0.contract`，214 行。生成工具拒绝覆盖已存在的不同快照。 |
| 构建期门槛 | `kernel/build.rs` 渲染当前契约并校验：当前版本恰有一个同名快照且逐行一致；同主版本旧快照只能被新增条目扩展；Patch 升级必须保持正文完全相同；跨主版本不继承旧快照。失败直接阻止内核编译。 |
| 发布脚本 | `scripts/abi-release.sh Major.Minor.Patch` 只能单调提升版本，更新唯一真源并创建该版本的新快照；随后运行完整快照检查。`scripts/abi-freeze.sh` 冻结名字/ID 后也复跑完整契约检查。 |
| CI 历史不可变 | `scripts/abi-contract.sh immutable <base>` 拒绝修改、删除或重命名 base 中已有的快照，只允许新增文件；CI host job 使用完整 checkout 执行当前快照检查与历史门槛。 |

### 3. 三类发布路径

1. **内核变、ABI 不变**：不改 `abi-version.txt` 和任何快照；允许内部实现、性能和安全修复，只要外部契约未变。
2. **同主版本新增次版本**：提升 Minor，新增快照。当前契约必须逐行包含旧快照的全部条目；可以新增操作/布局/语义，不能删除或改写旧条目。
3. **主版本轮换**：提升 Major，新增该主版本的快照；不要求继承旧主版本的 ID、布局或语义。旧程序仍由装载器在执行前按 Major 明确拒绝。

补丁版本单独受更严格约束：Patch 只表示不改变契约的修订，因此新增 Patch 快照的正文必须与同主同次的旧契约完全相等。

### 4. 验证

| 层 | 结果 |
|---|---|
| 快照生成/检查 | `bash scripts/abi-contract.sh check`：PASS，`1.0.0` 当前快照与源码一致 |
| kernel-core 单元 | `cargo test -p kernel-core abi_contract --lib`：6 passed / 0 failed |
| Proptest | `cargo test --manifest-path verification/toolbox/Cargo.toml --test abi_contract`：3 passed / 0 failed；任意正文行变异都被拒、任意伪造版本不能绕过当前快照要求 |
| Miri | PASS：构建 VM `cargo +nightly miri test ... --test abi_contract contract_snapshot_rules_under_miri`，1 passed / 0 failed；只覆盖纯函数 |
| cargo-fuzz | PASS：构建 VM `cargo fuzz run abi_contract -- -runs=100000`，100000 DONE、0 崩溃，最终 cov 335 / ft 1096。首轮抓到 fuzz 夹具自身在 UTF-8 非字符边界切分的问题；修正夹具后重新跑满 |
| 内核构建期门槛 | `cargo check -p jasper-kernel --target x86_64-unknown-none --no-default-features`：PASS；构建脚本实际读取并校验当前快照 |
| 真实装载回归 | `accept-20261107-144141` 定点 SPOT PASS：`ABI` 与 `m51pre` 均 PASS；缺章/损坏/跨主版本/次版本过新均在映射前拒绝，QEMU 37 仅为计时参考 |

### 5. 明确边界与后续

1. **能力清单尚未随程序 ABI 章下发**：本片让 Profile/能力的发布语义进入契约、防止未来悄悄改变，但用户程序的 `.note.jasper.abi` 仍只有版本字段；下一片需设计版本化的 required-capabilities 章，并在映射前按生效 Profile 的真实服务面校验。
2. **Jasper 语言侧程序盖章**：当前真实用户程序都是仓库内 Rust 程序；Jasper 工具链可用时必须在同一装载门槛下增加真实 Jasper 产物。
3. **语义文本仍是设计契约**：快照能机械阻止语义文字在同一主版本内被修改，但不能自动证明实现永远符合文字。实现行为由 Ring/调度/对象等专项验证承担。
4. **历史不可变防误改**：CI 能阻止普通修改/删除旧快照；拥有仓库写权限并能同时修改 CI 的对手不在该门槛的威胁模型内。
