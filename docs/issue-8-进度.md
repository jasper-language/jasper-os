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
