# Issue #35 CPU 拓扑完整性切片

更新时间：2026-11-18。

状态：**软件容量矩阵通过；超过 128 的堆后备每核状态与真实 LoongArch
多拓扑运行仍未完成**。

## 本切片

- `CpuSet` 从 32 位单字扩展为两个 64 位字，运行时准入宽度与启动前的
  `BOOTSTRAP_CPUS=128` 库存宽度一致；
- 同一软件制品覆盖 1、32、33、64、128 CPU 集合，未在 32 处静默截断；
- 超过显式 128 容量不能插入，统一 SMP 启动门仍以
  `discovered/admitted/capacity/dropped` 失败关闭；
- `bits_u64()` 对含第 64 位以上成员的集合返回 `None`，旧 64 位亲和 ABI 不再
  静默移位或截断；
- LoongArch 启动前发现现在分别保留有效 discovered、容量溢出、转换失败和
  disabled 数量；重建统一拓扑时恢复 `dropped` 与 `disabled`，不会把固件已报告
  但禁用的 CPU 当作不存在；
- 调度器每核运行叶扩展到同一 128 槽，避免集合可表达但调度器在 32 槽后越界；
- Task affinity 旧 ABI 对 64 位无法表达的高位成员返回无效参数。
- Linux `sched_getaffinity` 的 64 位 legacy mask 若包含 CPU64–127，同样返回
  `EINVAL`，不把高位静默截掉；RT placement 的旧 64 位选择路径也失败关闭。
- 全仓库硬编码审计从 437 个候选降为 435 个：FD 表固定容量和 32 CPU
  `MAX_CPUS` 转为运行时预算/明确 128 槽准入，新增候选为 0。

## 验证

```text
cargo test -p kernel-core smp::tests
19 passed; 0 failed

cargo check -p jasper-kernel \
  --target x86_64-unknown-none --no-default-features
PASS

cargo check -p jasper-kernel \
  --target loongarch64-unknown-none-softfloat --no-default-features
PASS

cargo check -p jasper-kernel \
  --target aarch64-unknown-none --no-default-features
PASS

cargo check -p jasper-kernel --target x86_64-unknown-none \
  --features compat-syscall-verify
PASS

python3 scripts/check-hardcode-gate.py --base c8151f5
PASS
```

## 尚未完成

- `CpuSet`、每核运行队列、IRQ 和静态元数据仍是固定 128 槽；合法 >128 拓扑
  会明确拒绝，但还不能在同一制品中准入；
- Task affinity 等旧 ABI 仍只有一个 64 位掩码，128 CPU 的完整用户态 ABI 需要
  版本化动态 CPU 集合或分段 mask；
- LoongArch QEMU/真实固件的 33/64/128 CPU 压力启动与 disabled/重复/稀疏标识
  端到端日志尚未取得；当前只完成宿主机纯机制和交叉编译验证。

因此本切片不能宣称 Issue #35 HC-A01/A02 已全量关闭。
