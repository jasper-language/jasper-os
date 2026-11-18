# Issue #35 Linux ABI 与 ACPI 边界切片

更新时间：2026-11-18。

状态：**Linux 大请求错误语义已修复；ACPI 解析容量被确认为显式安全策略。**

## Linux ABI

- `write/pwrite64` 超过 1 MiB 不再返回 `EINVAL`，而是只执行本次兼容服务可容纳的
  有界前缀并返回实际字节数，调用方可按 Linux 语义继续；
- `getdents/getdents64` 不再拒绝大于 64 KiB 的用户缓冲，而是最多生成 64 KiB
  记录并返回本次实际结果；
- `sendmmsg/recvmmsg` 不再因 `vlen>16` 返回 `EINVAL`，而是有界处理 16 条并返回
  实际消息数；
- io_uring `entries` 使用 checked power-of-two；超过 64 且未声明
  `IORING_SETUP_CLAMP` 时返回 `EINVAL`，声明后显式钳制到当前支持上限；
- `eventfd` 最大计数 `u64::MAX-1` 和 alternate-signal-stack 最小尺寸属于 Linux
  UAPI 语义，不作为运行时资源容量；
- LSM context 4096 字节是当前兼容服务的有界复制策略，不冒充 Linux 内核 ABI。

这些上限仍应逐步接入 Workload IO/CPU 配额；本次先修正“合法大请求被当成参数错误”
以及静默钳制问题。

## ACPI

- `MAX_TABLE_LEN=1 MiB` 是解析不可信固件前的防耗尽策略；
- DMAR unit/scope/path 数组是有界解析容量，超出只累计 `dropped`，现有生产消费者
  在 `dropped != 0` 时拒绝启用 IOMMU，不把截断结果作为完整设备映射；
- ISA IRQ 无 ACPI override 时使用总线默认的高电平、边沿触发与恒等 GSI，这是
  规范默认，不是读取失败伪装；
- 这些条目进入分类账的 `explicit-safety-policy` 或 `protocol-abi`，不从门禁中
  直接删除。

## 验证

```text
cargo check -p jasper-kernel --target x86_64-unknown-none \
  --features compat-syscall-verify
PASS

python3 scripts/check-hardcode-inventory-ledger.py --self-test
python3 scripts/check-hardcode-inventory-ledger.py --check \
  docs/hardcode-inventory-ledger.json
```

## 尚未完成

- 真实 Linux 程序的大缓冲 write/getdents、大 vlen mmsg 和 io_uring clamp 行为；
- ACPI 真实多表、超过 1 MiB 的合法厂商表、多个 DMAR unit/scope 与多跳 bridge
  拓扑矩阵；
- 所有动态批次最终应读取 Workload IO/CPU 预算，而非长期固定为兼容服务常量。
