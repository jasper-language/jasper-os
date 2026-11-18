# Issue #35 启动线性映射与平台隔离切片

更新时间：2026-11-18。

状态：**映射包络失败关闭与 AArch64 平台参数隔离通过；Sv48、动态每核映射表和
多平台真实启动矩阵仍未完成。**

## 本切片

- 新增与 ISA 无关的 `kernel-core::boot_memory::linear_map_end`：完整 discovered
  物理图超过显式映射包络、发生溢出或映射粒度非法时返回 `None`，不截断；
- AArch64 完整内存图超过 512 GiB 映射包络时输出
  `discovered_end/admitted_end/rejected/complete=false` 并失败关闭，不再把超限 RAM
  标成 Reserved 后继续启动；
- RISC-V 通过同一准入函数保留既有 64 GiB Sv39 包络失败关闭语义，不把超限窗口
  转换成可发布 RAM；
- 通用 AArch64 直接启动只使用启动协议提供的非零 DTB 地址，不再要求 QEMU 风格的
  2 MiB 对齐猜测；
- Pixel 4 GiB 固件表窗口移入独立 `arch/aarch64/platform.rs` 验证适配器；通用 MMU
  和启动流程只读取 `BootPlatform` 选择结果；
- 初始最小线性映射长度同样由平台适配器声明，不再散落为 MMU 内的 QEMU/Pixel
  条件常量。

## 验证

```text
cargo test -p kernel-core boot_memory -- --nocapture
2 passed; 0 failed

cargo check -p jasper-kernel \
  --target aarch64-unknown-none-softfloat --no-default-features
PASS

cargo check -p jasper-kernel \
  --target riscv64gc-unknown-none-elf --no-default-features
PASS
```

纯机制测试覆盖 0、32/33、64 GiB 精确边界、64 GiB+1、512 GiB 最大包络、
`u64` 溢出、零粒度、最小终点高于最大终点；超限均返回拒绝而不是夹取。

全仓库硬编码存量从 435 个候选降为 428 个；新增候选为 0。下降来自平台参数集中
到适配模块、删除 AArch64 的 QEMU/Pixel MMU 条件常量，以及用包络准入替代夹取。

## 尚未完成

- AArch64 仍未实现按实际 IPA/VA 能力选择更小或更大页表模式的矩阵，512 GiB
  是当前布局的显式支持边界；
- RISC-V 仍固定 Sv39/64 GiB，尚未实现 Sv48 或其他模式的运行时协商；
- Pixel 固定窗口是显式验证平台适配，仍需要真实 UEFI 表地址证据来进一步取消；
- 尚缺多个不同 RAM 起点、稀疏/冲突窗口、>64 GiB RISC-V 和 >512 GiB AArch64
  的实际 QEMU/固件启动日志；当前证据为纯准入测试和交叉编译。
