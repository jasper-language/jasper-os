# Issue #35 策略边界与发现回退切片

更新时间：2026-11-18。

状态：**配置/策略常量已分类，FDT 深度和必需设备事实的缺陷修复通过测试；真实
多平台展开仍属于后续运行矩阵。**

## 裁决

### HC-A09：FDT 最大深度 16

该值不是硬件事实，而是无堆解析器固定 `cells` 栈的安全上限。walk、strict
validation 和 subtree skip 现在使用一致边界：根节点计 1 层，最多 16 层；第 17 层
失败。根节点名称非空也在 walk 与 strict 两条路径同时拒绝。没有删除深度防护。

### HC-A12：生命周期文件加载 1–32 MiB

这些读取仅存在于 `lifecycle-root-exec-verify` 或 Android/ART 验证特性；它们限制
验证镜像读取，不是生产更新包格式或 LC-2 包大小。生产健康链继续读取 ELF/metadata
前缀和实际 P0 分区，不依赖这些 probe 上限。保留为测试/验证策略。

### HC-A13：IOAPIC serial/RTC binding

固定的是本构建已实现的设备驱动清单，不是 IOAPIC 物理线数。实现会枚举 MADT
声明的全部控制器和读数确认的全部 pin、全部初始屏蔽，并把未支持设备计数输出。
AML `_CRS` 和更多设备的动态资格仍属于设备生态范围。

### HC-A15：发现路径 `unwrap_or`

- GIC 缺 distributor、CPU interface 或 redistributor 必需 `reg`/长度时，不再生成
  `base=0` 的伪设备；
- PL011 缺 `reg` 或长度为零时返回未发现；
- `simple-framebuffer` 缺 `reg/width/height/stride/format` 或零尺寸时返回未发现；
- FDT 规范默认 `#address-cells=2`、`#size-cells=1` 和明确绑定的
  GICv3 `redistributor-stride=128 KiB` 保留；
- CMOS RTC century 寄存器为零表示平台未提供；其他非法 BCD 直接失败，不再伪装成
  19xx/20xx 年份。

## 验证

```text
cargo test -p kernel-core fdt -- --nocapture
13 passed; 0 failed

cargo check -p jasper-kernel --target x86_64-unknown-none --no-default-features
PASS
```

新增负例覆盖 16/17 层 FDT 边界、非空根名、缺失 GIC/PL011/framebuffer 必需事实。

全仓库硬编码候选从 423 降为 414，新增 0；下降来自删除 9 个把读取失败解释为零
事实的发现路径回退。

## 尚未完成

- 需用真实 AArch64/RISC-V FDT 变体和 x86 ACPI 设备集运行展开矩阵；
- IOAPIC `_CRS`、更多设备资格和设备热插拔仍归后续设备生态/LC-4；
- 生命周期 probe 上限后续应按真实验证镜像预算配置化，不能扩展为生产包限制。
