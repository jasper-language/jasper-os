# MSI 向量与 TLB 击落批大小

更新时间：2026-11-19。

状态：**两项数值分别属于硬件协议表示和明确的批处理安全策略，不是待扩容的
运行期集合容量。**

## MSI 向量编号

`kernel_core::msi::MAX_SLOTS = 256` 对应 8 位 MSI vector index 的完整表示范围。
来源登记为 `Intel-SDM-Vol3-Vector-Fields`。该值不是允许接入的 MSI 设备数量：
每核实际可用向量由平台 IRQ 路由、`VectorPool` 准入、设备数量和策略共同决定。
设备数量增长不会通过扩大 256 这个值解决，也不能把 256 个设备误当作硬件能力。

## TLB 击落批大小

`MAX_SHOOTDOWN_PAGES = 512` 是单公告板请求的批处理策略，来源登记为
`smp-shootdown-batch-policy`。范围更大时 `tlb_shootdown_on` 直接提升为一次
whole-table flush，而不是拒绝或截断请求。因此它不限制可撤销映射范围，只限制
单次逐页描述的规模。

负例和语义由既有 `SmpError::BadRange`、whole-table shootdown 单请求、
每目标单 IPI、完成/撤销测试以及 4-vCPU/8-vCPU 并发击落验收覆盖。

## 边界

- 普通 MSI 设备/中断数量仍必须由真实平台库存和资源预算准入；
- TLB 范围仍必须页对齐且无地址回绕；
- 本裁决不表示 CPU 动态拓扑、IRQ 路由或其他运行期容量已经完成。
