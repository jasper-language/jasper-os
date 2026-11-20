# ELF Image Page Admission

更新时间：2026-11-20。

状态：**loader 私有页容量已移除，页计划由调用方运行时预算准入。**

## 实现

- 删除 `MAX_IMAGE_PAGES=262_144` 的 1 GiB 固定计划上限。
- 删除 `MAX_PAGE_SIZE=64 KiB` 的隐性页大小默认上限；页大小仍必须是非零 2 的幂，
  且不能超过用户地址空间。
- `ImageLayout::new` 接收显式 `page_budget`，并在构造时和后续 `map_image` 复验时
  拒绝超过预算的页集合。
- `plan_dynamic_program` 对主程序与解释器共享一个总预算；解释器只取得主程序后
  剩余的部分。
- 内核装载入口的预算取进程剩余 `memory_account` 额度和当前空闲物理帧的较小值，
  不新增全局常量或第二套配额权威。

## 验证

```text
cargo test -p jasper-compat-loader
36 passed; caller_page_budget_bounds_layout_and_mutated_plans PASS

cargo check -p jasper-compat-loader --target x86_64-unknown-none
PASS

cargo check -p jasper-kernel --target x86_64-unknown-none
PASS

hardcode inventory
findings=310; runtime-resource-capacity=42; added=0
```

这些宿主测试证明布局拒绝和预算传递，不替代真实 UEFI Linux ELF 装载回归；完整
三架构验收仍由公开 CI 及后续 QEMU acceptance 提供。
