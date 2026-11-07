# FV-4 地址空间隔离与页帧生命周期验证

更新日期：2026-11-07。

## 工具裁决

FV-3 已正式给出 Verus no-go：完整 `HandleTable` 需要复制生产状态机，维护成本与收益不匹配。FV-4 沿用该结论，使用 **Kani/现有属性测试 + TLA+ 组合模型 + 真实多核 KVM**，不宣称生产 Rust 的 Verus 代码级证明。

## 组合模型

`verification/fv4_address_lifecycle.tla` 组合以下真实机制：

* 一个内存对象（SHM-1）的同一帧被两个进程别名映射；
* 两个别名分别撤映射，带页表代次；
* 每次撤映射要求目标处理器完成 TLB 击落应答；
* 内存对象销毁后，只有在最后别名消失、全部应答完成且不存在旧视图时才归还帧；
* 击落超时不得归还，帧进入隔离集合；
* 负例配置允许旧别名/旧 TLB 视图下释放，必须违反 `Safety`。

正例检查：

* `AliasesRetainFrame`：任一派生别名仍存在时帧不得归零；
* `MappedRequiresObject`：有映射即有内存对象；
* `ReleasedNoStaleView`：释放时所有相关核的视图不旧于释放代次；
* `FrameAccountedOnce`：帧只处于“可用或隔离”之一，不会双记。

当前工具结果：

* `fv4_address_lifecycle` 正例无 `Safety` 违例，允许旧视图释放的负例命中 `Safety`；
* 原 `tlb_shootdown`：2,116 生成 / 940 可达 / 深度 17，无错误；
* 原 `tlb_timeout_quarantine`：6 生成 / 6 可达 / 深度 4，无错误；
* `memory_object` 3 项、`memory_abi` 2 项宿主测试通过。

## 生产回归

FV-4 不新增生产 ABI。组合模型对应以下已有可执行证据：

* `memory_object` / `memory_abi`：别名映射、只读、非法范围与句柄生命周期；
* `tlb_shootdown` 与 `tlb_timeout_quarantine`：应答、超时和不可回收隔离；
* `M2.4`：独立地址空间隔离、内核共享、私有不外泄、销毁后页帧全回收；
* `HARDEN-1C`：多核用户指针固定与并发取消映射，无跨进程读写；
* `TLB-KRN0`：100,352 页跨核 map/写/并发读/unmap；
* `SHM-1` 用户生命周期与失败回滚；
* 完整 KVM 批次中的单核/4 核/8 核回归。

## 可信假设与边界

* 硬件遵守页表权限，TLB 必须由显式击落或上下文切换失效；
* 对象表、页表和 TLB 公告板的 Rust 锁在当前实现中串行化对应状态；
* 模型把单次本地页表修改和单核应答视为原子，不证明 Rust 弱内存、中断硬件投递或任意长公平性；
* 模型只覆盖一帧、两别名、两处理器；更多对象/页/核由生产压力测试覆盖，不把有限模型外推为全系统证明；
* Kani/属性工具链若未在当前环境运行，不把发版 harness 记作已运行；
* 本里程碑不声称硬件页表或 TLB 实现本身被形式化证明。

## 复现

```bash
bash verification/run-fv4-address-lifecycle-tlc.sh
bash verification/run-tlb-quarantine-tlc.sh
bash verification/run-tlc.sh
```
