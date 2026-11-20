# Issue #35 硬编码存量分类账

更新时间：2026-11-20。

状态：**全部 295 个基线命中已聚合为 272 个唯一指纹，并按消费者、规范或明确
安全策略完成首轮分类；`unclassified=0`。**

## 为什么不是 347 个 Bug

规则扫描只能指出“需要裁决的常量、平台名称或发现路径回退”。同一个数值可能是
协议字段宽度、安全解析上限、真实运行时预算、测试夹具或已确认缺陷。分类账要求
每个基线指纹具有唯一类别和非空理由，但不会把启发式类别自动升级为“已修复”。

分类由“路径 + 规则 + 完整规范化源码行”的 SHA-256 指纹绑定。当前 295 个命中聚合
为 272 个唯一指纹；相同源码行出现多次时保留 `count`。此前指纹解析在源码的类型
冒号处截断，曾把不同标识符但相同尾部类型的常量错误合并；修复后独立候选全部
重新分类，`unclassified=0`。

## 当前分类

| 类别 | 唯一指纹 | 基线命中 | 含义 |
| --- | ---: | ---: | --- |
| `explicit-safety-policy` | 139 | 144 | 有界工作、解析/等待上限、fail-closed 或诊断哨兵、明确策略默认 |
| `runtime-resource-capacity` | 56 | 58 | 运行期集合/容量，应由资源预算和准入决定 |
| `platform-adapter` | 28 | 44 | QEMU/Pixel 等架构特定选择，需保留显式 Profile 边界 |
| `protocol-abi` | 42 | 42 | Wire、FDT/PCI、Linux UAPI、磁盘格式、地址宽度或内部位域契约 |
| `confirmed-defect` | 0 | 0 | 当前分类账中尚无新增的已证实未修缺陷 |
| `test-demo-fixture` | 7 | 7 | 显式 benchmark、probe、capacity 或 PCI 模型夹具 |
| `unclassified` | 0 | 0 | 所有基线指纹均已有可核查理由 |

`confirmed-defect` 和 `unclassified` 同时为空不代表 Issue #35 全量完成。当前基线
已全部归类，但运行时容量、安全策略和平台矩阵仍需真实预算、负例和资源回收证据。

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
- 声明的唯一指纹计数、基线命中权重和逐项条目一致，权重总和必须等于 295；
- 当前源码扫描与 baseline 没有漂移。

修改生产代码清除条目后，应先用 `--write-inventory-baseline` 更新基线，再重新生成
分类账；禁止手工修改指纹或把未知项批量标为安全策略。

## 后续清零顺序

1. 先沿运行时消费者处理 56 个 `runtime-resource-capacity`，并补齐调用方预算和
   拒绝负例；
2. 将 139 个 `explicit-safety-policy` 逐项绑定到规范、策略或负例证据；
3. 把 28 个 `platform-adapter` 收敛到经验证的平台 Profile；
4. 审核 42 个协议条目和 7 个夹具，确认冻结边界不会泄漏到生产；
5. 只有调用链、负例和资源回收证据完整后才允许清除基线条目。
