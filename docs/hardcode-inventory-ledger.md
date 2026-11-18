# Issue #35 硬编码存量分类账

更新时间：2026-11-18。

状态：**全部 423 个基线命中已有且仅有一条可核查分类；139 个仍明确保持
`unclassified`。**

## 为什么不是 428 个 Bug

规则扫描只能指出“需要裁决的常量、平台名称或发现路径回退”。同一个数值可能是
协议字段宽度、安全解析上限、真实运行时预算、测试夹具或已确认缺陷。分类账要求
每个基线指纹具有唯一类别和非空理由，但不会把启发式类别自动升级为“已修复”。

分类由“路径 + 规则 + 规范化源码行”的 SHA-256 指纹绑定。当前 423 个命中聚合为
337 个唯一指纹；相同源码行出现多次时保留 `count`。

## 当前分类

| 类别 | 唯一指纹 | 基线命中 | 含义 |
| --- | ---: | ---: | --- |
| `explicit-safety-policy` | 96 | 101 | 解析器、批处理、地址或安全上限；仍需文档化消费链 |
| `runtime-resource-capacity` | 57 | 97 | 运行期集合/容量，应由资源预算和准入决定 |
| `platform-adapter` | 27 | 43 | QEMU/Pixel 等架构特定选择，需保留显式 Profile 边界 |
| `protocol-abi` | 18 | 21 | Wire、Loader、Package、Graphics 或 Lifecycle 协议候选 |
| `confirmed-defect` | 0 | 0 | 当前分类账中尚无新增的已证实未修缺陷 |
| `test-demo-fixture` | 0 | 0 | 扫描器已排除 test/demo 路径，当前无该类别 |
| `unclassified` | 139 | 161 | 尚无消费者级证据，保持开放，禁止据此豁免 |

`confirmed-defect` 为空不代表 Issue #35 全量完成；它表示本分类账没有把尚未完成
消费链审计的项目虚报为已证实缺陷。A08 等具体整改由独立切片处理。

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
- 声明的唯一指纹计数、基线命中权重和逐项条目一致，权重总和必须等于 423；
- 当前源码扫描与 baseline 没有漂移。

修改生产代码清除条目后，应先用 `--write-inventory-baseline` 更新基线，再重新生成
分类账；禁止手工修改指纹或把未知项批量标为安全策略。

## 后续清零顺序

1. 先沿运行时消费者处理 58 个 `runtime-resource-capacity`；
2. 将 98 个 `explicit-safety-policy` 逐项绑定到规范、策略或调用链证据；
3. 把 27 个 `platform-adapter` 收敛到经验证的平台 Profile；
4. 审核 18 个协议候选和剩余 139 个未知项；
5. 只有调用链、负例和资源回收证据完整后才新增 `confirmed-defect` 或降为零。
