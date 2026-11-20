# Fscrypt Keyring Runtime Capacity

更新时间：2026-11-20。

状态：**固定 key/用户槽位已移除，keyring 由可失败堆准入决定。**

## 实现

- 删除 `MAX_KEYS=4` 与未单独计入的 `MAX_KEY_USERS=4`。
- key 条目由 `Vec<StoredKey>::try_reserve` 增长，每 key 的用户 claim 由
  `Vec<u32>::try_reserve` 增长；分配失败返回现有 `NoSpace`，不发布部分状态。
- 删除 key 时物理清零 master key；最后一个用户撤销后同时删除条目，否则保留 key
  并返回剩余用户语义。
- `MAX_KEY_BYTES=64` 保留为 fscrypt AES-XTS 主密钥格式/安全上限，不纳入本次
  运行期容量整改。

## 验证

使用真实 `kernel/src/fscrypt.rs` 与宿主 `SpinLock`/`kernel-core` 依赖构成的隔离
测试 harness：

```text
running 4 tests
test result: ok. 4 passed; 0 failed
```

其中 `keyring_and_user_claims_grow_past_former_slots` 创建一个 key 的 8 个用户
claim，再创建 6 个独立 key，并逐个验证派生和删除；旧固定 4/4 槽位下该测试不能
通过。

```text
cargo check -p jasper-kernel --target x86_64-unknown-none
PASS

hardcode inventory
findings=308; runtime-resource-capacity=41; added=0
```

隔离 harness 证明 keyring 状态机；完整 UEFI fscrypt/Android 文件生命周期仍由兼容层
产品验收覆盖。
