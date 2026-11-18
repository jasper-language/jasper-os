# LC-4 Android boot image / AVB firmware admission slice

更新时间：2026-11-18。

状态：**软件预检切片；LC-4 仍为 core-passed，真实设备矩阵未完成**。

`jasper-lifecycle-model::android_firmware` 使用 AOSP Android boot image v4 与
AVB vbmeta 的公开、大端固定布局，在只读字节上执行以下检查：

- 验证 `AVBf` footer、`AVB0` header、范围、版本和描述符边界；
- 验证已保护区域的 SHA-256/SHA-512、RSA PKCS#1 v1.5 签名和 AVB 公钥编码；
- 从完整 AVB 公钥编码派生 SHA-256 signer 指纹；
- 验证 `boot` 分区描述符的加盐内容摘要与原始镜像长度；
- 暴露 rollback index、algorithm、flags、分区内容摘要和 v4 kernel/ramdisk 布局。

这些事实不是 Jasper 授权根。生命周期服务仍须把 signer 指纹绑定到 Jasper 自己的
信任、撤销和 release floor 策略，再执行 Issue #39 的本地授权与技术准入双门禁。
AVB 通过不能替代 Driver Host、IOMMU、DMA/IRQ 静默、设备 generation 或真实
Pixel 安装验收。

## 真实 stock 文件验证

本机 Pixel 6a factory `boot.img` 的嵌入式 vbmeta 使用 SHA-256 + RSA-4096：

```text
avb-verify: PASS partition=boot version=4 kernel_size=16565921
  original_image_size=16588800 rollback_index=1764892800
```

`scripts/pixel6a-avb-check.sh` 还要求：

- 翻转 kernel 内容中的一个字节后，`boot` 描述符内容摘要必须失败；
- 用 `vendor_boot` 作为目标分区时，必须因缺少对应描述符失败；
- 只读取文件，不调用 fastboot，不刷写、擦除或切换 slot。

该切片不实现 AVB chain partition 的递归信任、公钥/rollback 分区持久化、
firmware hotplug、失败固件恢复或 Pixel 物理写入。完整 LC-4 退出条件仍未满足。
