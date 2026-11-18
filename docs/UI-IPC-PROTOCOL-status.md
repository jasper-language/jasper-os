# Jasper UI Service 原生 IPC 帧 v1

更新时间：2026-11-18。

状态：**版本化帧编解码与负例完成；Scene/Patch/Input/Present/Close 已绑定真实
Jasper Channel 与 CPL3 UI Service 三帧会话；分片、背压和重连仍未完成。**

## 边界

`kernel-core::ui_protocol` 只定义服务层消息，不登记 syscall、不包含指针地址或
设备/Vulkan 句柄。实际传输复用现有 Channel/AsyncRing；Handle/Rights、
MemoryObject 和完成事件仍由既有对象机制带外转移，不能藏进不透明载荷绕过授权。
原生 Channel 端点额外以 `MSG_BYTES - JSUI_HEADER_BYTES` 限制单帧载荷，避免
协议自身可表达但传输消息无法容纳的帧。

## 帧

- Magic `JSUI`，协议版本 1；
- 支持 `scene`、`patch`、`input`、`present`、`cancel`、`close`、`error` 七类；
- 固定 40 字节小端头：kind、flags、client slot+generation、request id、
  sequence、payload bytes；
- 单帧载荷 64 KiB，超过必须显式分片；`UI_FLAG_MORE` 表达后续片；
- 客户端 generation 使用 `UiClientKey`，关闭后旧帧不会绑定新客户端；
- request id 为 0、未知 flags/kind、非规范输入布尔、非零保留字节、截断或尾随
  数据全部拒绝；

## 验证

```text
cargo test -p kernel-core ui_protocol
4 passed; 0 failed

scripts/ui-process-check.sh
Scene receive=495 bytes
Present receive=16424 bytes (40-byte JSUI header + 16384 RGBA8 bytes)
Input receive=8 bytes canonical Enter
Versioned Patch advances the rendered background
Second Present receive=16424 bytes
PASS
```

覆盖七类帧往返、magic/version/header/reserved/kind/flags/client/request 篡改、
输入记录非规范布尔/保留字节、载荷超限以及截断/尾随数据。

## 尚未完成

- Engine `HostInbox` 的长时间/多事件持续会话 adapter；
- 真实 Surface/Scene 分片、背压、取消、重连和旧 generation 拒绝的镜像级测试；
- AsyncRing 服务提交与跨进程句柄转移的完整负例矩阵；
- 生产协议登记和跨版本兼容矩阵。不能把本模块的单元测试当作 UI-OS-1 完成。
