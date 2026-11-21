# Issue #42 M13：原生 File Event Service

更新时间：2026-11-21。

状态：**implemented-tested**。该服务只定义 Jasper 原生文件变更事件、cursor 和
rescan 语义；inotify/fanotify/FSEvents 的协议记录仍由兼容层解释。

## 实现

- `FileEventService<N>` 记录对象 ID、对象 generation、事件类型和单调 sequence。
- 事件在文件状态提交后发布；关闭后禁止继续发布。
- 调用方持有 `(instance, sequence)` cursor。同实例内只回放 cursor 之后的事件。
- 环形历史覆盖旧 sequence 时返回当前保留事件并标记 `resync=true`，禁止静默跳洞。
- 输出缓冲不足在复制前失败，不产生部分回放。
- 服务重启必须提升 instance 与 state generation；旧 cursor 失败关闭，调用者必须
  重新扫描权威文件状态并建立新 cursor。

## 验证

```text
cargo test -p kernel-core --lib file_event
4 passed; 0 failed
```

覆盖 cursor 后继回放、历史溢出 Resync、短输出失败原子、重启代际隔离和关闭终态。
