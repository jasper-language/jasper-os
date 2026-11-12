//! ABI 世代契约快照：把可发布的二进制/语义契约与实现源码绑定。
//! ABI generation contract snapshots: bind released binary/semantic contracts to source.
//!
//! # 为什么需要
//! `abi-version.txt` 只声明版本号，`system-ids.lock` 只冻结部分名字/ID。两者都不能单独回答：
//! “这个主版本承诺了哪些参数布局、Rights、Ring 记录、取消/完成语义？”本模块把当前源码中的
//! 这些契约渲染成确定性的行式快照；发布门槛要求每个 ABI 版本都有独立快照，并要求同主版本
//! 的新快照只增加条目、不删除或修改旧条目。
//!
//! # 边界
//! 这是**契约导出与机械比较**，不是 ELF/设备/调度器实现本身的证明。每个布局记录引用源码里
//! 的权威常量；部署到另一地址空间所需的 IPC/权限/取消/故障语义在 [`SEMANTICS`] 中显式登记。
//! 快照不分配内存，可在构建脚本、宿主工具和测试中复用。

use core::fmt;

use crate::abi::{self, AbiError, AbiLine};
use crate::abi_version::AbiVersion;
use crate::device;
use crate::extension_abi;
use crate::memory_abi;
use crate::ring_abi;
use crate::rt_abi;
use crate::spawn_abi;
use crate::subscription_abi;
use crate::syscall_set;

/// 快照文件格式版本。格式变化本身必须升级主 ABI 或显式迁移工具。
pub const SNAPSHOT_FORMAT: u32 = 1;

/// 一个定长布局字段的线上偏移与宽度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutField {
    /// 字段名。
    pub name: &'static str,
    /// 相对记录起点的字节偏移。
    pub offset: u16,
    /// 字段宽度（字节）。
    pub width: u16,
}

/// 一个用户与内核共享的定长布局。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutContract {
    /// 稳定布局名。
    pub name: &'static str,
    /// 布局自身的线上版本。
    pub version: u32,
    /// 记录总字节数。
    pub size: u32,
    /// 可选 magic；0 表示没有 magic。
    pub magic: u32,
    /// 字段偏移表。
    pub fields: &'static [LayoutField],
}

/// 一个可调用操作的寄存器级参数与返回约定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationContract {
    /// 与 `abi/system-ids.txt` 相同的规范名。
    pub name: &'static str,
    /// 从 `args[0]` 起使用的参数形状；`-` 表示不使用参数。
    pub args: &'static str,
    /// 标量返回值或终态类别。
    pub result: &'static str,
}

const PROGRAM_NOTE_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "namesz",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "descsz",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "type",
        offset: 8,
        width: 4,
    },
    LayoutField {
        name: "name",
        offset: 12,
        width: 8,
    },
    LayoutField {
        name: "major",
        offset: 20,
        width: 2,
    },
    LayoutField {
        name: "min_minor",
        offset: 22,
        width: 2,
    },
    LayoutField {
        name: "patch",
        offset: 24,
        width: 2,
    },
    LayoutField {
        name: "flags",
        offset: 26,
        width: 2,
    },
];
const SQE_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "op",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "flags",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "user_tag",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "arg0",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "arg1",
        offset: 24,
        width: 8,
    },
];
const CQE_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "request_id",
        offset: 0,
        width: 8,
    },
    LayoutField {
        name: "user_tag",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "op",
        offset: 16,
        width: 4,
    },
    LayoutField {
        name: "reserved",
        offset: 20,
        width: 4,
    },
    LayoutField {
        name: "result",
        offset: 24,
        width: 8,
    },
];
const ENTER_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "sq_ptr",
        offset: 0,
        width: 8,
    },
    LayoutField {
        name: "cq_ptr",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "id_ptr",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "sq_count",
        offset: 24,
        width: 4,
    },
    LayoutField {
        name: "cq_max",
        offset: 28,
        width: 4,
    },
    LayoutField {
        name: "wait_min",
        offset: 32,
        width: 4,
    },
    LayoutField {
        name: "reserved",
        offset: 36,
        width: 4,
    },
    LayoutField {
        name: "submitted",
        offset: 40,
        width: 4,
    },
    LayoutField {
        name: "reaped",
        offset: 44,
        width: 4,
    },
    LayoutField {
        name: "first_error",
        offset: 48,
        width: 8,
    },
];
const ENTER_UNTIL_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "bytes",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "deadline",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "enter",
        offset: 16,
        width: ring_abi::ENTER_ARGS_SIZE as u16,
    },
];
const MSG_DESC_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "data_ptr",
        offset: 0,
        width: 8,
    },
    LayoutField {
        name: "handles_ptr",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "data_len",
        offset: 16,
        width: 4,
    },
    LayoutField {
        name: "handles_cap",
        offset: 20,
        width: 4,
    },
    LayoutField {
        name: "out_data_len",
        offset: 24,
        width: 4,
    },
    LayoutField {
        name: "out_handles",
        offset: 28,
        width: 4,
    },
    LayoutField {
        name: "out_sender",
        offset: 32,
        width: 4,
    },
    LayoutField {
        name: "out_sender_app",
        offset: 36,
        width: 4,
    },
];
const SPAWN_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "magic",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "version",
        offset: 4,
        width: 2,
    },
    LayoutField {
        name: "size",
        offset: 6,
        width: 2,
    },
    LayoutField {
        name: "image_ptr",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "image_len",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "calls",
        offset: 24,
        width: syscall_set::BYTES as u16,
    },
    LayoutField {
        name: "arg",
        offset: 56,
        width: 8,
    },
    LayoutField {
        name: "cpu_limit_permille",
        offset: 64,
        width: 4,
    },
    LayoutField {
        name: "flags",
        offset: 68,
        width: 4,
    },
    LayoutField {
        name: "out_process",
        offset: 72,
        width: 8,
    },
    LayoutField {
        name: "out_channel",
        offset: 80,
        width: 8,
    },
];
const MEMORY_MAP_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "bytes",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "address",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "offset_pages",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "pages",
        offset: 24,
        width: 8,
    },
    LayoutField {
        name: "flags",
        offset: 32,
        width: 4,
    },
    LayoutField {
        name: "reserved",
        offset: 36,
        width: 4,
    },
];
const RT_SET_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "bytes",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "quota",
        offset: 8,
        width: 4,
    },
    LayoutField {
        name: "period",
        offset: 12,
        width: 4,
    },
    LayoutField {
        name: "target",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "reserved",
        offset: 24,
        width: 8,
    },
];
const RT_AFFINITY_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "bytes",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "target",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "cpus",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "reserved",
        offset: 24,
        width: 8,
    },
];
const RT_NS_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "bytes",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "quota_ns",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "period_ns",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "target",
        offset: 24,
        width: 8,
    },
    LayoutField {
        name: "reserved",
        offset: 32,
        width: 8,
    },
];
const SUB_WAIT_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 2,
    },
    LayoutField {
        name: "bytes",
        offset: 2,
        width: 2,
    },
    LayoutField {
        name: "capacity",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "ptr",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "reserved",
        offset: 16,
        width: 8,
    },
];
const SUB_RECORD_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "kind",
        offset: 0,
        width: 8,
    },
    LayoutField {
        name: "first",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "last",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "value",
        offset: 24,
        width: 8,
    },
];
const SUB_SOURCE_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 2,
    },
    LayoutField {
        name: "bytes",
        offset: 2,
        width: 2,
    },
    LayoutField {
        name: "kind",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "target",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "reserved",
        offset: 16,
        width: 8,
    },
];
const SUB_CREATE_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 2,
    },
    LayoutField {
        name: "bytes",
        offset: 2,
        width: 2,
    },
    LayoutField {
        name: "policy",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "record_bytes",
        offset: 8,
        width: 4,
    },
    LayoutField {
        name: "reserved",
        offset: 12,
        width: 4,
    },
    LayoutField {
        name: "reserved_tail",
        offset: 16,
        width: 16,
    },
];
const EXT_HEADER_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "bytes",
        offset: 4,
        width: 4,
    },
];
const EXT_SEGMENT_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "source_kind",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "flags",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "source",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "offset",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "length",
        offset: 24,
        width: 8,
    },
];
const EXT_SERVICE_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "protocol",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "version",
        offset: 4,
        width: 2,
    },
    LayoutField {
        name: "bytes",
        offset: 6,
        width: 2,
    },
];
const EXT_SET_V2_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "bytes",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "words",
        offset: 8,
        width: 32,
    },
];
const EXT_BORROW_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "bytes",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "memory",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "offset",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "length",
        offset: 24,
        width: 8,
    },
    LayoutField {
        name: "request",
        offset: 32,
        width: 8,
    },
    LayoutField {
        name: "reserved",
        offset: 40,
        width: 8,
    },
];
const EXT_CONTROL_FIELDS: &[LayoutField] = &[
    LayoutField {
        name: "version",
        offset: 0,
        width: 4,
    },
    LayoutField {
        name: "bytes",
        offset: 4,
        width: 4,
    },
    LayoutField {
        name: "subject",
        offset: 8,
        width: 8,
    },
    LayoutField {
        name: "payload",
        offset: 16,
        width: 8,
    },
    LayoutField {
        name: "reserved",
        offset: 24,
        width: 8,
    },
];

/// 当前 ABI 的定长布局契约。新增/改变布局必须随 ABI 发版产生新快照。
pub const LAYOUTS: &[LayoutContract] = &[
    LayoutContract {
        name: "program.note",
        version: 1,
        size: crate::abi_version::NOTE_BYTES as u32,
        magic: 0,
        fields: PROGRAM_NOTE_FIELDS,
    },
    LayoutContract {
        name: "program.caps_note",
        version: 1,
        size: crate::program_caps::CAPS_NOTE_MAX_BYTES as u32,
        magic: 0,
        fields: &[
            LayoutField {
                name: "namesz",
                offset: 0,
                width: 4,
            },
            LayoutField {
                name: "descsz",
                offset: 4,
                width: 4,
            },
            LayoutField {
                name: "type",
                offset: 8,
                width: 4,
            },
            LayoutField {
                name: "name",
                offset: 12,
                width: 8,
            },
            LayoutField {
                name: "version",
                offset: 20,
                width: 2,
            },
            LayoutField {
                name: "flags",
                offset: 22,
                width: 2,
            },
            LayoutField {
                name: "count",
                offset: 24,
                width: 2,
            },
            LayoutField {
                name: "reserved",
                offset: 26,
                width: 2,
            },
            LayoutField {
                name: "names",
                offset: 28,
                width: 64,
            },
        ],
    },
    LayoutContract {
        name: "syscall.set.v1",
        version: 1,
        size: syscall_set::BYTES as u32,
        magic: 0,
        fields: &[LayoutField {
            name: "words",
            offset: 0,
            width: syscall_set::BYTES as u16,
        }],
    },
    LayoutContract {
        name: "syscall.set.v2",
        version: 2,
        size: extension_abi::SYSCALL_SET_V2_BYTES as u32,
        magic: 0,
        fields: EXT_SET_V2_FIELDS,
    },
    LayoutContract {
        name: "ring.sqe",
        version: 1,
        size: ring_abi::SQE_SIZE as u32,
        magic: 0,
        fields: SQE_FIELDS,
    },
    LayoutContract {
        name: "ring.cqe",
        version: 1,
        size: ring_abi::CQE_SIZE as u32,
        magic: 0,
        fields: CQE_FIELDS,
    },
    LayoutContract {
        name: "ring.enter",
        version: 1,
        size: ring_abi::ENTER_ARGS_SIZE as u32,
        magic: 0,
        fields: ENTER_FIELDS,
    },
    LayoutContract {
        name: "ring.enter_until",
        version: 1,
        size: ring_abi::ENTER_UNTIL_SIZE as u32,
        magic: 0,
        fields: ENTER_UNTIL_FIELDS,
    },
    LayoutContract {
        name: "ring.msg_desc",
        version: 1,
        size: ring_abi::MSG_DESC_SIZE as u32,
        magic: 0,
        fields: MSG_DESC_FIELDS,
    },
    LayoutContract {
        name: "spawn.desc",
        version: spawn_abi::SPAWN_DESC_VERSION as u32,
        size: spawn_abi::SPAWN_DESC_SIZE as u32,
        magic: spawn_abi::SPAWN_DESC_MAGIC,
        fields: SPAWN_FIELDS,
    },
    LayoutContract {
        name: "memory.map_args",
        version: memory_abi::VERSION,
        size: memory_abi::MAP_ARGS_BYTES as u32,
        magic: 0,
        fields: MEMORY_MAP_FIELDS,
    },
    LayoutContract {
        name: "rt.set_args",
        version: rt_abi::VERSION,
        size: rt_abi::BYTES as u32,
        magic: 0,
        fields: RT_SET_FIELDS,
    },
    LayoutContract {
        name: "rt.affinity_args",
        version: rt_abi::VERSION,
        size: rt_abi::BYTES as u32,
        magic: 0,
        fields: RT_AFFINITY_FIELDS,
    },
    LayoutContract {
        name: "rt.set_ns_args",
        version: 1,
        size: rt_abi::SetNsArgs::BYTES as u32,
        magic: 0,
        fields: RT_NS_FIELDS,
    },
    LayoutContract {
        name: "subscription.wait_args",
        version: 1,
        size: subscription_abi::WAIT_BYTES as u32,
        magic: 0,
        fields: SUB_WAIT_FIELDS,
    },
    LayoutContract {
        name: "subscription.record",
        version: 1,
        size: subscription_abi::RECORD_BYTES as u32,
        magic: 0,
        fields: SUB_RECORD_FIELDS,
    },
    LayoutContract {
        name: "subscription.source_args",
        version: 1,
        size: subscription_abi::SOURCE_BYTES as u32,
        magic: 0,
        fields: SUB_SOURCE_FIELDS,
    },
    LayoutContract {
        name: "subscription.create_args",
        version: 1,
        size: subscription_abi::SUBSCRIBE_BYTES as u32,
        magic: 0,
        fields: SUB_CREATE_FIELDS,
    },
    LayoutContract {
        name: "extension.header",
        version: extension_abi::VERSION,
        size: extension_abi::HEADER_BYTES as u32,
        magic: 0,
        fields: EXT_HEADER_FIELDS,
    },
    LayoutContract {
        name: "extension.segment",
        version: 1,
        size: extension_abi::SEGMENT_BYTES as u32,
        magic: 0,
        fields: EXT_SEGMENT_FIELDS,
    },
    LayoutContract {
        name: "extension.service_header",
        version: 1,
        size: extension_abi::SERVICE_HEADER_BYTES as u32,
        magic: 0,
        fields: EXT_SERVICE_FIELDS,
    },
    LayoutContract {
        name: "extension.borrow",
        version: 1,
        size: extension_abi::BORROW_BYTES as u32,
        magic: 0,
        fields: EXT_BORROW_FIELDS,
    },
    LayoutContract {
        name: "extension.control",
        version: 1,
        size: extension_abi::CONTROL_BYTES as u32,
        magic: 0,
        fields: EXT_CONTROL_FIELDS,
    },
    LayoutContract {
        name: "device.record",
        version: 1,
        size: device::RECORD_SIZE as u32,
        magic: 0,
        fields: &[LayoutField {
            name: "record",
            offset: 0,
            width: device::RECORD_SIZE as u16,
        }],
    },
    LayoutContract {
        name: "device.description",
        version: 1,
        size: device::DESC_SIZE as u32,
        magic: 0,
        fields: &[LayoutField {
            name: "description",
            offset: 0,
            width: device::DESC_SIZE as u16,
        }],
    },
    LayoutContract {
        name: "device.capability_record",
        version: 1,
        size: device::CAP_RECORD_SIZE as u32,
        magic: 0,
        fields: &[LayoutField {
            name: "record",
            offset: 0,
            width: device::CAP_RECORD_SIZE as u16,
        }],
    },
    LayoutContract {
        name: "workload.create_args",
        version: 1,
        size: 40,
        magic: crate::workload_abi::MAGIC,
        fields: &[
            LayoutField {
                name: "parent",
                offset: 8,
                width: 8,
            },
            LayoutField {
                name: "cpu_permille",
                offset: 16,
                width: 4,
            },
            LayoutField {
                name: "threads",
                offset: 20,
                width: 4,
            },
            LayoutField {
                name: "memory_bytes",
                offset: 24,
                width: 8,
            },
            LayoutField {
                name: "ring_entries",
                offset: 32,
                width: 4,
            },
        ],
    },
    LayoutContract {
        name: "workload.create_args",
        version: crate::workload_abi::VERSION as u32,
        size: crate::workload_abi::CREATE_BYTES as u32,
        magic: crate::workload_abi::MAGIC,
        fields: &[
            LayoutField {
                name: "parent",
                offset: 8,
                width: 8,
            },
            LayoutField {
                name: "cpu_permille",
                offset: 16,
                width: 4,
            },
            LayoutField {
                name: "threads",
                offset: 20,
                width: 4,
            },
            LayoutField {
                name: "memory_bytes",
                offset: 24,
                width: 8,
            },
            LayoutField {
                name: "ring_entries",
                offset: 32,
                width: 4,
            },
            LayoutField {
                name: "io_bytes",
                offset: 40,
                width: 8,
            },
            LayoutField {
                name: "io_ops",
                offset: 48,
                width: 8,
            },
        ],
    },
    LayoutContract {
        name: "workload.info",
        version: 1,
        size: 64,
        magic: crate::workload_abi::MAGIC,
        fields: &[
            LayoutField {
                name: "state",
                offset: 6,
                width: 1,
            },
            LayoutField {
                name: "key",
                offset: 8,
                width: 8,
            },
            LayoutField {
                name: "parent",
                offset: 16,
                width: 8,
            },
            LayoutField {
                name: "limits",
                offset: 24,
                width: 20,
            },
            LayoutField {
                name: "children",
                offset: 44,
                width: 4,
            },
            LayoutField {
                name: "usage",
                offset: 48,
                width: 16,
            },
        ],
    },
    LayoutContract {
        name: "workload.info",
        version: crate::workload_abi::VERSION as u32,
        size: crate::workload_abi::INFO_BYTES as u32,
        magic: crate::workload_abi::MAGIC,
        fields: &[
            LayoutField {
                name: "state",
                offset: 6,
                width: 1,
            },
            LayoutField {
                name: "key",
                offset: 8,
                width: 8,
            },
            LayoutField {
                name: "parent",
                offset: 16,
                width: 8,
            },
            LayoutField {
                name: "limits",
                offset: 24,
                width: 20,
            },
            LayoutField {
                name: "children",
                offset: 44,
                width: 4,
            },
            LayoutField {
                name: "usage",
                offset: 48,
                width: 16,
            },
            LayoutField {
                name: "io_limits",
                offset: 64,
                width: 16,
            },
            LayoutField {
                name: "io_usage",
                offset: 80,
                width: 16,
            },
        ],
    },
    LayoutContract {
        name: "sandbox.info",
        version: crate::sandbox_abi::VERSION as u32,
        size: crate::sandbox_abi::INFO_BYTES as u32,
        magic: crate::sandbox_abi::MAGIC,
        fields: &[
            LayoutField {
                name: "state",
                offset: 6,
                width: 1,
            },
            LayoutField {
                name: "key",
                offset: 8,
                width: 8,
            },
        ],
    },
    LayoutContract {
        name: "sandbox.image.add_args",
        version: crate::sandbox_storage_abi::VERSION as u32,
        size: crate::sandbox_storage_abi::IMAGE_ADD_BYTES as u32,
        magic: crate::sandbox_storage_abi::IMAGE_MAGIC,
        fields: &[
            LayoutField {
                name: "sandbox",
                offset: 8,
                width: 8,
            },
            LayoutField {
                name: "content",
                offset: 16,
                width: 32,
            },
            LayoutField {
                name: "signer",
                offset: 48,
                width: 8,
            },
            LayoutField {
                name: "signature",
                offset: 56,
                width: 32,
            },
            LayoutField {
                name: "image_version",
                offset: 88,
                width: 6,
            },
            LayoutField {
                name: "rootfs_bytes",
                offset: 96,
                width: 8,
            },
            LayoutField {
                name: "writable_bytes",
                offset: 104,
                width: 8,
            },
            LayoutField {
                name: "max_volumes",
                offset: 112,
                width: 2,
            },
            LayoutField {
                name: "layer_count",
                offset: 114,
                width: 2,
            },
        ],
    },
    LayoutContract {
        name: "sandbox.image.info",
        version: crate::sandbox_storage_abi::VERSION as u32,
        size: crate::sandbox_storage_abi::IMAGE_INFO_BYTES as u32,
        magic: crate::sandbox_storage_abi::IMAGE_MAGIC,
        fields: &[
            LayoutField {
                name: "image_key",
                offset: 8,
                width: 8,
            },
            LayoutField {
                name: "content",
                offset: 16,
                width: 32,
            },
            LayoutField {
                name: "signer",
                offset: 48,
                width: 8,
            },
            LayoutField {
                name: "signature",
                offset: 56,
                width: 32,
            },
            LayoutField {
                name: "image_version",
                offset: 88,
                width: 6,
            },
            LayoutField {
                name: "rootfs_bytes",
                offset: 96,
                width: 8,
            },
            LayoutField {
                name: "writable_bytes",
                offset: 104,
                width: 8,
            },
            LayoutField {
                name: "max_volumes",
                offset: 112,
                width: 2,
            },
            LayoutField {
                name: "volumes",
                offset: 114,
                width: 2,
            },
            LayoutField {
                name: "layers",
                offset: 116,
                width: 2,
            },
        ],
    },
    LayoutContract {
        name: "sandbox.image.layer_info",
        version: crate::sandbox_storage_abi::VERSION as u32,
        size: crate::sandbox_storage_abi::LAYER_INFO_BYTES as u32,
        magic: crate::sandbox_storage_abi::IMAGE_MAGIC,
        fields: &[
            LayoutField {
                name: "content",
                offset: 8,
                width: 32,
            },
            LayoutField {
                name: "bytes",
                offset: 40,
                width: 8,
            },
        ],
    },
    LayoutContract {
        name: "sandbox.volume.create_args",
        version: crate::sandbox_storage_abi::VERSION as u32,
        size: crate::sandbox_storage_abi::VOLUME_CREATE_BYTES as u32,
        magic: crate::sandbox_storage_abi::VOLUME_MAGIC,
        fields: &[
            LayoutField {
                name: "sandbox",
                offset: 8,
                width: 8,
            },
            LayoutField {
                name: "image",
                offset: 16,
                width: 8,
            },
            LayoutField {
                name: "capacity_bytes",
                offset: 24,
                width: 8,
            },
        ],
    },
    LayoutContract {
        name: "sandbox.volume.clone_args",
        version: crate::sandbox_storage_abi::VERSION as u32,
        size: crate::sandbox_storage_abi::VOLUME_CREATE_BYTES as u32,
        magic: crate::sandbox_storage_abi::VOLUME_MAGIC,
        fields: &[
            LayoutField {
                name: "sandbox",
                offset: 8,
                width: 8,
            },
            LayoutField {
                name: "parent",
                offset: 16,
                width: 8,
            },
            LayoutField {
                name: "capacity_bytes",
                offset: 24,
                width: 8,
            },
        ],
    },
    LayoutContract {
        name: "sandbox.volume.info",
        version: crate::sandbox_storage_abi::VERSION as u32,
        size: crate::sandbox_storage_abi::VOLUME_INFO_BYTES as u32,
        magic: crate::sandbox_storage_abi::VOLUME_MAGIC,
        fields: &[
            LayoutField {
                name: "volume_key",
                offset: 8,
                width: 8,
            },
            LayoutField {
                name: "image",
                offset: 16,
                width: 8,
            },
            LayoutField {
                name: "parent",
                offset: 24,
                width: 8,
            },
            LayoutField {
                name: "capacity_bytes",
                offset: 32,
                width: 8,
            },
            LayoutField {
                name: "used_bytes",
                offset: 40,
                width: 8,
            },
        ],
    },
];

/// 可调用操作的逐个寄存器契约。名字必须与 `abi/system-ids.txt` 的操作集合完全相等。
pub const OPERATIONS: &[OperationContract] = &[
    OperationContract {
        name: "system.task.exit",
        args: "i64:code",
        result: "does_not_return",
    },
    OperationContract {
        name: "system.task.yield",
        args: "-",
        result: "0",
    },
    OperationContract {
        name: "system.time.now",
        args: "-",
        result: "u64:tick",
    },
    OperationContract {
        name: "system.console.write",
        args: "u64:user_ptr,u64:len",
        result: "i64:bytes_or_error",
    },
    OperationContract {
        name: "system.task.spawn",
        args: "u64:entry,u64:stack,u64:arg",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.handle.close",
        args: "handle",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.handle.duplicate",
        args: "handle,u32:rights",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.handle.restrict",
        args: "handle,u32:rights",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.async.ring.create",
        args: "u32:capacity",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.async.ring.enter",
        args: "ring_handle,u64:enter_args_ptr",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.async.cancel",
        args: "ring_handle,u64:request_id",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.time.wait",
        args: "u64:ticks",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.channel.create",
        args: "u64:two_handle_out_ptr",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.channel.send",
        args: "endpoint_handle,u64:msg_desc_ptr",
        result: "terminal_result_or_error",
    },
    OperationContract {
        name: "system.channel.recv",
        args: "endpoint_handle,u64:msg_desc_ptr",
        result: "terminal_result_or_error",
    },
    OperationContract {
        name: "system.process.exit",
        args: "i64:code",
        result: "does_not_return",
    },
    OperationContract {
        name: "system.task.wait",
        args: "task_handle",
        result: "terminal_result_or_error",
    },
    OperationContract {
        name: "system.process.wait",
        args: "process_handle",
        result: "terminal_result_or_error",
    },
    OperationContract {
        name: "system.memory.map",
        args: "u64:va,u64:pages,u32:flags",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.memory.unmap",
        args: "u64:va,u64:pages",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.memory.protect",
        args: "u64:va,u64:pages,u32:flags",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.task.qos.set",
        args: "u32:qos",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.process.spawn",
        args: "u64:spawn_desc_ptr",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.profile.list",
        args: "-",
        result: "count",
    },
    OperationContract {
        name: "system.profile.get",
        args: "u64:index,u64:buf,u64:cap",
        result: "i64:bytes_or_error",
    },
    OperationContract {
        name: "system.device.list",
        args: "u32:filter,u64:buf,u64:cap",
        result: "i64:required_or_written",
    },
    OperationContract {
        name: "system.device.open",
        args: "u32:bdf,u32:rights",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.device.get",
        args: "device_handle,u64:buf,u64:cap",
        result: "i64:bytes_or_error",
    },
    OperationContract {
        name: "system.device.map",
        args: "device_handle,u32:bar,u64:va",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.device.capability.list",
        args: "device_handle,u64:buf,u64:cap",
        result: "i64:required_or_written",
    },
    OperationContract {
        name: "system.device.interrupt.create",
        args: "device_handle,u32:entry,u32:cpu",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.device.interrupt.wait",
        args: "interrupt_handle",
        result: "ring_only",
    },
    OperationContract {
        name: "system.async.ring.deadline.enter",
        args: "ring_handle,u64:enter_until_args_ptr",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.memory.object.create",
        args: "u64:pages",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.memory.object.map",
        args: "memory_handle,u64:map_args_ptr",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.memory.object.unmap",
        args: "u64:va,u64:pages",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.memory.buffer.create",
        args: "reserved",
        result: "unsupported",
    },
    OperationContract {
        name: "system.memory.buffer.destroy",
        args: "reserved",
        result: "unsupported",
    },
    OperationContract {
        name: "system.execution.restricted.create",
        args: "reserved",
        result: "unsupported",
    },
    OperationContract {
        name: "system.task.interrupt.send",
        args: "reserved",
        result: "unsupported",
    },
    OperationContract {
        name: "system.memory.dma.map",
        args: "memory_handle,u64:dma_map_args_ptr",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.io.segment.submit",
        args: "reserved",
        result: "unsupported",
    },
    OperationContract {
        name: "system.task.syscalls.set",
        args: "task_handle,u64:calls_set_ptr,u64:flags",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.event.subscription.wait",
        args: "reserved",
        result: "unsupported",
    },
    OperationContract {
        name: "system.event.source.create",
        args: "u64:source_args_ptr",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.event.subscription.create",
        args: "source_handle,u64:create_args_ptr",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.task.rt.set",
        args: "u64:rt_set_args_ptr",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.task.affinity.set",
        args: "u64:affinity_args_ptr",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.task.affinity.get",
        args: "task_handle",
        result: "u32:cpu_mask_or_error",
    },
    OperationContract {
        name: "system.task.rt.deadline.set",
        args: "u64:rt_set_ns_args_ptr",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.time.deadline.get",
        args: "-",
        result: "i64:monotonic_ns_or_error",
    },
    OperationContract {
        name: "system.time.deadline.wait",
        args: "u64:absolute_deadline_ns",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.sync.mutex.create",
        args: "-",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.sync.mutex.acquire",
        args: "mutex_handle",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.sync.mutex.release",
        args: "mutex_handle",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.abi.get",
        args: "-",
        result: "packed_abi_version",
    },
    OperationContract {
        name: "system.sync.mutex.try.acquire",
        args: "mutex_handle",
        result: "0_or_busy",
    },
    OperationContract {
        name: "system.time.timer.create",
        args: "u64:period_ns,u64:slack_ns,u64:flags",
        result: "handle_or_error",
    },
    OperationContract {
        name: "system.time.timer.arm",
        args: "timer_handle,u64:when_ns,u64:flags",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.time.timer.cancel",
        args: "timer_handle",
        result: "1_if_armed_else_0_or_error",
    },
    OperationContract {
        name: "system.time.timer.wait",
        args: "timer_handle",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.time.timer.get",
        args: "timer_handle",
        result: "u64:remaining_ns_or_error",
    },
    OperationContract {
        name: "system.info.get",
        args: "u64:request_id,u64:buf,u64:cap",
        result: "bytes_or_required",
    },
    OperationContract {
        name: "system.process.list",
        args: "u64:request_id,u64:buf,u64:cap",
        result: "bytes_or_required",
    },
    OperationContract {
        name: "system.module.list",
        args: "u64:request_id,u64:buf,u64:cap",
        result: "bytes_or_required",
    },
    OperationContract {
        name: "system.module.lifecycle.get",
        args: "u64:request_id,u64:buf,u64:cap",
        result: "bytes_or_required",
    },
    OperationContract {
        name: "system.workload.create",
        args: "u64:create_desc_ptr",
        result: "workload_key_or_error",
    },
    OperationContract {
        name: "system.workload.query",
        args: "u64:workload_key,u64:buf,u64:cap",
        result: "i64:bytes_or_error",
    },
    OperationContract {
        name: "system.workload.stop",
        args: "u64:workload_key",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.workload.destroy",
        args: "u64:workload_key",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.workload.spawn",
        args: "u64:workload_key,u64:spawn_desc_ptr",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.workload.kill",
        args: "u64:workload_key",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.workload.member.query",
        args: "u64:workload_key",
        result: "i64:member_count_or_error",
    },
    OperationContract {
        name: "system.sandbox.create",
        args: "u64:workload_create_desc_ptr",
        result: "sandbox_key_or_error",
    },
    OperationContract {
        name: "system.sandbox.query",
        args: "u64:sandbox_key,u64:buf,u64:cap",
        result: "i64:bytes_or_error",
    },
    OperationContract {
        name: "system.sandbox.stop",
        args: "u64:sandbox_key",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.sandbox.destroy",
        args: "u64:sandbox_key",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.sandbox.image.load",
        args: "u64:image_add_desc_ptr",
        result: "image_key_or_error",
    },
    OperationContract {
        name: "system.sandbox.image.query",
        args: "u64:sandbox_key,u64:image_key,u64:buf,u64:cap",
        result: "i64:bytes_or_error",
    },
    OperationContract {
        name: "system.sandbox.image.layer.query",
        args: "u64:sandbox_key,u64:image_key,u64:index,u64:buf,u64:cap",
        result: "i64:bytes_or_error",
    },
    OperationContract {
        name: "system.sandbox.image.destroy",
        args: "u64:sandbox_key,u64:image_key",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.sandbox.volume.create",
        args: "u64:volume_create_desc_ptr",
        result: "volume_key_or_error",
    },
    OperationContract {
        name: "system.sandbox.volume.duplicate",
        args: "u64:volume_clone_desc_ptr",
        result: "volume_key_or_error",
    },
    OperationContract {
        name: "system.sandbox.volume.query",
        args: "u64:sandbox_key,u64:volume_key,u64:buf,u64:cap",
        result: "i64:bytes_or_error",
    },
    OperationContract {
        name: "system.sandbox.volume.write",
        args: "u64:sandbox_key,u64:volume_key,u64:bytes",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.sandbox.volume.release",
        args: "u64:sandbox_key,u64:volume_key,u64:bytes",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.sandbox.volume.destroy",
        args: "u64:sandbox_key,u64:volume_key",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.sandbox.wait",
        args: "u64:sandbox_key,u64:timeout_ns",
        result: "0_or_error",
    },
    OperationContract {
        name: "system.sandbox.kill",
        args: "u64:sandbox_key",
        result: "0_or_error",
    },
];

/// Rights 位是外部 ABI；位值变化必须产生新快照并随 ABI 版本裁决。
pub const RIGHTS: &[(&str, u32)] = &[
    ("READ", 1 << 0),
    ("WRITE", 1 << 1),
    ("EXECUTE", 1 << 2),
    ("WAIT", 1 << 3),
    ("CONTROL", 1 << 4),
    ("DUPLICATE", 1 << 5),
    ("TRANSFER", 1 << 6),
    ("MAP", 1 << 7),
    ("SUBSCRIBE", 1 << 8),
];

/// 无法由结构体字节数单独表达的稳定语义。值变化会改变契约快照。
pub const SEMANTICS: &[(&str, &str)] = &[
    (
        "abi.same_major",
        "program.major==kernel.major and program.min_minor<=kernel.minor",
    ),
    (
        "abi.cross_major",
        "reject_before_user_mapping_and_execution",
    ),
    ("abi.patch", "recorded_not_a_feature_gate"),
    (
        "abi.program_stamp",
        "ELF.note.jasper.abi;exact_28_bytes;unknown_flags_rejected",
    ),
    (
        "abi.program_capabilities",
        "ELF.note.jasper.caps;version_1;nul_names;max_24;duplicates_rejected;missing_note_means_empty",
    ),
    (
        "abi.capability_gate",
        "all_required_capabilities_published_by_active_profile_before_any_mapping",
    ),
    (
        "syscall.arguments",
        "id_register_plus_six_u64_registers;little_endian_descriptors",
    ),
    (
        "syscall.result",
        "nonnegative_success;negative_is_negated_error_id",
    ),
    (
        "syscall.authorization",
        "registered_callset_then_service_gate_then_handler",
    ),
    (
        "handle.value",
        "32_bit_slot_plus_32_bit_generation;stale_generation_rejected",
    ),
    (
        "object.rights",
        "monotonic_reduction_only;no_grant_escalation",
    ),
    ("async.request_terminal", "at_most_one_terminal_decision"),
    (
        "async.completion",
        "release_backend_before_publish;result_negative_is_negated_error_id",
    ),
    (
        "async.cancel",
        "cancelled_operation_returns_cancelled_terminal;delivered_operation_wins_by_linearization",
    ),
    (
        "async.close",
        "close_rejects_new_submissions_and_preserves_inflight_terminal_semantics",
    ),
    (
        "spawn.calls",
        "child_callset_subset_of_parent_and_registered_set",
    ),
    (
        "spawn.atomicity",
        "invalid_header_calls_image_or_quota_causes_no_partial_child",
    ),
    (
        "module.capability",
        "published_only_by_initialized_and_healthy_implementation",
    ),
    (
        "module.withdrawal",
        "withdraw_from_discovery_then_drain_readers",
    ),
    (
        "cross_domain.identity",
        "proxy_identity_and_generation_must_survive_transport",
    ),
    (
        "cross_domain.cancel",
        "cancellation_not_observed_until_remote_terminal_decision",
    ),
    (
        "cross_domain.death",
        "service_death_maps_to_stable_unavailable_or_cancelled_terminal",
    ),
    (
        "cross_domain.rollback",
        "failed_remote_activation_leaves_no_published_capability_or_handle",
    ),
    (
        "cross_domain.performance",
        "same_workload_and_sample_size_required_for_release_claims",
    ),
    (
        "timer.clock",
        "monotonic_unsigned_nanoseconds;relative_overflow_rejected",
    ),
    (
        "timer.urgency",
        "precise_at;tolerant_at_through_at_plus_slack;never_after_latest",
    ),
    (
        "timer.period",
        "zero_is_one_shot;nonzero_is_fixed_phase;missed_periods_are_skipped",
    ),
    (
        "timer.identity",
        "object_local_slot_plus_generation;closed_identity_never_reused",
    ),
    (
        "timer.waiters",
        "at_most_one;arm_cancel_close_wake_with_terminal_result",
    ),
    (
        "timer.coalescing",
        "shared_timer_irq_may_wake_after_at_and_never_after_latest",
    ),
    (
        "workload.domain",
        "kernel_issued_caller_domain;descriptor_cannot_select_domain",
    ),
    (
        "workload.query",
        "same_domain_only;fixed_64_byte_record;domain_not_disclosed",
    ),
    (
        "workload.stop",
        "running_to_stopping;stopped_requires_zero_usage_and_children",
    ),
    (
        "workload.destroy",
        "same_domain_only;terminal_only;zero_usage_and_children",
    ),
    (
        "workload.spawn",
        "same_domain_running_only;bind_before_pages_and_threads;spawn_v2_descriptor;workload_owns_cpu_limit",
    ),
    (
        "workload.kill",
        "same_domain_running_or_stopping;begin_exit_all_members;resources_cleaned_by_normal_exit",
    ),
    (
        "workload.member.query",
        "same_domain_only;counts_current_process_members;closed_members_are_not_observable",
    ),
    (
        "sandbox.identity",
        "kernel_issued_same_domain_key;one_root_workload;root_key_not_disclosed",
    ),
    (
        "sandbox.lifecycle",
        "state_delegated_to_root_workload;no_copied_limits_usage_or_membership",
    ),
    (
        "sandbox.lifecycle.transition",
        "create_starts_root;stop_requests_then_completes_only_after_workload_cleanup",
    ),
    (
        "sandbox.destroy",
        "same_domain_only;terminal_only;root_usage_children_and_members_must_be_zero",
    ),
    (
        "sandbox.storage.ownership",
        "kernel_issued_domain;sandbox_must_be_live;path_is_not_authority",
    ),
    (
        "sandbox.storage.lifecycle",
        "image_requires_no_volumes_before_destroy;volume_requires_no_cow_children",
    ),
    (
        "sandbox.storage.layer",
        "bounded_immutable_layers;content_digest_identity;no_writable_lower_layer",
    ),
    (
        "sandbox.storage.volume",
        "writable_upper_separate_from_image;child_clone_has_independent_usage",
    ),
    (
        "sandbox.wait",
        "observes_root_terminal_state_only;zero_timeout_is_nonblocking;max_timeout_is_wait_forever;kernel_monotonic_clock",
    ),
    (
        "sandbox.kill",
        "same_domain_only;root_workload_begin_exit_members;stopped_requires_normal_resource_drain",
    ),
];

/// 渲染失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderError {
    /// 登记表格式或唯一性失败。
    Registry(AbiError),
    /// 当前登记表里的操作没有参数契约。
    MissingOperation,
    /// 参数契约表里有重复名字。
    DuplicateOperation,
    /// 参数契约表里有未登记的操作。
    ExtraOperation,
    /// 输出 writer 失败。
    Output,
}

/// 快照校验失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// 缺少 `format=1`、`abi=Major.Minor.Patch` 或出现未知记录。
    Malformed,
    /// 当前 ABI 版本没有同名快照。
    MissingCurrent(AbiVersion),
    /// 同名快照出现多次。
    DuplicateCurrent(AbiVersion),
    /// 同名快照内容与当前源码渲染不一致。
    CurrentDiff,
    /// 旧快照晚于当前 ABI。
    SnapshotNewer {
        snapshot: AbiVersion,
        native: AbiVersion,
    },
    /// 同主版本的旧条目被删除或修改。
    ContractChanged,
    /// Patch 升级必须保持契约完全不变。
    PatchChanged,
}

/// 快照输入：版本来自文件名/`abi=`，正文用于比较。
#[derive(Debug, Clone, Copy)]
pub struct Snapshot<'a> {
    /// 快照声明的 ABI 版本。
    pub version: AbiVersion,
    /// 完整文件文本。
    pub text: &'a str,
}

fn find_operation(name: &str) -> Option<&'static OperationContract> {
    OPERATIONS.iter().find(|op| op.name == name)
}

fn line_for_id(registry: &str, id: u32) -> Option<AbiLine<'_>> {
    registry.lines().enumerate().find_map(|(i, line)| {
        abi::parse_line(i + 1, line)
            .ok()
            .flatten()
            .filter(|rec| rec.id == id)
    })
}

fn write_layout<W: fmt::Write>(layout: LayoutContract, out: &mut W) -> Result<(), RenderError> {
    write!(
        out,
        "layout|{}|v{}|size={}|magic=0x{:08x}|fields=",
        layout.name, layout.version, layout.size, layout.magic
    )
    .map_err(|_| RenderError::Output)?;
    for (i, field) in layout.fields.iter().enumerate() {
        if i != 0 {
            out.write_char(',').map_err(|_| RenderError::Output)?;
        }
        write!(out, "{}:{}:{}", field.name, field.offset, field.width)
            .map_err(|_| RenderError::Output)?;
    }
    out.write_char('\n').map_err(|_| RenderError::Output)
}

/// 从登记表与当前源码常量渲染规范快照。输出按接口 ID、布局/语义声明顺序确定。
pub fn render_current<W: fmt::Write>(registry: &str, out: &mut W) -> Result<(), RenderError> {
    let mut max_id = 0u32;
    let mut op_count = 0usize;
    let mut duplicate_op = false;
    abi::validate(registry, |rec| {
        max_id = max_id.max(rec.id);
        if rec.kind == "op" {
            op_count += 1;
            if OPERATIONS.iter().filter(|op| op.name == rec.name).count() != 1 {
                duplicate_op = true;
            }
        }
    })
    .map_err(RenderError::Registry)?;
    if duplicate_op {
        return Err(RenderError::DuplicateOperation);
    }
    if op_count != OPERATIONS.len() {
        return Err(if op_count > OPERATIONS.len() {
            RenderError::MissingOperation
        } else {
            RenderError::ExtraOperation
        });
    }

    writeln!(
        out,
        "# jasper-os ABI contract snapshot; generated, do not edit"
    )
    .map_err(|_| RenderError::Output)?;
    writeln!(out, "format={}", SNAPSHOT_FORMAT).map_err(|_| RenderError::Output)?;
    writeln!(
        out,
        "abi={}.{}.{}",
        crate::abi_version::NATIVE.major,
        crate::abi_version::NATIVE.minor,
        crate::abi_version::NATIVE.patch
    )
    .map_err(|_| RenderError::Output)?;

    for id in 1..=max_id {
        let Some(rec) = line_for_id(registry, id) else {
            continue;
        };
        writeln!(
            out,
            "iface|{}|{}|{}|{}|{}",
            rec.id, rec.kind, rec.name, rec.version, rec.effects
        )
        .map_err(|_| RenderError::Output)?;
        if rec.kind == "op" {
            let op = find_operation(rec.name).ok_or(RenderError::MissingOperation)?;
            writeln!(out, "op|{}|args={}|result={}", op.name, op.args, op.result)
                .map_err(|_| RenderError::Output)?;
        }
    }
    for (name, bit) in RIGHTS {
        writeln!(out, "rights|{}|{}", name, bit).map_err(|_| RenderError::Output)?;
    }
    for layout in LAYOUTS {
        write_layout(*layout, out)?;
    }
    for (key, value) in SEMANTICS {
        writeln!(out, "semantics|{}|{}", key, value).map_err(|_| RenderError::Output)?;
    }
    Ok(())
}

fn parse_version_text(raw: &str) -> Option<AbiVersion> {
    let mut parts = raw.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(AbiVersion::new(major, minor, patch))
}

/// 从快照文本读取 `abi=Major.Minor.Patch`。
pub fn snapshot_version(text: &str) -> Result<AbiVersion, SnapshotError> {
    let mut version = None;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if let Some(raw) = line.strip_prefix("abi=") {
            if version.is_some() {
                return Err(SnapshotError::Malformed);
            }
            version = Some(parse_version_text(raw).ok_or(SnapshotError::Malformed)?);
        }
    }
    version.ok_or(SnapshotError::Malformed)
}

fn validate_snapshot_text(text: &str) -> Result<AbiVersion, SnapshotError> {
    let version = snapshot_version(text)?;
    let mut format = None;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if let Some(raw) = line.strip_prefix("format=") {
            if format
                .replace(raw.parse::<u32>().map_err(|_| SnapshotError::Malformed)?)
                .is_some()
            {
                return Err(SnapshotError::Malformed);
            }
        } else if line.starts_with("abi=") {
        } else if line.starts_with("iface|")
            || line.starts_with("op|")
            || line.starts_with("rights|")
            || line.starts_with("layout|")
            || line.starts_with("semantics|")
        {
        } else {
            return Err(SnapshotError::Malformed);
        }
    }
    if format != Some(SNAPSHOT_FORMAT) {
        return Err(SnapshotError::Malformed);
    }
    Ok(version)
}

fn body_contains(current: &str, expected: &str) -> bool {
    current.lines().map(str::trim).any(|line| line == expected)
}

/// 检查当前渲染与已提交快照集合。要求：
/// * 当前 ABI 版本恰好有一个同名快照，且正文完全一致；
/// * 同主版本的旧快照是当前契约的子集；
/// * 只升 Patch 时正文必须完全相等；
/// * 主版本变化不要求继承旧主版本快照。
pub fn check_snapshot_set(current: &str, snapshots: &[Snapshot<'_>]) -> Result<(), SnapshotError> {
    let current_version = validate_snapshot_text(current)?;
    let mut current_found = 0usize;
    for snapshot in snapshots {
        let snapshot_version = validate_snapshot_text(snapshot.text)?;
        if snapshot_version != snapshot.version {
            return Err(SnapshotError::Malformed);
        }
        if snapshot.version == current_version {
            current_found += 1;
            if snapshot.text != current {
                return Err(SnapshotError::CurrentDiff);
            }
            continue;
        }
        if snapshot.version.major != current_version.major {
            continue;
        }
        if snapshot.version > current_version {
            return Err(SnapshotError::SnapshotNewer {
                snapshot: snapshot.version,
                native: current_version,
            });
        }
        let patch_only = snapshot.version.minor == current_version.minor;
        if patch_only {
            let same = current
                .lines()
                .map(str::trim)
                .filter(|line| {
                    !line.is_empty() && !line.starts_with('#') && !line.starts_with("abi=")
                })
                .eq(snapshot.text.lines().map(str::trim).filter(|line| {
                    !line.is_empty() && !line.starts_with('#') && !line.starts_with("abi=")
                }));
            if !same {
                return Err(SnapshotError::PatchChanged);
            }
        } else {
            for line in snapshot.text.lines().map(str::trim).filter(|line| {
                !line.is_empty() && !line.starts_with('#') && !line.starts_with("abi=")
            }) {
                if !body_contains(current, line) {
                    return Err(SnapshotError::ContractChanged);
                }
            }
        }
    }
    match current_found {
        0 => Err(SnapshotError::MissingCurrent(current_version)),
        1 => Ok(()),
        _ => Err(SnapshotError::DuplicateCurrent(current_version)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi_version::AbiVersion;

    const REG: &str = include_str!("../../abi/system-ids.txt");

    fn render() -> String {
        let mut out = String::new();
        render_current(REG, &mut out).unwrap();
        out
    }

    fn snap(version: AbiVersion, text: &str) -> Snapshot<'_> {
        Snapshot { version, text }
    }

    #[test]
    fn every_registered_operation_has_one_signature_and_layouts_are_well_formed() {
        let text = render();
        assert!(text.contains("iface|1|op|system.task.exit|1|irreversible"));
        assert!(text.contains("op|system.abi.get|args=-|result=packed_abi_version"));
        for layout in LAYOUTS {
            for field in layout.fields {
                assert!(
                    (field.offset as u32 + field.width as u32) <= layout.size,
                    "{} field {} exceeds size",
                    layout.name,
                    field.name
                );
            }
        }
        let mut seen = 0;
        for line in text.lines().filter(|line| line.starts_with("op|")) {
            let name = line.split('|').nth(1).unwrap();
            assert_eq!(find_operation(name).map(|op| op.name), Some(name));
            seen += 1;
        }
        assert_eq!(seen, OPERATIONS.len());
    }

    #[test]
    fn exact_current_snapshot_passes_and_missing_snapshot_fails() {
        let current = render();
        let version = crate::abi_version::NATIVE;
        assert_eq!(
            check_snapshot_set(&current, &[snap(version, &current)]),
            Ok(())
        );
        assert_eq!(
            check_snapshot_set(&current, &[]),
            Err(SnapshotError::MissingCurrent(version))
        );
    }

    #[test]
    fn same_major_minor_addition_is_allowed_but_removal_or_change_is_rejected() {
        let current = render();
        let native = crate::abi_version::NATIVE;
        let old_version = AbiVersion::new(native.major, 0, 0);
        let current_version = AbiVersion::new(native.major, 1, 0);
        let current = current.replace(
            &format!("abi={}.{}.{}", native.major, native.minor, native.patch),
            &format!("abi={}.1.0", native.major),
        );
        let old = current.replace("semantics|cross_domain.performance|same_workload_and_sample_size_required_for_release_claims\n", "")
            .replace(&format!("abi={}.1.0", native.major), &format!("abi={}.0.0", native.major));
        assert_eq!(
            check_snapshot_set(
                &current,
                &[snap(old_version, &old), snap(current_version, &current)]
            ),
            Ok(())
        );
        let changed = current.replace(
            "semantics|cross_domain.performance|same_workload_and_sample_size_required_for_release_claims",
            "semantics|cross_domain.performance|best_effort",
        );
        let old_changed = current.replace(
            &format!("abi={}.1.0", native.major),
            &format!("abi={}.0.0", native.major),
        );
        assert_eq!(
            check_snapshot_set(
                &changed,
                &[
                    snap(old_version, &old_changed),
                    snap(current_version, &changed)
                ]
            ),
            Err(SnapshotError::ContractChanged)
        );
    }

    #[test]
    fn patch_upgrade_requires_identical_contract_body() {
        let mut current = render();
        let native = crate::abi_version::NATIVE;
        current = current.replace(
            &format!("abi={}.{}.{}", native.major, native.minor, native.patch),
            &format!("abi={}.{}.{}", native.major, native.minor, native.patch + 1),
        );
        let current_snapshot = snap(
            AbiVersion::new(native.major, native.minor, native.patch + 1),
            &current,
        );
        let mut old = current.clone();
        old = old.replace(
            &format!("abi={}.{}.{}", native.major, native.minor, native.patch + 1),
            &format!("abi={}.{}.{}", native.major, native.minor, native.patch),
        );
        assert_eq!(
            check_snapshot_set(&current, &[snap(native, &old), current_snapshot]),
            Ok(())
        );
        let changed = current.replace("rights|READ|1", "rights|READ|2");
        let changed_snapshot = snap(
            AbiVersion::new(native.major, native.minor, native.patch + 1),
            &changed,
        );
        assert_eq!(
            check_snapshot_set(&changed, &[snap(native, &old), changed_snapshot]),
            Err(SnapshotError::PatchChanged)
        );
    }

    #[test]
    fn new_major_does_not_inherit_old_major_contracts() {
        let mut current = render();
        let native = crate::abi_version::NATIVE;
        let next_major = native.major + 1;
        current = current.replace(
            &format!("abi={}.{}.{}", native.major, native.minor, native.patch),
            &format!("abi={}.0.0", next_major),
        );
        let version = AbiVersion::new(next_major, 0, 0);
        let old = render();
        assert_eq!(
            check_snapshot_set(&current, &[snap(native, &old), snap(version, &current)]),
            Ok(())
        );
    }

    #[test]
    fn malformed_and_duplicate_current_snapshots_are_rejected() {
        let current = render();
        let version = crate::abi_version::NATIVE;
        assert_eq!(
            check_snapshot_set(
                &current,
                &[snap(version, &current), snap(version, &current)]
            ),
            Err(SnapshotError::DuplicateCurrent(version))
        );
        assert_eq!(
            check_snapshot_set("format=2\nabi=1.0.0\n", &[]),
            Err(SnapshotError::Malformed)
        );
    }
}
