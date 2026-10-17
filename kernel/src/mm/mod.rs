//! 内存管理子系统门面（M2.x）。
//!
//! * `frame` —— 全局物理页帧分配服务（M2.1）：把 `kernel-core` 的位图分配器接到真实内存图上
//! * `map`   —— 内核地址空间映射服务（M2.2）：经 `arch::Mapper` 实现 Core 的 `PageMapper` 契约
//! * `heap`  —— 内核堆与 `#[global_allocator]`（M2.3）：页帧 + 映射之上按需增长
//! * `space` —— 独立虚拟地址空间对象 `VmSpace`（M2.4）：私有窗口 + 共享内核部分，真实切换
//! * `user`  —— 用户指针安全（M3.3）：系统调用参数中用户地址的校验与经物理映射的复制
//! * `demo`  —— 里程碑演练（与机制分离，可整体删除）
//! * 本文件  —— 物理地址 ↔ 内核可访问虚拟地址的换算（经引导器提供的「全物理内存映射」偏移）
//!

pub mod demo;
pub mod frame;
pub mod heap;
pub mod map;
pub mod space;
pub mod user;

use crate::boot;

/// 物理地址 → 内核可直接解引用的虚拟地址。
///
/// 依赖引导器把全部物理内存线性映射到 `phys_offset` 处；未映射时返回 `None`。
pub fn phys_to_virt(phys: u64) -> Option<*mut u8> {
    let offset = boot::get()?.phys_offset?;
    Some(offset.checked_add(phys)? as *mut u8)
}
