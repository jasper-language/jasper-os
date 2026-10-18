//! 虚拟地址空间对象（M2.4）：架构无关的「一套独立的地址翻译」。
//!
//! # 职责
//! * [`VmSpace`]：创建（私有窗口为空、内核部分共享）、在私有窗口内映射/取消映射/查询、激活、销毁
//! * Core 只认 `arch::SpaceRoot`（不透明）与 `arch::USER_WINDOW`；PML4/CR3 等全在 `arch/<isa>/space.rs`
//!
//! # 与 `kernel_core::memory::AddressSpace` 的关系
//! 后者是**区域记账**（哪段虚拟区间分给了谁、权限是什么）；本类型是**硬件翻译根**。
//! 进程对象（M3.4）会同时持有两者：记账决定「允许映射什么」，`VmSpace` 负责「真的映射上」。
//!
//! # 安全规则
//! * 只允许修改**私有窗口**内的映射：窗口外的下级页表被所有空间共享，经本类型修改会影响全部空间。
//! * `Drop` 时自动销毁（RAII）：不能销毁当前活动空间——若仍活动，先切回内核空间。
//! * 叶子映射指向的数据帧由调用者负责归还；`VmSpace` 只回收页表结构本身。

use kernel_core::frame::PhysFrame;
use kernel_core::paging::{MapError, MapFlags, PageMapper, VirtPage};
use spin::Once;

use super::map::GlobalFrames;
use crate::arch;
use crate::boot;

/// 启动时的内核地址空间根与内核共享部分的准备结果。
/// 根总会被记录（切回内核空间需要它）；准备失败时结果为 `Err`，此后一律拒绝创建新空间。
struct KernelSpace {
    root: arch::SpaceRoot,
    ready: Result<usize, MapError>,
}

static KERNEL: Once<KernelSpace> = Once::new();

/// 记录内核地址空间根并预分配内核共享部分的顶级表项（在创建任何其他空间之前调用；只生效一次）。
///
/// 预分配失败**不会被忽略**：结果被记录下来，[`VmSpace::new`] 据此拒绝创建地址空间——
/// 否则之后新增的内核映射可能对部分空间不可见。返回准备结果（重复调用返回首次的结果）。
/// Initialise the kernel space once; a preparation failure is recorded and makes every later `VmSpace::new` fail.
pub fn init() -> Result<usize, MapError> {
    KERNEL
        .call_once(|| {
            let root = arch::current_space();
            let ready = match boot::get().and_then(|b| b.phys_offset) {
                // SAFETY：此时尚未创建其他地址空间，且当前就是内核空间。
                Some(offset) => unsafe { arch::prepare_kernel_space(root, offset, &mut GlobalFrames) },
                None => Err(MapError::NotMapped),
            };
            KernelSpace { root, ready }
        })
        .ready
}

/// 内核空间是否已就绪；未就绪时给出原因（供创建前检查，也便于单独演练拒绝路径）。
/// Whether a recorded preparation result allows creating address spaces.
pub fn ready_from(result: Result<usize, MapError>) -> Result<(), MapError> {
    result.map(|_| ())
}

/// 切回内核地址空间。
pub fn activate_kernel() {
    if let Some(&KernelSpace { root, .. }) = KERNEL.get() {
        // SAFETY：内核空间是启动时的活动空间，包含全部内核映射。
        unsafe { arch::switch_space(root) };
    }
}

/// 地址是否位于私有窗口内。
pub fn in_private_window(va: u64) -> bool {
    va >= arch::USER_WINDOW.0 && va < arch::USER_WINDOW.1
}

/// 一个独立的虚拟地址空间。
pub struct VmSpace {
    root: arch::SpaceRoot,
    mapper: arch::Mapper,
    phys_offset: u64,
}

impl VmSpace {
    /// 新建地址空间。
    pub fn new() -> Result<Self, MapError> {
        let phys_offset = boot::get().and_then(|b| b.phys_offset).ok_or(MapError::NotMapped)?;
        ready_from(init())?;
        // SAFETY：offset 来自引导器；新空间的映射器只用于私有窗口（见 `map` 的检查），不与内核映射器别名修改共享表。
        unsafe {
            let root = arch::create_space(phys_offset, &mut GlobalFrames)?;
            let mapper = arch::space_mapper(root, phys_offset);
            Ok(VmSpace { root, mapper, phys_offset })
        }
    }

    /// 地址空间根（诊断用）。
    pub fn root(&self) -> arch::SpaceRoot {
        self.root
    }

    /// 在私有窗口内映射一页。窗口外返回 [`MapError::InvalidAddress`]。
    pub fn map(&mut self, page: VirtPage, frame: PhysFrame, flags: MapFlags) -> Result<(), MapError> {
        if !in_private_window(page.start()) {
            return Err(MapError::InvalidAddress);
        }
        self.mapper.map(page, frame, flags, &mut GlobalFrames)
    }

    /// 取消私有窗口内的映射并返回原帧。
    pub fn unmap(&mut self, page: VirtPage) -> Result<PhysFrame, MapError> {
        if !in_private_window(page.start()) {
            return Err(MapError::InvalidAddress);
        }
        self.mapper.unmap(page)
    }

    /// 查询映射（窗口内外都可查询）。
    pub fn translate(&self, page: VirtPage) -> Option<(PhysFrame, MapFlags)> {
        self.mapper.translate(page)
    }

    /// 切换到本地址空间。
    pub fn activate(&self) {
        // SAFETY：本空间由 create_space 建立、未销毁，且共享全部内核映射。
        unsafe { arch::switch_space(self.root) };
    }

    /// 本空间当前是否为活动空间。
    pub fn is_active(&self) -> bool {
        arch::current_space() == self.root
    }
}

impl Drop for VmSpace {
    fn drop(&mut self) {
        if self.is_active() {
            activate_kernel();
        }
        // SAFETY：已确保不是活动空间；此后不再使用 root。
        unsafe { arch::destroy_space(self.root, self.phys_offset, &mut GlobalFrames) };
    }
}
