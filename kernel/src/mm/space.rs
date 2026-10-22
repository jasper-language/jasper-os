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
use kernel_core::smp::{CpuSet, CpuState};
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
        crate::smp::percpu::this().set_space(None);
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
    /// 页表已经改变、但跨核击落尚未完成；期间拒绝同一空间的其它修改。
    shootdown_pending: bool,
}

impl VmSpace {
    /// 新建地址空间。
    pub fn new() -> Result<Self, MapError> {
        let phys_offset = boot::get().and_then(|b| b.phys_offset).ok_or(MapError::NotMapped)?;
        ready_from(init())?;
        // 以内核地址空间为模板（而非当前空间：在用户进程的系统调用里创建时，当前空间是该进程的）
        let template = KERNEL.get().map(|k| k.root).ok_or(MapError::NotMapped)?;
        // SAFETY：offset 来自引导器；模板是启动时记录的内核空间根；新空间的映射器只用于私有窗口（见 `map` 的检查），不与内核映射器别名修改共享表。
        unsafe {
            let root = arch::create_space(template, phys_offset, &mut GlobalFrames)?;
            let mapper = arch::space_mapper(root, phys_offset);
            Ok(VmSpace { root, mapper, phys_offset, shootdown_pending: false })
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
        if self.shootdown_pending {
            return Err(MapError::Busy);
        }
        self.map_raw(page, frame, flags)
    }

    /// 只映射页表；调用者必须在同一地址空间的变更临界区内调用。
    /// Install one mapping while the caller owns the address-space mutation window.
    pub(crate) fn map_raw(&mut self, page: VirtPage, frame: PhysFrame, flags: MapFlags) -> Result<(), MapError> {
        if !in_private_window(page.start()) {
            return Err(MapError::InvalidAddress);
        }
        self.mapper.map(page, frame, flags, &mut GlobalFrames)
    }

    /// 取消私有窗口内的一页；在返回原帧前完成本空间活跃处理器上的击落。
    pub fn unmap(&mut self, page: VirtPage) -> Result<PhysFrame, MapError> {
        if !in_private_window(page.start()) {
            return Err(MapError::InvalidAddress);
        }
        if self.shootdown_pending {
            return Err(MapError::Busy);
        }
        let frame = self.unmap_raw(page)?;
        self.shootdown_active(page.start(), 1)?;
        Ok(frame)
    }

    /// 修改私有窗口内一页的权限；返回前完成本空间活跃处理器上的击落。
    pub fn protect(&mut self, page: VirtPage, flags: MapFlags) -> Result<(), MapError> {
        if !in_private_window(page.start()) {
            return Err(MapError::InvalidAddress);
        }
        if self.shootdown_pending {
            return Err(MapError::Busy);
        }
        self.protect_raw(page, flags)?;
        self.shootdown_active(page.start(), 1)
    }

    /// 只修改页表、不执行击落；调用者必须在返回帧之前批量执行 [`shootdown_active`]。
    /// Change only the page table; the caller must shoot down before releasing any frame.
    pub(crate) fn unmap_raw(&mut self, page: VirtPage) -> Result<PhysFrame, MapError> {
        if !in_private_window(page.start()) {
            return Err(MapError::InvalidAddress);
        }
        self.mapper.unmap(page)
    }

    /// 只修改页表权限、不执行击落。
    /// Change only page permissions; the caller must shoot down before returning.
    pub(crate) fn protect_raw(&mut self, page: VirtPage, flags: MapFlags) -> Result<(), MapError> {
        if !in_private_window(page.start()) {
            return Err(MapError::InvalidAddress);
        }
        self.mapper.protect(page, flags)
    }

    /// 本地址空间当前装入的在线处理器集合。
    /// Online processors whose current user address space is this space.
    pub fn active_cpus(&self) -> CpuSet {
        let mut set = CpuSet::EMPTY;
        for cpu in 0..crate::smp::cpu_count() {
            if let Some(p) = crate::smp::percpu::get(cpu) {
                if p.state.get() == CpuState::Online && p.space() == Some(self.root) {
                    set.insert(cpu);
                }
            }
        }
        set
    }

    /// 对当前活跃处理器批量作废一段页表映射；过大范围在公告板层退化为整表刷新。
    /// Invalidate a range on the active processor set; the board promotes large ranges to a whole-table flush.
    pub(crate) fn shootdown_active(&self, va: u64, pages: u64) -> Result<(), MapError> {
        crate::smp::tlb_shootdown_on(self.active_cpus(), va, pages).map_err(|_| MapError::Busy)
    }

    /// 标记页表修改跨越击落等待；已在等待时返回 `false`。
    /// Start a page-table mutation that crosses a shootdown.
    pub(crate) fn begin_shootdown(&mut self) -> bool {
        if self.shootdown_pending {
            false
        } else {
            self.shootdown_pending = true;
            true
        }
    }

    /// 完成击落后重新允许该地址空间的修改。
    /// Finish a page-table mutation and permit later changes.
    pub(crate) fn end_shootdown(&mut self) {
        self.shootdown_pending = false;
    }

    /// 查询映射（窗口内外都可查询）。
    pub fn translate(&self, page: VirtPage) -> Option<(PhysFrame, MapFlags)> {
        self.mapper.translate(page)
    }

    /// 切换到本地址空间。
    pub fn activate(&self) {
        // SAFETY：本空间由 create_space 建立、未销毁，且共享全部内核映射。
        unsafe { arch::switch_space(self.root) };
        crate::smp::percpu::this().set_space(Some(self.root));
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
        crate::smp::percpu::this().set_space(None);
        // SAFETY：已确保不是活动空间；此后不再使用 root。
        unsafe { arch::destroy_space(self.root, self.phys_offset, &mut GlobalFrames) };
    }
}
