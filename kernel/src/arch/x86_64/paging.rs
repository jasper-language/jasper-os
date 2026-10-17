//! x86_64 页映射：用 4 级页表（PML4 → PDPT → PD → PT）实现 Core 的 [`PageMapper`] 契约。
//!
//! 职责：把中立的 [`MapFlags`] 翻译成 x86 表项位（PRESENT/WRITABLE/USER_ACCESSIBLE/GLOBAL/NO_EXECUTE），
//! 并在修改后刷新对应 TLB 项。页表本身通过「全物理内存映射偏移」访问（引导器已建立该映射）。
//!
//! 只有本文件知道 PML4、CR3、PTE 位、`invlpg`；Core 只看到 [`PageMapper`]。

use kernel_core::frame::{FrameAllocator, PhysFrame};
use kernel_core::paging::{MapError, MapFlags, PageMapper, VirtPage};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::{MapToError, MappedFrame, TranslateResult, UnmapError};
use x86_64::structures::paging::{
    FrameAllocator as X86FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame as X86Frame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

/// 当前活动地址空间的映射器。
pub struct X86Mapper {
    table: OffsetPageTable<'static>,
}

impl X86Mapper {
    /// 以当前 CR3 指向的 PML4 建立映射器。
    ///
    /// # Safety
    /// * `phys_offset` 必须是引导器建立的「全物理内存映射」偏移；
    /// * 同一时刻只能存在一个指向该 PML4 的映射器（否则会产生别名的 `&mut PageTable`）。
    pub unsafe fn active(phys_offset: u64) -> Self {
        let (pml4_frame, _) = Cr3::read();
        Self::for_root(pml4_frame.start_address().as_u64(), phys_offset)
    }

    /// 为任意一张 PML4（物理地址 `pml4_phys`）建立映射器；该空间不必是当前活动空间。
    ///
    /// # Safety
    /// 同 [`X86Mapper::active`]；且 `pml4_phys` 必须是一张有效的 PML4。
    pub unsafe fn for_root(pml4_phys: u64, phys_offset: u64) -> Self {
        let pml4: &'static mut PageTable = &mut *((phys_offset + pml4_phys) as *mut PageTable);
        X86Mapper { table: OffsetPageTable::new(pml4, VirtAddr::new(phys_offset)) }
    }
}

/// 中立权限 → x86 表项位。
fn to_x86(flags: MapFlags) -> PageTableFlags {
    let mut f = PageTableFlags::PRESENT;
    if flags.contains(MapFlags::WRITE) {
        f |= PageTableFlags::WRITABLE;
    }
    if flags.contains(MapFlags::USER) {
        f |= PageTableFlags::USER_ACCESSIBLE;
    }
    if flags.contains(MapFlags::GLOBAL) {
        f |= PageTableFlags::GLOBAL;
    }
    if !flags.contains(MapFlags::EXECUTE) {
        f |= PageTableFlags::NO_EXECUTE;
    }
    f
}

/// x86 表项位 → 中立权限。
fn from_x86(f: PageTableFlags) -> MapFlags {
    let mut m = MapFlags::READ_ONLY;
    if f.contains(PageTableFlags::WRITABLE) {
        m = m | MapFlags::WRITE;
    }
    if f.contains(PageTableFlags::USER_ACCESSIBLE) {
        m = m | MapFlags::USER;
    }
    if f.contains(PageTableFlags::GLOBAL) {
        m = m | MapFlags::GLOBAL;
    }
    if !f.contains(PageTableFlags::NO_EXECUTE) {
        m = m | MapFlags::EXECUTE;
    }
    m
}

/// 校验并转换虚拟页（x86_64 要求规范地址：高 16 位是第 47 位的符号扩展）。
fn x86_page(page: VirtPage) -> Result<Page<Size4KiB>, MapError> {
    let va = VirtAddr::try_new(page.start()).map_err(|_| MapError::InvalidAddress)?;
    Page::from_start_address(va).map_err(|_| MapError::InvalidAddress)
}

/// 把 Core 的页帧分配器适配成 x86_64 crate 需要的形状（建立中间页表时调用）。
struct FrameAdapter<'a>(&'a mut dyn FrameAllocator);

// SAFETY：只返回分配器新分出、未被使用的 4 KiB 帧；x86_64 crate 会在用作页表前将其清零。
unsafe impl X86FrameAllocator<Size4KiB> for FrameAdapter<'_> {
    fn allocate_frame(&mut self) -> Option<X86Frame<Size4KiB>> {
        let f = self.0.allocate().ok()?;
        X86Frame::from_start_address(PhysAddr::new(f.start())).ok()
    }
}

impl PageMapper for X86Mapper {
    fn map(
        &mut self,
        page: VirtPage,
        frame: PhysFrame,
        flags: MapFlags,
        frames: &mut dyn FrameAllocator,
    ) -> Result<(), MapError> {
        let p = x86_page(page)?;
        let f = X86Frame::from_start_address(PhysAddr::new(frame.start())).map_err(|_| MapError::InvalidAddress)?;
        let mut adapter = FrameAdapter(frames);
        // SAFETY：调用者负责 `frame` 不被别处同时以冲突方式使用；新映射不会覆盖已有映射（会报错）。
        let flush = unsafe { self.table.map_to(p, f, to_x86(flags), &mut adapter) }.map_err(|e| match e {
            MapToError::FrameAllocationFailed => MapError::OutOfFrames,
            MapToError::ParentEntryHugePage => MapError::HugePage,
            MapToError::PageAlreadyMapped(_) => MapError::AlreadyMapped,
        })?;
        flush.flush();
        Ok(())
    }

    fn unmap(&mut self, page: VirtPage) -> Result<PhysFrame, MapError> {
        let p = x86_page(page)?;
        let (frame, flush) = self.table.unmap(p).map_err(|e| match e {
            UnmapError::PageNotMapped => MapError::NotMapped,
            UnmapError::ParentEntryHugePage => MapError::HugePage,
            UnmapError::InvalidFrameAddress(_) => MapError::InvalidAddress,
        })?;
        flush.flush();
        PhysFrame::from_start(frame.start_address().as_u64()).ok_or(MapError::InvalidAddress)
    }

    fn translate(&self, page: VirtPage) -> Option<(PhysFrame, MapFlags)> {
        let va = VirtAddr::try_new(page.start()).ok()?;
        match self.table.translate(va) {
            TranslateResult::Mapped { frame: MappedFrame::Size4KiB(f), flags, .. } => {
                Some((PhysFrame::from_start(f.start_address().as_u64())?, from_x86(flags)))
            }
            _ => None,
        }
    }

    fn protect(&mut self, page: VirtPage, flags: MapFlags) -> Result<(), MapError> {
        let p = x86_page(page)?;
        if self.translate(page).is_none() {
            return Err(MapError::NotMapped);
        }
        // SAFETY：只修改已存在的 4 KiB 映射的权限位，不改变其指向的帧。
        let flush = unsafe { self.table.update_flags(p, to_x86(flags)) }.map_err(|_| MapError::HugePage)?;
        flush.flush();
        Ok(())
    }
}
