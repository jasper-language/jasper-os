//! 多级基数页表的通用遍历：映射、取消映射、查询、改权限、预分配顶级表项、回收下级表。
//! Generic multi-level radix page-table walker shared by the ISA ports.
//!
//! # 职责与边界
//! * 只负责「沿各级表走到叶子」这一与 ISA 无关的算法；表项的**位格式**由 [`EntryFormat`]（Strategy）给出，
//!   页表所在物理内存的**访问方式**由 [`TableMemory`] 给出（内核经全物理内存映射，宿主测试用内存模拟）。
//! * 不做 TLB 维护：修改成功后由调用者（各 ISA 的映射器）按本 ISA 的规则刷新。
//! * 只处理 4 KiB 叶子页；遇到非叶级的大页块一律报 [`MapError::HugePage`]，不拆分、不改动它。
//! * 每张表 4 KiB。表项宽度与每级下标位数由位格式给出：默认 512 个 8 字节表项（AArch64 4 KiB 粒度、
//!   RISC-V Sv39/Sv48），也可以是 1024 个 4 字节表项（RISC-V Sv32）；顶级表可以只用前一部分表项（由可用虚拟地址位数决定）。
//!   表项在接口上一律以 `u64` 传递，4 字节表项由 [`TableMemory`] 的实现负责截断与零扩展。
//!
//! # 失败语义
//! 所有修改操作都是「全有或全无」：[`PageTable::map`] 中途分配下级表失败时，本次新建的下级表全部摘除并归还；
//! [`PageTable::prealloc_top`] 先备齐全部帧再一次性安装。失败返回时页表与页帧分配器都回到调用前的状态。

use core::marker::PhantomData;
use core::ops::Range;

use crate::frame::{FrameAllocator, PhysFrame, FRAME_SIZE};
use crate::paging::{MapError, MapFlags};

/// 一张表的字节数（各级相同）。
/// Size of one page table in bytes.
pub const TABLE_BYTES: usize = 4096;
/// 支持的最大级数（含顶级）。
pub const MAX_LEVELS: usize = 5;

/// 每张表的表项数：表大小除以表项宽度。
/// Number of entries in one table for the given entry width.
pub const fn entries_per_table(entry_bytes: usize) -> usize {
    TABLE_BYTES / entry_bytes
}

/// 表项位格式（每个 ISA 一个实现）。级别编号：0 = 顶级，`LEVELS - 1` = 叶级。
/// Entry bit format of one ISA; level 0 is the top level.
pub trait EntryFormat {
    /// 级数（含顶级与叶级），不超过 [`MAX_LEVELS`]。
    const LEVELS: usize;
    /// 可用虚拟地址位数：只接受 `[0, 2^VA_BITS)` 内的地址。
    const VA_BITS: u32;
    /// 每级下标的位数（默认 9；Sv32 为 10）。
    /// Index bits per level.
    const INDEX_BITS: u32 = 9;
    /// 表项宽度（字节；默认 8；Sv32 为 4）。必须与 `TABLE_BYTES / 2^INDEX_BITS` 一致。
    /// Entry width in bytes.
    const ENTRY_BYTES: usize = 8;
    /// 表项是否有效。
    fn is_valid(raw: u64) -> bool;
    /// 非叶级的**有效**表项是否指向下级表（否则是大页块）。
    fn is_table(raw: u64) -> bool;
    /// 指向下级表 `table_phys` 的表项。
    fn table_entry(table_phys: u64) -> u64;
    /// 映射 4 KiB 帧 `frame_phys`、权限为 `flags` 的叶表项。
    fn leaf_entry(frame_phys: u64, flags: MapFlags) -> u64;
    /// 表项指向的物理地址（下级表或数据帧）。
    fn output_address(raw: u64) -> u64;
    /// 叶表项的中立权限。
    fn leaf_flags(raw: u64) -> MapFlags;
}

/// 页表所在物理内存的访问方式。实现者保证：遍历器给出的 `table` 都是有效的 4 KiB 表的物理地址时，读写安全。
/// Access to the physical memory holding page tables.
pub trait TableMemory {
    /// 表项宽度（字节）：遍历器在编译期检查它与位格式的 [`EntryFormat::ENTRY_BYTES`] 一致。
    /// Entry width in bytes; checked against the format at compile time.
    const ENTRY_BYTES: usize;
    /// 读表 `table` 的第 `index` 项（4 字节表项零扩展）。
    fn read(&self, table: u64, index: usize) -> u64;
    /// 写表 `table` 的第 `index` 项（4 字节表项只写低 32 位；遍历器保证高位为 0）。
    fn write(&mut self, table: u64, index: usize, raw: u64);
    /// 把整张表清零。
    fn zero(&mut self, table: u64);
}

/// 以 `root`（顶级表物理地址）为根的一棵页表。
/// One page-table tree rooted at a top-level table.
pub struct PageTable<F, M> {
    root: u64,
    mem: M,
    _format: PhantomData<F>,
}

impl<F: EntryFormat, M: TableMemory> PageTable<F, M> {
    /// 顶级表实际使用的表项数。
    /// Number of usable entries in the top-level table.
    pub const TOP_ENTRIES: usize = 1 << (F::VA_BITS - 12 - F::INDEX_BITS * (F::LEVELS as u32 - 1));
    /// 每张表的表项数。
    /// Number of entries in every table.
    pub const ENTRIES: usize = 1 << F::INDEX_BITS;

    /// 建立遍历器。`root` 必须是一张有效的顶级表（或清零的空表）。
    /// Create a walker over the tree at `root`.
    pub fn new(root: u64, mem: M) -> Self {
        const {
            assert!(F::ENTRY_BYTES == M::ENTRY_BYTES, "位格式与页表内存的表项宽度不一致");
            assert!(entries_per_table(F::ENTRY_BYTES) == 1 << F::INDEX_BITS, "表项宽度与下标位数不匹配");
            assert!(F::LEVELS >= 1 && F::LEVELS <= MAX_LEVELS);
        }
        PageTable { root, mem, _format: PhantomData }
    }

    /// 顶级表的物理地址。
    pub fn root(&self) -> u64 {
        self.root
    }

    /// `va` 在第 `level` 级表中的下标。
    fn index(va: u64, level: usize) -> usize {
        let shift = 12 + F::INDEX_BITS * (F::LEVELS - 1 - level) as u32;
        ((va >> shift) as usize) & (Self::ENTRIES - 1)
    }

    /// 校验虚拟地址：4 KiB 对齐且在 `[0, 2^VA_BITS)` 内。
    fn check(va: u64) -> Result<(), MapError> {
        if va % FRAME_SIZE != 0 || va >> F::VA_BITS != 0 {
            return Err(MapError::InvalidAddress);
        }
        Ok(())
    }

    /// 走到叶级表：返回叶级表的物理地址；途中缺表返回 `NotMapped`，遇大页块返回 `HugePage`。
    fn leaf_table(&self, va: u64) -> Result<u64, MapError> {
        let mut table = self.root;
        for level in 0..F::LEVELS - 1 {
            let e = self.mem.read(table, Self::index(va, level));
            if !F::is_valid(e) {
                return Err(MapError::NotMapped);
            }
            if !F::is_table(e) {
                return Err(MapError::HugePage);
            }
            table = F::output_address(e);
        }
        Ok(table)
    }

    /// 映射 `va` → `frame`。缺少的下级表从 `frames` 分配并清零；失败时本次新建的下级表全部摘除归还。
    /// Map `va` to `frame`; intermediate tables created by a failed call are removed and freed.
    pub fn map(&mut self, va: u64, frame: PhysFrame, flags: MapFlags, frames: &mut dyn FrameAllocator) -> Result<(), MapError> {
        Self::check(va)?;
        // 本次新建的下级表：(父表, 下标, 新表帧)
        let mut created: [Option<(u64, usize, PhysFrame)>; MAX_LEVELS] = [None; MAX_LEVELS];
        let mut table = self.root;
        let mut result = Ok(());
        for level in 0..F::LEVELS - 1 {
            let i = Self::index(va, level);
            let e = self.mem.read(table, i);
            if !F::is_valid(e) {
                match frames.allocate() {
                    Ok(f) => {
                        self.mem.zero(f.start());
                        self.mem.write(table, i, F::table_entry(f.start()));
                        created[level] = Some((table, i, f));
                        table = f.start();
                    }
                    Err(_) => {
                        result = Err(MapError::OutOfFrames);
                        break;
                    }
                }
            } else if !F::is_table(e) {
                result = Err(MapError::HugePage);
                break;
            } else {
                table = F::output_address(e);
            }
        }
        if result.is_ok() {
            let i = Self::index(va, F::LEVELS - 1);
            if F::is_valid(self.mem.read(table, i)) {
                result = Err(MapError::AlreadyMapped);
            } else {
                self.mem.write(table, i, F::leaf_entry(frame.start(), flags));
                return Ok(());
            }
        }
        // 回滚：自深向浅摘除并归还本次新建的表（它们只含本次写入的下一级表项，摘除即无残留）
        for (parent, i, f) in created.iter().rev().flatten() {
            self.mem.write(*parent, *i, 0);
            let _ = frames.deallocate(*f);
        }
        result
    }

    /// 取消 `va` 的映射，返回原来映射的帧（下级表保留，由 [`PageTable::free_tables`] 统一回收）。
    /// Unmap `va` and return the frame it mapped.
    pub fn unmap(&mut self, va: u64) -> Result<PhysFrame, MapError> {
        Self::check(va)?;
        let table = self.leaf_table(va)?;
        let i = Self::index(va, F::LEVELS - 1);
        let e = self.mem.read(table, i);
        if !F::is_valid(e) {
            return Err(MapError::NotMapped);
        }
        self.mem.write(table, i, 0);
        PhysFrame::from_start(F::output_address(e)).ok_or(MapError::InvalidAddress)
    }

    /// 查询 `va` 所在 4 KiB 页的映射与权限（地址不必对齐）；未映射或位于大页块内返回 `None`。只读，不修改任何表。
    /// Look up the 4 KiB mapping containing `va`; read-only.
    pub fn translate(&self, va: u64) -> Option<(PhysFrame, MapFlags)> {
        let page = va - va % FRAME_SIZE;
        Self::check(page).ok()?;
        let table = self.leaf_table(page).ok()?;
        let e = self.mem.read(table, Self::index(page, F::LEVELS - 1));
        if !F::is_valid(e) {
            return None;
        }
        Some((PhysFrame::from_start(F::output_address(e))?, F::leaf_flags(e)))
    }

    /// 把已存在的映射 `va` 改为权限 `flags`（指向的帧不变）。
    /// Change the permissions of an existing mapping.
    pub fn protect(&mut self, va: u64, flags: MapFlags) -> Result<(), MapError> {
        Self::check(va)?;
        let table = self.leaf_table(va)?;
        let i = Self::index(va, F::LEVELS - 1);
        let e = self.mem.read(table, i);
        if !F::is_valid(e) {
            return Err(MapError::NotMapped);
        }
        self.mem.write(table, i, F::leaf_entry(F::output_address(e), flags));
        Ok(())
    }

    /// 顶级下标区间 `top` 内已使用的表项数。
    /// Number of used top-level entries in `top`.
    pub fn used_top(&self, top: Range<usize>) -> usize {
        top.filter(|&i| F::is_valid(self.mem.read(self.root, i))).count()
    }

    /// 为顶级下标区间 `top` 内的每个空表项预先安装一张清零的下级表，返回新安装数。
    /// **全有或全无**：先分配齐全部帧（用帧自身串成链，不占栈空间），任一失败即全部归还、顶级表一项不改。
    /// Pre-install empty next-level tables for every unused top entry in `top`; all-or-nothing.
    pub fn prealloc_top(&mut self, top: Range<usize>, frames: &mut dyn FrameAllocator) -> Result<usize, MapError> {
        if top.end > Self::TOP_ENTRIES {
            return Err(MapError::InvalidAddress);
        }
        // 第一阶段：只分配。链表：每帧开头存下一帧的地址（0 = 链尾；帧 0 永不分配，不会混淆）
        let need = top.len() - self.used_top(top.clone());
        let mut head = 0u64;
        for _ in 0..need {
            match frames.allocate() {
                Ok(f) => {
                    self.write_link(f.start(), head);
                    head = f.start();
                }
                Err(_) => {
                    while head != 0 {
                        let next = self.read_link(head);
                        let _ = frames.deallocate(PhysFrame::from_number(head / FRAME_SIZE));
                        head = next;
                    }
                    return Err(MapError::OutOfFrames);
                }
            }
        }
        // 第二阶段：逐个清零并安装（不会再失败）
        let mut installed = 0;
        for i in top {
            if F::is_valid(self.mem.read(self.root, i)) {
                continue;
            }
            let f = head;
            head = self.read_link(f);
            self.mem.zero(f);
            self.mem.write(self.root, i, F::table_entry(f));
            installed += 1;
        }
        Ok(installed)
    }

    /// 在空闲帧 `table` 开头记下链表的下一帧地址：8 字节表项占第 0 项；4 字节表项按低 / 高 32 位占第 0、1 项
    /// （物理地址可超过 32 位，例如 Sv32 的 34 位物理地址）。
    fn write_link(&mut self, table: u64, next: u64) {
        if F::ENTRY_BYTES >= 8 {
            self.mem.write(table, 0, next);
        } else {
            self.mem.write(table, 0, next & 0xffff_ffff);
            self.mem.write(table, 1, next >> 32);
        }
    }

    /// 读出 [`Self::write_link`] 记下的下一帧地址。
    fn read_link(&self, table: u64) -> u64 {
        if F::ENTRY_BYTES >= 8 {
            self.mem.read(table, 0)
        } else {
            self.mem.read(table, 0) | (self.mem.read(table, 1) << 32)
        }
    }

    /// 从另一张顶级表 `src_root` 复制下标区间 `top` 之外的全部顶级表项（共享同一批下级表）。
    /// Copy every top-level entry outside `top` from `src_root`, sharing the lower tables.
    pub fn adopt_top_except(&mut self, src_root: u64, top: Range<usize>) {
        for i in 0..Self::TOP_ENTRIES {
            if !top.contains(&i) {
                let e = self.mem.read(src_root, i);
                self.mem.write(self.root, i, e);
            }
        }
    }

    /// 回收顶级下标区间 `top` 下的全部**页表**帧并清空这些顶级表项，返回回收的表数。
    /// 叶子指向的数据帧不归还（由其所有者负责）；大页块只清除表项。
    /// Free every page-table frame below `top` (data frames stay with their owners).
    pub fn free_tables(&mut self, top: Range<usize>, frames: &mut dyn FrameAllocator) -> usize {
        let mut freed = 0;
        for i in top {
            let e = self.mem.read(self.root, i);
            if F::is_valid(e) && F::is_table(e) && F::LEVELS > 1 {
                freed += self.free_subtree(F::output_address(e), 1, frames);
            }
            self.mem.write(self.root, i, 0);
        }
        freed
    }

    /// 递归回收第 `level` 级的表 `table` 及其下级表（深度不超过 [`MAX_LEVELS`]）。
    fn free_subtree(&mut self, table: u64, level: usize, frames: &mut dyn FrameAllocator) -> usize {
        let mut freed = 0;
        if level < F::LEVELS - 1 {
            for i in 0..Self::ENTRIES {
                let e = self.mem.read(table, i);
                if F::is_valid(e) && F::is_table(e) {
                    freed += self.free_subtree(F::output_address(e), level + 1, frames);
                }
            }
        }
        if frames.deallocate(PhysFrame::from_number(table / FRAME_SIZE)).is_ok() {
            freed += 1;
        }
        freed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameError;
    use std::collections::{BTreeSet, HashMap};

    /// 测试用位格式：bit0 有效、bit1 指向下级表（非叶级）、bit2 可写、bit3 用户、bit4 可执行；地址在 [12, 48)。
    struct TestFormat;
    impl EntryFormat for TestFormat {
        const LEVELS: usize = 4;
        const VA_BITS: u32 = 47;
        fn is_valid(raw: u64) -> bool {
            raw & 1 != 0
        }
        fn is_table(raw: u64) -> bool {
            raw & 2 != 0
        }
        fn table_entry(p: u64) -> u64 {
            p | 3
        }
        fn leaf_entry(p: u64, f: MapFlags) -> u64 {
            let mut e = p | 1;
            if f.contains(MapFlags::WRITE) {
                e |= 4;
            }
            if f.contains(MapFlags::USER) {
                e |= 8;
            }
            if f.contains(MapFlags::EXECUTE) {
                e |= 16;
            }
            e
        }
        fn output_address(raw: u64) -> u64 {
            raw & 0x0000_ffff_ffff_f000
        }
        fn leaf_flags(raw: u64) -> MapFlags {
            let mut f = MapFlags::READ_ONLY;
            if raw & 4 != 0 {
                f = f | MapFlags::WRITE;
            }
            if raw & 8 != 0 {
                f = f | MapFlags::USER;
            }
            if raw & 16 != 0 {
                f = f | MapFlags::EXECUTE;
            }
            f
        }
    }

    /// 3 级、38 位（RISC-V Sv39 低半区的形状）：位格式与 [`TestFormat`] 相同，只改级数与地址位数。
    struct ThreeLevel;
    impl EntryFormat for ThreeLevel {
        const LEVELS: usize = 3;
        const VA_BITS: u32 = 38;
        fn is_valid(raw: u64) -> bool {
            TestFormat::is_valid(raw)
        }
        fn is_table(raw: u64) -> bool {
            TestFormat::is_table(raw)
        }
        fn table_entry(p: u64) -> u64 {
            TestFormat::table_entry(p)
        }
        fn leaf_entry(p: u64, f: MapFlags) -> u64 {
            TestFormat::leaf_entry(p, f)
        }
        fn output_address(raw: u64) -> u64 {
            TestFormat::output_address(raw)
        }
        fn leaf_flags(raw: u64) -> MapFlags {
            TestFormat::leaf_flags(raw)
        }
    }

    /// 模拟物理内存：按帧地址存放的表；`W` 为表项宽度（字节），4 字节表项写入超出 32 位的值即测试失败。
    #[derive(Default)]
    struct Mem<const W: usize>(HashMap<u64, Vec<u64>>);
    impl<const W: usize> TableMemory for &mut Mem<W> {
        const ENTRY_BYTES: usize = W;
        fn read(&self, t: u64, i: usize) -> u64 {
            self.0.get(&t).map(|x| x[i]).unwrap_or(0)
        }
        fn write(&mut self, t: u64, i: usize, raw: u64) {
            assert!(W >= 8 || raw >> 32 == 0, "4 字节表项写入了超出 32 位的值 {raw:#x}");
            self.0.entry(t).or_insert_with(|| vec![0; entries_per_table(W)])[i] = raw;
        }
        fn zero(&mut self, t: u64) {
            self.0.insert(t, vec![0; entries_per_table(W)]);
        }
    }

    /// 带上限的测试分配器：记录在用的帧，便于断言「无泄漏」。
    struct Frames {
        next: u64,
        limit: usize,
        live: BTreeSet<u64>,
    }
    impl Frames {
        fn new(limit: usize) -> Self {
            Self::starting_at(0x10_1000, limit)
        }
        fn starting_at(first: u64, limit: usize) -> Self {
            Frames { next: first - FRAME_SIZE, limit, live: BTreeSet::new() }
        }
    }
    impl FrameAllocator for Frames {
        fn allocate(&mut self) -> Result<PhysFrame, FrameError> {
            if self.live.len() >= self.limit {
                return Err(FrameError::OutOfFrames);
            }
            self.next += FRAME_SIZE;
            self.live.insert(self.next);
            Ok(PhysFrame::from_start(self.next).unwrap())
        }
        fn deallocate(&mut self, f: PhysFrame) -> Result<(), FrameError> {
            if self.live.remove(&f.start()) {
                Ok(())
            } else {
                Err(FrameError::DoubleFree)
            }
        }
        fn free_frames(&self) -> usize {
            self.limit - self.live.len()
        }
        fn usable_frames(&self) -> usize {
            self.limit
        }
    }

    type Pt<'a> = PageTable<TestFormat, &'a mut Mem<8>>;
    const ROOT: u64 = 0x1000;
    const DATA: u64 = 0x9000_0000;

    #[test]
    fn top_entries_follow_va_bits() {
        assert_eq!(Pt::TOP_ENTRIES, 256, "47 位 4 级 ⇒ 顶级 256 项");
    }

    #[test]
    fn map_translate_protect_unmap() {
        let mut mem = Mem::default();
        let mut frames = Frames::new(16);
        let mut pt = Pt::new(ROOT, &mut mem);
        let va = 0x1000_0000_0000u64 + 0x5000;
        let f = PhysFrame::from_start(DATA).unwrap();
        pt.map(va, f, MapFlags::WRITE | MapFlags::USER, &mut frames).unwrap();
        assert_eq!(frames.live.len(), 3, "新建 3 张下级表");
        assert_eq!(pt.translate(va + 0x123), Some((f, MapFlags::WRITE | MapFlags::USER)));
        assert_eq!(pt.translate(va + FRAME_SIZE), None);
        assert_eq!(pt.map(va, f, MapFlags::WRITE, &mut frames), Err(MapError::AlreadyMapped));
        pt.protect(va, MapFlags::EXECUTE).unwrap();
        assert_eq!(pt.translate(va), Some((f, MapFlags::EXECUTE)));
        assert_eq!(pt.unmap(va), Ok(f));
        assert_eq!(pt.unmap(va), Err(MapError::NotMapped));
        assert_eq!(pt.protect(va, MapFlags::WRITE), Err(MapError::NotMapped));
        assert_eq!(pt.translate(va), None);
        // 相邻页复用已有下级表，不再分配
        pt.map(va + FRAME_SIZE, f, MapFlags::READ_ONLY, &mut frames).unwrap();
        assert_eq!(frames.live.len(), 3);
        assert_eq!(pt.free_tables(32..64, &mut frames), 3);
        assert!(frames.live.is_empty(), "下级表全部回收");
        assert_eq!(pt.translate(va + FRAME_SIZE), None);
    }

    #[test]
    fn rejects_bad_addresses_without_changes() {
        let mut mem = Mem::default();
        let mut frames = Frames::new(16);
        let mut pt = Pt::new(ROOT, &mut mem);
        let f = PhysFrame::from_start(DATA).unwrap();
        assert_eq!(pt.map(0x8000_0000_0000, f, MapFlags::WRITE, &mut frames), Err(MapError::InvalidAddress), "超出 47 位");
        assert_eq!(pt.map(0x1001, f, MapFlags::WRITE, &mut frames), Err(MapError::InvalidAddress), "未对齐");
        assert_eq!(pt.unmap(u64::MAX - 0xfff), Err(MapError::InvalidAddress));
        assert_eq!(pt.translate(0xffff_8000_0000_0000), None);
        assert!(frames.live.is_empty());
        assert_eq!(pt.used_top(0..256), 0);
    }

    #[test]
    fn out_of_frames_rolls_back_new_tables() {
        let mut mem = Mem::default();
        let mut frames = Frames::new(2); // 需要 3 张下级表，只给 2 张
        let mut pt = Pt::new(ROOT, &mut mem);
        let f = PhysFrame::from_start(DATA).unwrap();
        assert_eq!(pt.map(0x2000_0000, f, MapFlags::WRITE, &mut frames), Err(MapError::OutOfFrames));
        assert!(frames.live.is_empty(), "新建的表全部归还");
        assert_eq!(pt.used_top(0..256), 0, "顶级表未被改动");
        // 已有的下级表不会在失败时被摘除
        let mut frames = Frames::new(3);
        pt.map(0x2000_0000, f, MapFlags::WRITE, &mut frames).unwrap();
        let before = frames.live.clone();
        assert_eq!(pt.map(0x40_0000_0000, f, MapFlags::WRITE, &mut frames), Err(MapError::OutOfFrames));
        assert_eq!(frames.live, before, "失败后在用的表与之前完全相同");
        assert_eq!(pt.translate(0x2000_0000).map(|x| x.0), Some(f), "原有映射不受影响");
    }

    #[test]
    fn huge_blocks_are_reported_not_split() {
        let mut mem = Mem::default();
        let mut frames = Frames::new(16);
        let mut pt = Pt::new(ROOT, &mut mem);
        // 顶级第 1 项指向一张下级表，其中第 0 项是有效但非表的大页块
        pt.mem.write(ROOT, 1, TestFormat::table_entry(0x5000));
        pt.mem.write(0x5000, 0, 0x4000_0000 | 1);
        let va = 1u64 << 39;
        let f = PhysFrame::from_start(DATA).unwrap();
        assert_eq!(pt.map(va, f, MapFlags::WRITE, &mut frames), Err(MapError::HugePage));
        assert_eq!(pt.unmap(va), Err(MapError::HugePage));
        assert_eq!(pt.protect(va, MapFlags::WRITE), Err(MapError::HugePage));
        assert_eq!(pt.translate(va), None);
        assert!(frames.live.is_empty());
        assert_eq!(pt.mem.read(0x5000, 0), 0x4000_0000 | 1, "大页块未被改动");
    }

    #[test]
    fn prealloc_is_all_or_nothing() {
        let mut mem = Mem::default();
        let mut pt = Pt::new(ROOT, &mut mem);
        pt.mem.write(ROOT, 130, TestFormat::table_entry(0x7000)); // 已占用一项
        let mut short = Frames::new(126); // 需要 127 帧
        assert_eq!(pt.prealloc_top(128..256, &mut short), Err(MapError::OutOfFrames));
        assert!(short.live.is_empty(), "失败时帧全部归还");
        assert_eq!(pt.used_top(128..256), 1, "顶级表未被改动");
        let mut enough = Frames::new(1000);
        assert_eq!(pt.prealloc_top(128..256, &mut enough), Ok(127));
        assert_eq!(pt.used_top(128..256), 128);
        assert_eq!(pt.used_top(0..128), 0);
        // 安装的下级表已清零（链表指针不残留）
        let first = TestFormat::output_address(pt.mem.read(ROOT, 128));
        assert_eq!(pt.mem.read(first, 0), 0);
        assert_eq!(pt.prealloc_top(128..256, &mut enough), Ok(0), "再次调用不重复安装");
        assert_eq!(pt.prealloc_top(0..257, &mut enough), Err(MapError::InvalidAddress));
    }

    #[test]
    fn adopt_shares_lower_tables_outside_window() {
        let mut mem = Mem::default();
        let mut frames = Frames::new(64);
        let f = PhysFrame::from_start(DATA).unwrap();
        {
            let mut kernel = Pt::new(ROOT, &mut mem);
            kernel.map(0x4444_4444_0000, f, MapFlags::WRITE, &mut frames).unwrap();
        }
        let mut space = Pt::new(0x2000, &mut mem);
        space.mem.zero(0x2000);
        space.adopt_top_except(ROOT, 32..64);
        assert_eq!(space.translate(0x4444_4444_0000).map(|x| x.0), Some(f), "窗口外共享内核映射");
        space.map(0x1000_0000_0000, f, MapFlags::USER, &mut frames).unwrap();
        let kernel = Pt::new(ROOT, &mut mem);
        assert_eq!(kernel.translate(0x1000_0000_0000), None, "窗口内的私有映射不外泄");
    }

    type Pt3<'a> = PageTable<ThreeLevel, &'a mut Mem<8>>;

    #[test]
    fn three_level_layout_maps_and_rejects() {
        assert_eq!(Pt3::TOP_ENTRIES, 256, "38 位 3 级 ⇒ 顶级 256 项（每项 1 GiB）");
        let mut mem = Mem::default();
        let mut frames = Frames::new(16);
        let mut pt = Pt3::new(ROOT, &mut mem);
        let f = PhysFrame::from_start(DATA).unwrap();
        let va = (32u64 << 30) + 0x1000_0000; // 私有窗口（顶级 32..64）内
        pt.map(va, f, MapFlags::WRITE | MapFlags::USER, &mut frames).unwrap();
        assert_eq!(frames.live.len(), 2, "3 级只新建 2 张下级表");
        assert_eq!(pt.translate(va), Some((f, MapFlags::WRITE | MapFlags::USER)));
        assert_eq!(pt.used_top(32..64), 1);
        // 失败路径：超出 38 位、未对齐 —— 拒绝且不分配、不改动
        assert_eq!(pt.map(1 << 38, f, MapFlags::WRITE, &mut frames), Err(MapError::InvalidAddress));
        assert_eq!(pt.map(va + 1, f, MapFlags::WRITE, &mut frames), Err(MapError::InvalidAddress));
        assert_eq!(frames.live.len(), 2);
        assert_eq!(pt.used_top(0..256), 1);
        assert_eq!(pt.unmap(va), Ok(f));
        assert_eq!(pt.free_tables(32..64, &mut frames), 2);
        assert!(frames.live.is_empty(), "下级表全部回收");
    }

    #[test]
    fn top_level_leaf_is_shared_but_never_split() {
        // 顶级第 64 项是 1 GiB 的叶子（全物理内存映射的形状）：遍历器只报告 HugePage，不改动它；复制时原样共享
        let mut mem = Mem::default();
        let mut frames = Frames::new(16);
        let gigapage = 0x4000_0000 | 1;
        {
            let mut kernel = Pt3::new(ROOT, &mut mem);
            kernel.mem.write(ROOT, 64, gigapage);
            let va = 64u64 << 30;
            let f = PhysFrame::from_start(DATA).unwrap();
            assert_eq!(kernel.map(va, f, MapFlags::WRITE, &mut frames), Err(MapError::HugePage));
            assert_eq!(kernel.unmap(va), Err(MapError::HugePage));
            assert_eq!(kernel.protect(va, MapFlags::READ_ONLY), Err(MapError::HugePage));
            assert!(frames.live.is_empty());
            assert_eq!(kernel.mem.read(ROOT, 64), gigapage, "大页未被改动");
            assert_eq!(kernel.used_top(64..128), 1);
        }
        let mut space = Pt3::new(0x2000, &mut mem);
        space.mem.zero(0x2000);
        space.adopt_top_except(ROOT, 32..64);
        assert_eq!(space.mem.read(0x2000, 64), gigapage, "窗口外的顶级叶子被原样共享");
        assert_eq!(space.used_top(32..64), 0, "私有窗口为空");
    }

    /// 2 级、32 位、每级 10 位下标、4 字节表项（RISC-V Sv32 的形状）：物理页号放在位 10 起（同 Sv32），
    /// 因此 32 位表项能表示 34 位物理地址；其余位与 [`TestFormat`] 相同。
    struct TwoLevel32;
    impl EntryFormat for TwoLevel32 {
        const LEVELS: usize = 2;
        const VA_BITS: u32 = 32;
        const INDEX_BITS: u32 = 10;
        const ENTRY_BYTES: usize = 4;
        fn is_valid(raw: u64) -> bool {
            TestFormat::is_valid(raw)
        }
        fn is_table(raw: u64) -> bool {
            TestFormat::is_table(raw)
        }
        fn table_entry(p: u64) -> u64 {
            ((p >> 12) << 10) | 3
        }
        fn leaf_entry(p: u64, f: MapFlags) -> u64 {
            TestFormat::leaf_entry(0, f) | ((p >> 12) << 10)
        }
        fn output_address(raw: u64) -> u64 {
            ((raw & 0xffff_ffff) >> 10) << 12
        }
        fn leaf_flags(raw: u64) -> MapFlags {
            TestFormat::leaf_flags(raw & 0x3ff)
        }
    }

    type Pt2<'a> = PageTable<TwoLevel32, &'a mut Mem<4>>;

    #[test]
    fn two_level_32bit_layout_maps_high_physical_frames() {
        assert_eq!(Pt2::TOP_ENTRIES, 1024, "32 位 2 级 ⇒ 顶级 1024 项（每项 4 MiB）");
        assert_eq!(Pt2::ENTRIES, 1024);
        let mut mem = Mem::<4>::default();
        // 页表帧与数据帧都在 4 GiB 之上（34 位物理地址）
        let mut frames = Frames::starting_at(0x3_0000_0000, 16);
        let mut pt = Pt2::new(ROOT, &mut mem);
        let f = PhysFrame::from_start(0x3_8765_4000).unwrap();
        let va = 0x0040_0000u64 + 0x5000; // 私有窗口（顶级 1..256）内
        pt.map(va, f, MapFlags::WRITE | MapFlags::USER, &mut frames).unwrap();
        assert_eq!(frames.live.len(), 1, "2 级只新建 1 张下级表");
        assert_eq!(pt.translate(va + 0x123), Some((f, MapFlags::WRITE | MapFlags::USER)), "34 位物理地址原样往返");
        assert_eq!(pt.used_top(1..256), 1);
        // 失败路径：超出 32 位、未对齐、重复映射 —— 拒绝且不分配、不改动
        assert_eq!(pt.map(1 << 32, f, MapFlags::WRITE, &mut frames), Err(MapError::InvalidAddress));
        assert_eq!(pt.map(va + 2, f, MapFlags::WRITE, &mut frames), Err(MapError::InvalidAddress));
        assert_eq!(pt.map(va, f, MapFlags::WRITE, &mut frames), Err(MapError::AlreadyMapped));
        assert_eq!(pt.translate(u64::MAX - 0xfff), None);
        assert_eq!(frames.live.len(), 1);
        assert_eq!(pt.used_top(0..1024), 1);
        assert_eq!(pt.unmap(va), Ok(f));
        assert_eq!(pt.free_tables(1..256, &mut frames), 1);
        assert!(frames.live.is_empty(), "下级表全部回收");
    }

    #[test]
    fn two_level_32bit_prealloc_links_frames_above_4gib() {
        let mut mem = Mem::<4>::default();
        let mut pt = Pt2::new(ROOT, &mut mem);
        // 帧跨越 4 GiB 边界：链表指针必须完整保存 34 位地址
        let mut short = Frames::starting_at(0xffff_e000, 127);
        assert_eq!(pt.prealloc_top(576..704, &mut short), Err(MapError::OutOfFrames));
        assert!(short.live.is_empty(), "失败时帧全部归还（含 4 GiB 之上的帧）");
        assert_eq!(pt.used_top(0..1024), 0, "顶级表未被改动");
        let mut enough = Frames::starting_at(0xffff_e000, 1000);
        assert_eq!(pt.prealloc_top(576..704, &mut enough), Ok(128));
        assert_eq!(pt.used_top(576..704), 128);
        let mut tables: Vec<u64> = (576..704).map(|i| TwoLevel32::output_address(pt.mem.read(ROOT, i))).collect();
        tables.sort();
        tables.dedup();
        assert_eq!(tables.len(), 128, "每项一张不同的下级表");
        assert!(tables.iter().any(|&t| t >= 1 << 32), "部分下级表位于 4 GiB 之上");
        assert!(tables.iter().all(|&t| enough.live.contains(&t)), "安装的都是本次分配的帧");
        for &t in &tables {
            assert_eq!((pt.mem.read(t, 0), pt.mem.read(t, 1)), (0, 0), "链表指针不残留");
        }
        assert_eq!(pt.prealloc_top(0..1025, &mut enough), Err(MapError::InvalidAddress));
    }
}
