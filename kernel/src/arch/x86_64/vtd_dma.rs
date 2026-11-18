//! Minimal runtime VT-d backend for opaque DMA mappings.
//!
//! 运行时 opaque DMA 映射的最小 VT-d 后端。The manager owns only translation
//! tables and invalidation registers; Memory ownership and bus-master
//! quiescence remain with the DMA object and Device lifecycle.

use alloc::vec::Vec;

use kernel_core::acpi::{self, DmarUnit};
use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::pci::Bdf;

use crate::sync::IrqSpinLock;
use crate::{boot, mm};

use super::smp;

const REG_CAP: u64 = 0x08;
const REG_ECAP: u64 = 0x10;
const REG_GCMD: u64 = 0x18;
const REG_GSTS: u64 = 0x1c;
const REG_RTADDR: u64 = 0x20;
const REG_CCMD: u64 = 0x28;

const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
const GCMD_WBF: u32 = 1 << 27;
const GSTS_TE: u32 = 1 << 31;
const GSTS_RTPS: u32 = 1 << 30;
const GSTS_WBF: u32 = 1 << 27;

const CCMD_ICC: u64 = 1 << 63;
const CCMD_GLOBAL: u64 = 1 << 61;
const TLB_IVT: u64 = 1 << 63;
const TLB_GLOBAL: u64 = 1 << 60;

const WAIT_SPINS: usize = 6_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    AmbiguousScope,
    Firmware,
    DeviceUnit,
    Range,
    Overlap,
    Capacity,
    Hardware,
    Stale,
}

impl Error {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unsupported => "system.iommu.error.unsupported",
            Self::AmbiguousScope => "system.iommu.error.ambiguous_scope",
            Self::Firmware => "system.iommu.error.firmware",
            Self::DeviceUnit => "system.iommu.error.device_unit",
            Self::Range => "system.iommu.error.range",
            Self::Overlap => "system.iommu.error.overlap",
            Self::Capacity => "system.iommu.error.capacity",
            Self::Hardware => "system.iommu.error.hardware",
            Self::Stale => "system.iommu.error.stale",
        }
    }
}

fn read32(reg: *mut u8, off: u64) -> u32 {
    // SAFETY: `reg` names the DMAR register window and callers use defined
    // offsets no larger than the firmware-declared register page.
    unsafe { ((reg as *const u8).add(off as usize) as *const u32).read_volatile() }
}

fn write32(reg: *mut u8, off: u64, value: u32) {
    // SAFETY: same window and alignment contract as `read32`.
    unsafe { ((reg as *mut u8).add(off as usize) as *mut u32).write_volatile(value) }
}

fn read64(reg: *mut u8, off: u64) -> u64 {
    // SAFETY: same window contract as `read32`; split register halves are
    // naturally aligned inside the VT-d unit.
    unsafe { ((reg as *const u8).add(off as usize) as *const u64).read_volatile() }
}

fn write64(reg: *mut u8, off: u64, value: u64) {
    // SAFETY: same window and alignment contract as `read64`.
    unsafe { ((reg as *mut u8).add(off as usize) as *mut u64).write_volatile(value) }
}

fn table(frame: PhysFrame) -> Result<*mut u8, Error> {
    mm::phys_to_virt(frame.start()).ok_or(Error::Hardware)
}

fn allocate_zeroed() -> Result<PhysFrame, Error> {
    let frame = mm::frame::allocate().map_err(|_| Error::Capacity)?;
    let pointer = table(frame)?;
    // SAFETY: the frame allocator handed this page exclusively to the manager.
    unsafe { core::ptr::write_bytes(pointer, 0, FRAME_SIZE as usize) };
    Ok(frame)
}

struct PageTable {
    index: usize,
    frame: PhysFrame,
}

struct Domain {
    bus: u8,
    sid: u8,
    id: u16,
    pdpt: PhysFrame,
    pd: PhysFrame,
    tables: Vec<PageTable>,
    pages: u64,
}

impl Domain {
    fn new(bus: u8, sid: u8, id: u16) -> Result<Self, Error> {
        let pdpt = allocate_zeroed()?;
        let pd = match allocate_zeroed() {
            Ok(frame) => frame,
            Err(error) => {
                let _ = mm::frame::deallocate(pdpt);
                return Err(error);
            }
        };
        Ok(Self {
            bus,
            sid,
            id,
            pdpt,
            pd,
            tables: Vec::new(),
            pages: 0,
        })
    }

    fn table_for(&self, pd_index: usize) -> Option<PhysFrame> {
        self.tables
            .iter()
            .find(|entry| entry.index == pd_index)
            .map(|entry| entry.frame)
    }

    fn page_table(&self, iova: u64) -> Result<Option<(usize, PhysFrame)>, Error> {
        let pd_index = ((iova >> 21) & 0x1ff) as usize;
        Ok(self.table_for(pd_index).map(|frame| (pd_index, frame)))
    }

    fn prepare_tables(&mut self, iova: u64, pages: u64) -> Result<Vec<usize>, Error> {
        let end = iova
            .checked_add(pages.checked_mul(FRAME_SIZE).ok_or(Error::Range)?)
            .ok_or(Error::Range)?;
        if iova >> 30 != (end - 1) >> 30 {
            return Err(Error::Range);
        }
        let first = ((iova >> 21) & 0x1ff) as usize;
        let last = (((end - 1) >> 21) & 0x1ff) as usize;
        let mut created = Vec::new();
        for pd_index in first..=last {
            if self.table_for(pd_index).is_some() {
                continue;
            }
            let frame = match allocate_zeroed() {
                Ok(frame) => frame,
                Err(error) => {
                    for index in created {
                        let entry = self
                            .tables
                            .iter()
                            .position(|table| table.index == index)
                            .expect("created page-table entry");
                        let table = self.tables.remove(entry);
                        let _ = mm::frame::deallocate(table.frame);
                    }
                    return Err(error);
                }
            };
            let pointer = table(frame)?;
            let pd = table(self.pd)?;
            // SAFETY: PD and PT pages are exclusively owned by this domain.
            unsafe {
                write64(pd, (pd_index * 8) as u64, frame.start() | 0x3);
                core::ptr::write_bytes(pointer, 0, FRAME_SIZE as usize);
            }
            self.tables.push(PageTable {
                index: pd_index,
                frame,
            });
            created.push(pd_index);
        }
        Ok(created)
    }

    fn check_empty(&self, iova: u64, pages: u64) -> Result<(), Error> {
        for page in 0..pages {
            let address = iova
                .checked_add(page.checked_mul(FRAME_SIZE).ok_or(Error::Range)?)
                .ok_or(Error::Range)?;
            if let Ok(Some((_, frame))) = self.page_table(address) {
                let pt = table(frame)?;
                let index = ((address >> 12) & 0x1ff) as usize;
                if read64(pt, (index * 8) as u64) & 1 != 0 {
                    return Err(Error::Overlap);
                }
            }
        }
        Ok(())
    }

    fn map(&mut self, iova: u64, frames: &[PhysFrame], writable: bool) -> Result<(), Error> {
        self.check_empty(iova, frames.len() as u64)?;
        self.prepare_tables(iova, frames.len() as u64)?;
        for (page, frame) in frames.iter().enumerate() {
            let address = iova + (page as u64) * FRAME_SIZE;
            let (_, pt) = self.page_table(address)?.ok_or(Error::Hardware)?;
            let pointer = table(pt)?;
            let index = ((address >> 12) & 0x1ff) as usize;
            let flags = if writable { 0x3 } else { 0x1 };
            // The PT page is exclusively owned and this PTE was verified empty
            // before any modification.
            let entry = frame.start() | flags;
            write64(pointer, (index * 8) as u64, entry);
            crate::kprintln!(
                "[JSR-IOMMU-DMA] pte iova=0x{:x} index={} entry=0x{:x}",
                address,
                index,
                entry
            );
        }
        self.pages = self
            .pages
            .checked_add(frames.len() as u64)
            .ok_or(Error::Capacity)?;
        Ok(())
    }

    fn translate(&self, iova: u64) -> Option<PhysFrame> {
        let (_, pt) = self.page_table(iova).ok()??;
        let pointer = table(pt).ok()?;
        let index = ((iova >> 12) & 0x1ff) as usize;
        let entry = read64(pointer, (index * 8) as u64);
        (entry & 1 != 0).then(|| PhysFrame::from_number((entry & !0xfff) / FRAME_SIZE))
    }

    fn release_tables(&mut self) {
        for entry in self.tables.drain(..) {
            let _ = mm::frame::deallocate(entry.frame);
        }
        let _ = mm::frame::deallocate(self.pd);
        let _ = mm::frame::deallocate(self.pdpt);
    }
}

struct Vtd {
    unit: DmarUnit,
    reg: *mut u8,
    cap: u64,
    tlb_reg: u64,
    root: Option<PhysFrame>,
    enabled: bool,
    contexts: Vec<(u8, PhysFrame)>,
    domains: Vec<Domain>,
    next_domain: u16,
}

// The register pointer is a stable direct-map address from firmware discovery,
// and the global manager serializes every access through an IrqSpinLock.
// 寄存器指针来自稳定直接映射，所有访问都由全局中断安全锁串行化。
unsafe impl Send for Vtd {}

/// All usable DMAR hardware units for the current platform.
///
/// 当前平台的可用 DMAR hardware unit 集合。Each requester must be claimed by
/// exactly one unit; a zero-match or overlapping scope is never resolved by
/// table order.
struct Units {
    dmar: acpi::Dmar,
    items: Vec<Vtd>,
}

impl Units {
    fn firmware() -> Result<Option<Self>, Error> {
        let Some(boot) = boot::get() else {
            return Ok(None);
        };
        let Some(offset) = boot.phys_offset else {
            return Ok(None);
        };
        let Some(rsdp) = boot.acpi_rsdp else {
            return Ok(None);
        };
        let dmar = match acpi::parse_dmar(&smp::PhysWindow(offset), rsdp) {
            Ok(dmar) => dmar,
            Err(acpi::AcpiError::NoDmar) => return Ok(None),
            Err(_) => return Err(Error::Firmware),
        };
        if dmar.dropped != 0 || dmar.units().is_empty() {
            return Err(Error::Firmware);
        }
        if dmar.units().iter().any(|unit| unit.segment != 0) {
            // The PCI object identifies a bus/device/function but no PCI
            // segment. Mapping a nonzero-segment scope onto segment zero
            // would select the wrong requester, so keep it unsupported.
            return Err(Error::Unsupported);
        }
        let mut items = Vec::new();
        items
            .try_reserve(dmar.units().len())
            .map_err(|_| Error::Capacity)?;
        for unit in dmar.units() {
            items.push(Vtd::new(*unit)?);
        }
        Ok(Some(Self {
            dmar,
            items,
        }))
    }

    fn select(&self, bdf: Bdf) -> Result<usize, Error> {
        self.dmar
            .unit_index_for_unique(0, bdf.bus(), bdf.device(), bdf.function())
            .map_err(|selection| match selection {
                acpi::DmarUnitSelection::Missing => Error::DeviceUnit,
                acpi::DmarUnitSelection::Ambiguous => Error::AmbiguousScope,
            })
    }
}

struct Manager {
    state: State,
}

enum State {
    Uninitialized,
    Disabled,
    Failed(Error),
    Ready(Units),
}

static MANAGER: IrqSpinLock<Manager> = IrqSpinLock::new(Manager {
    state: State::Uninitialized,
});

impl Vtd {
    fn new(unit: DmarUnit) -> Result<Self, Error> {
        let reg = mm::phys_to_virt(unit.register_base).ok_or(Error::Hardware)?;
        let cap = read64(reg, REG_CAP);
        let ecap = read64(reg, REG_ECAP);
        if read32(reg, 0) >> 4 != 1 || cap & (1 << 10) == 0 {
            return Err(Error::Unsupported);
        }
        // 4 KiB pages require a non-zero maximum address width below 48 bits.
        if (cap >> 34) & 0xf == 0 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            unit,
            reg,
            cap,
            tlb_reg: ((ecap >> 8) & 0x3ff) * 16,
            root: None,
            enabled: false,
            contexts: Vec::new(),
            domains: Vec::new(),
            next_domain: 1,
        })
    }

    fn units_match(&self, bdf: Bdf) -> bool {
        self.unit.covers(0, bdf.bus(), bdf.device(), bdf.function())
    }

    fn prepare(&mut self, bdf: Bdf) -> Result<(), Error> {
        if !self.units_match(bdf) {
            return Err(Error::DeviceUnit);
        }
        if self.root.is_some() {
            return Ok(());
        }
        if read32(self.reg, REG_GSTS) & GSTS_TE != 0 {
            return Err(Error::Hardware);
        }
        let root = allocate_zeroed()?;
        write64(self.reg, REG_RTADDR, root.start());
        self.root = Some(root);
        Ok(())
    }

    fn activate(&mut self, bdf: Bdf) -> Result<(), Error> {
        self.prepare(bdf)?;
        if self.enabled {
            return Ok(());
        }
        write32(self.reg, REG_GCMD, GCMD_SRTP);
        if !wait(|| read32(self.reg, REG_GSTS) & GSTS_RTPS != 0) {
            return Err(Error::Hardware);
        }
        write32(self.reg, REG_GCMD, GCMD_TE);
        if !wait(|| read32(self.reg, REG_GSTS) & GSTS_TE != 0) {
            write32(self.reg, REG_GCMD, 0);
            return Err(Error::Hardware);
        }
        self.enabled = true;
        Ok(())
    }

    fn context(&mut self, bus: u8) -> Result<PhysFrame, Error> {
        if let Some((_, frame)) = self.contexts.iter().find(|(entry, _)| *entry == bus) {
            return Ok(*frame);
        }
        let context = allocate_zeroed()?;
        let root = table(self.root.ok_or(Error::Stale)?)?;
        // The root page is exclusively owned by this manager.
        write64(root, u64::from(bus) * 16, context.start() | 1);
        self.contexts.push((bus, context));
        Ok(context)
    }

    fn domain(&mut self, bdf: Bdf) -> Result<usize, Error> {
        let sid = (bdf.device() << 3) | bdf.function();
        if let Some(index) = self
            .domains
            .iter()
            .position(|domain| domain.bus == bdf.bus() && domain.sid == sid)
        {
            return Ok(index);
        }
        let domain = Domain::new(bdf.bus(), sid, self.next_domain)?;
        self.next_domain = self.next_domain.checked_add(1).ok_or(Error::Capacity)?;
        self.domains.push(domain);
        let index = self.domains.len() - 1;
        let context = self.context(bdf.bus())?;
        let domain = &self.domains[index];
        let context_pointer = table(context)?;
        // Context tables are exclusively owned and each SID is inserted once.
        write64(
            context_pointer,
            u64::from(sid) * 16,
            domain.pdpt.start() | 1,
        );
        write64(
            context_pointer,
            u64::from(sid) * 16 + 8,
            (u64::from(domain.id) << 8) | 1,
        );
        // Write permission must be present on every second-level table entry.
        // 第二级页表的每一层都必须具备写权限，否则设备能读描述符但不能写
        // used ring 或数据缓冲区。
        write64(table(domain.pdpt)?, 0, domain.pd.start() | 0x3);
        Ok(index)
    }

    fn invalidate(&self) {
        if self.cap & (1 << 4) != 0 {
            write32(self.reg, REG_GCMD, GCMD_WBF);
            let _ = wait(|| read32(self.reg, REG_GSTS) & GSTS_WBF == 0);
        }
        write64(self.reg, REG_CCMD, CCMD_ICC | CCMD_GLOBAL);
        let _ = wait(|| read64(self.reg, REG_CCMD) & CCMD_ICC == 0);
        write64(self.reg, self.tlb_reg + 8, TLB_IVT | TLB_GLOBAL);
        let _ = wait(|| read64(self.reg, self.tlb_reg + 8) & TLB_IVT == 0);
    }

    fn map(
        &mut self,
        bdf: Bdf,
        iova: u64,
        frames: &[PhysFrame],
        writable: bool,
    ) -> Result<(), Error> {
        crate::kprintln!(
            "[JSR-IOMMU-DMA] map iova=0x{:x} pages={} writable={}",
            iova,
            frames.len(),
            writable
        );
        let bytes = (frames.len() as u64)
            .checked_mul(FRAME_SIZE)
            .ok_or(Error::Range)?;
        if frames.is_empty()
            || iova == 0
            || iova % FRAME_SIZE != 0
            || iova
                .checked_add(bytes)
                .is_none_or(|end| end > (1u64 << 30))
        {
            return Err(Error::Range);
        }
        self.prepare(bdf)?;
        let index = self.domain(bdf)?;
        self.domains[index].map(iova, frames, writable)?;
        self.activate(bdf)?;
        self.invalidate();
        Ok(())
    }

    fn translate(&mut self, bdf: Bdf, iova: u64) -> Result<Option<PhysFrame>, Error> {
        if !self.units_match(bdf) {
            return Err(Error::DeviceUnit);
        }
        let sid = (bdf.device() << 3) | bdf.function();
        Ok(self
            .domains
            .iter()
            .find(|domain| domain.bus == bdf.bus() && domain.sid == sid)
            .and_then(|domain| domain.translate(iova)))
    }

    fn release_if_empty(&mut self) -> Result<(), Error> {
        if self.domains.iter().any(|domain| domain.pages != 0) {
            return Ok(());
        }
        let buses: Vec<u8> = self.domains.iter().map(|domain| domain.bus).collect();
        let root = self.root;
        if root.is_some() {
            write32(self.reg, REG_GCMD, 0);
            let _ = wait(|| read32(self.reg, REG_GSTS) & GSTS_TE == 0);
            write64(self.reg, REG_RTADDR, 0);
            self.enabled = false;
            self.invalidate();
        }
        for domain in &mut self.domains {
            domain.release_tables();
        }
        self.domains.clear();
        if let Some(root) = root {
            let root_pointer = table(root)?;
            for bus in buses {
                if !self.contexts.iter().any(|(entry, _)| *entry == bus) {
                    continue;
                }
                if let Some(position) = self.contexts.iter().position(|(entry, _)| *entry == bus) {
                    let (_, context) = self.contexts.remove(position);
                    // The root and context pages are exclusively owned.
                    write64(root_pointer, u64::from(bus) * 16, 0);
                    let _ = mm::frame::deallocate(context);
                }
            }
            let _ = mm::frame::deallocate(root);
            self.root = None;
        }
        Ok(())
    }

    fn unmap(&mut self, bdf: Bdf, iova: u64, pages: u64) -> Result<(), Error> {
        let sid = (bdf.device() << 3) | bdf.function();
        let index = self
            .domains
            .iter()
            .position(|domain| domain.bus == bdf.bus() && domain.sid == sid)
            .ok_or(Error::Stale)?;
        for page in 0..pages {
            let address = iova + page * FRAME_SIZE;
            let Some((_, pt)) = self.domains[index].page_table(address)? else {
                return Err(Error::Stale);
            };
            let pointer = table(pt)?;
            let pte = ((address >> 12) & 0x1ff) as usize;
            if read64(pointer, (pte * 8) as u64) & 1 == 0 {
                return Err(Error::Stale);
            }
        }
        for page in 0..pages {
            let address = iova + page * FRAME_SIZE;
            let (_, pt) = self.domains[index]
                .page_table(address)?
                .ok_or(Error::Stale)?;
            let pointer = table(pt)?;
            let pte = ((address >> 12) & 0x1ff) as usize;
            // This PTE belongs to the requested live mapping.
            write64(pointer, (pte * 8) as u64, 0);
        }
        self.domains[index].pages = self.domains[index].pages.saturating_sub(pages);
        self.invalidate();
        self.release_if_empty()
    }
}

fn wait(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..WAIT_SPINS {
        if condition() {
            return true;
        }
        core::hint::spin_loop();
    }
    condition()
}

fn ensure(manager: &mut Manager, bdf: Bdf) -> Result<bool, Error> {
    if matches!(manager.state, State::Uninitialized) {
        manager.state = match Units::firmware() {
            Ok(Some(units)) => State::Ready(units),
            Ok(None) => State::Disabled,
            Err(error) => State::Failed(error),
        };
    }
    match &mut manager.state {
        State::Uninitialized => Err(Error::Hardware),
        State::Disabled => Ok(false),
        State::Failed(error) => Err(*error),
        State::Ready(units) => {
            units.select(bdf)?;
            Ok(true)
        }
    }
}

pub fn map(bdf: Bdf, iova: u64, frames: &[PhysFrame], writable: bool) -> Result<bool, Error> {
    let mut manager = MANAGER.lock();
    if !ensure(&mut manager, bdf)? {
        return Ok(false);
    }
    let State::Ready(units) = &mut manager.state else {
        return Err(Error::Hardware);
    };
    let index = units.select(bdf)?;
    let vtd = &mut units.items[index];
    if let Err(error) = vtd.map(bdf, iova, frames, writable) {
        crate::kprintln!("[JSR-IOMMU-DMA] map_error={}", error.name());
        let _ = vtd.release_if_empty();
        return Err(error);
    }
    Ok(true)
}

pub fn translate(bdf: Bdf, iova: u64) -> Result<Option<PhysFrame>, Error> {
    let mut manager = MANAGER.lock();
    match &mut manager.state {
        State::Uninitialized | State::Disabled => Ok(None),
        State::Failed(error) => Err(*error),
        State::Ready(units) => {
            let index = units.select(bdf)?;
            let vtd = &mut units.items[index];
            if vtd.root.is_some() {
                vtd.translate(bdf, iova)
            } else {
                Ok(None)
            }
        }
    }
}

pub fn unmap(bdf: Bdf, iova: u64, pages: u64) -> Result<(), Error> {
    let mut manager = MANAGER.lock();
    let State::Ready(units) = &mut manager.state else {
        return Err(Error::Stale);
    };
    let index = units.select(bdf)?;
    let vtd = &mut units.items[index];
    vtd.unmap(bdf, iova, pages)
}
