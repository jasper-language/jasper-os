//! AMD SVM execution backend for HWV-3.
//!
//! This module owns the architectural VMCB, HSAVE page, I/O permission map and
//! MSR permission map. It consumes the NPT root produced by HWV-1 and enters a
//! guest only on a real AMD processor. Non-AMD hosts can still exercise the
//! fixed VMCB layout and NPT/intercept contract, but never receive a simulated
//! `VMRUN` success.

use core::arch::{asm, global_asm};
use core::ptr;

use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::hwvirt_vcpu::VcpuState;

use crate::kprintln;

macro_rules! const_assert {
    ($condition:expr) => {
        const _: () = assert!($condition);
    };
}

const IA32_PAT: u32 = 0x277;
const IA32_EFER: u32 = 0xC000_0080;
const MSR_VM_CR: u32 = 0xC001_0114;
const MSR_VM_HSAVE_PA: u32 = 0xC001_0117;

const EFER_SVME: u64 = 1 << 12;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const SVM_VM_CR_SVM_DIS: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;

const VMCB_SIZE: usize = 4096;
const VMCB_CONTROL_SIZE: usize = 1024;
const VMCB_SAVE_OFFSET: usize = 0x400;
const VMCB_SAVE_SIZE: usize = 744;

const CONTROL_INTERCEPTS: usize = 0x000;
const CONTROL_IOPM_BASE: usize = 0x040;
const CONTROL_MSRPM_BASE: usize = 0x048;
const CONTROL_TSC_OFFSET: usize = 0x050;
const CONTROL_ASID: usize = 0x058;
const CONTROL_TLB_CONTROL: usize = 0x05c;
const CONTROL_INT_CTL: usize = 0x060;
const CONTROL_EXIT_CODE: usize = 0x070;
const CONTROL_EXIT_INFO_1: usize = 0x078;
const CONTROL_EXIT_INFO_2: usize = 0x080;
const CONTROL_MISC_CTL: usize = 0x090;
const CONTROL_NESTED_CR3: usize = 0x0b0;
const CONTROL_CLEAN: usize = 0x0c0;
const CONTROL_NEXT_RIP: usize = 0x0c8;

const SAVE_ES: usize = VMCB_SAVE_OFFSET;
const SAVE_CS: usize = VMCB_SAVE_OFFSET + 0x10;
const SAVE_SS: usize = VMCB_SAVE_OFFSET + 0x20;
const SAVE_DS: usize = VMCB_SAVE_OFFSET + 0x30;
const SAVE_FS: usize = VMCB_SAVE_OFFSET + 0x40;
const SAVE_GS: usize = VMCB_SAVE_OFFSET + 0x50;
const SAVE_GDTR: usize = VMCB_SAVE_OFFSET + 0x60;
const SAVE_LDTR: usize = VMCB_SAVE_OFFSET + 0x70;
const SAVE_IDTR: usize = VMCB_SAVE_OFFSET + 0x80;
const SAVE_TR: usize = VMCB_SAVE_OFFSET + 0x90;
const SAVE_CPL: usize = 0x4cb;
const SAVE_EFER: usize = 0x4d0;
const SAVE_CR4: usize = 0x548;
const SAVE_CR3: usize = 0x550;
const SAVE_CR0: usize = 0x558;
const SAVE_DR7: usize = 0x560;
const SAVE_DR6: usize = 0x568;
const SAVE_RFLAGS: usize = 0x570;
const SAVE_RIP: usize = 0x578;
const SAVE_RSP: usize = 0x5d8;
const SAVE_RAX: usize = 0x5f8;
const SAVE_CR2: usize = 0x640;
const SAVE_PAT: usize = 0x668;

const INTERCEPT_INTR: u32 = 1 << 0;
const INTERCEPT_NMI: u32 = 1 << 1;
const INTERCEPT_RDTSC: u32 = 1 << 14;
const INTERCEPT_CPUID: u32 = 1 << 18;
const INTERCEPT_HLT: u32 = 1 << 25;
const INTERCEPT_IO: u32 = 1 << 27;
const INTERCEPT_MSR: u32 = 1 << 28;
const INTERCEPT_SHUTDOWN: u32 = 1 << 31;
const INTERCEPT_VMRUN: u32 = 1 << 0;
const INTERCEPT_VMMCALL: u32 = 1 << 1;
const INTERCEPT_VMLOAD: u32 = 1 << 2;
const INTERCEPT_VMSAVE: u32 = 1 << 3;
const INTERCEPT_STGI: u32 = 1 << 4;
const INTERCEPT_CLGI: u32 = 1 << 5;
const INTERCEPT_SKINIT: u32 = 1 << 6;
const INTERCEPT_RDTSCP: u32 = 1 << 7;
const INTERCEPT_ICEBP: u32 = 1 << 8;
const INTERCEPT_WBINVD: u32 = 1 << 9;
const INTERCEPT_XSETBV: u32 = 1 << 13;

const EXCEPTION_UD: u32 = 1 << 6;

const MISC_ENABLE_NP: u64 = 1;
const INT_MASKING: u32 = 1 << 24;
const TLB_FLUSH_ALL_ASID: u8 = 1;

const SVM_EXIT_UD: u64 = 0x046;
const SVM_EXIT_RDTSC: u64 = 0x06e;
const SVM_EXIT_CPUID: u64 = 0x072;
const SVM_EXIT_HLT: u64 = 0x078;
const SVM_EXIT_IO: u64 = 0x07b;
const SVM_EXIT_MSR: u64 = 0x07c;
const SVM_EXIT_SHUTDOWN: u64 = 0x07f;
const SVM_EXIT_NPF: u64 = 0x400;

const IOIO_TYPE_IN: u64 = 1;
const IOIO_SIZE_SHIFT: u64 = 4;
const IOIO_SIZE_MASK: u64 = 7 << IOIO_SIZE_SHIFT;
const IOIO_PORT_SHIFT: u64 = 16;

const SEGMENT_DATA: u16 = 0x0092;
const SEGMENT_CODE_64: u16 = 0x029a;
const SEGMENT_LDT: u16 = 0x0082;
const SEGMENT_TR: u16 = 0x008b;

const_assert!(VMCB_SAVE_OFFSET + VMCB_SAVE_SIZE == 0x6e8);
const_assert!(SAVE_CPL == 0x4cb);
const_assert!(SAVE_EFER == 0x4d0);
const_assert!(SAVE_CR4 == 0x548);
const_assert!(SAVE_CR3 == 0x550);
const_assert!(SAVE_CR0 == 0x558);
const_assert!(SAVE_RFLAGS == 0x570);
const_assert!(SAVE_RIP == 0x578);
const_assert!(SAVE_CR2 == 0x640);
const_assert!(SAVE_PAT == 0x668);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvmError {
    CpuUnsupported,
    SvmDisabled,
    MissingNpt,
    MissingPhysicalMap,
    OutOfFrames,
    InvalidState { code: u64 },
    TooManyExits,
    UnknownExit { code: u64 },
}

impl SvmError {
    pub const fn name(self) -> &'static str {
        match self {
            SvmError::CpuUnsupported => "hwvirt.svm.error.cpu_unsupported",
            SvmError::SvmDisabled => "hwvirt.svm.error.svm_disabled",
            SvmError::MissingNpt => "hwvirt.svm.error.missing_npt",
            SvmError::MissingPhysicalMap => "hwvirt.svm.error.missing_physical_map",
            SvmError::OutOfFrames => "hwvirt.svm.error.out_of_frames",
            SvmError::InvalidState { .. } => "hwvirt.svm.error.invalid_state",
            SvmError::TooManyExits => "hwvirt.svm.error.too_many_exits",
            SvmError::UnknownExit { .. } => "hwvirt.svm.error.unknown_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SvmFeatures {
    pub revision: u8,
    pub asid_count: u32,
    pub ecx: u32,
    pub npt: bool,
    pub nrips: bool,
    pub decode_assists: bool,
}

#[derive(Clone, Copy)]
pub struct GuestExecutionState {
    pub state: VcpuState,
    pub rsp: u64,
    pub cr3_gpa: u64,
    pub efer: u64,
    pub tsc_offset: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunReport {
    pub exits: u32,
    pub cpuid: u32,
    pub rdtsc: u32,
    pub msr_reads: u32,
    pub io: u32,
    pub npf_violations: u32,
    pub exceptions: u32,
    pub halted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractReport {
    pub vmcb_size: usize,
    pub control_size: usize,
    pub save_offset: usize,
    pub save_size: usize,
    pub nested_cr3: u64,
    pub npt_enabled: bool,
    pub all_io_intercepted: bool,
    pub all_msr_intercepted: bool,
    pub control_valid: bool,
    pub guest_state_valid: bool,
    pub gprs: [u64; 16],
}

struct Region {
    frame: PhysFrame,
}

impl Region {
    fn allocate_zeroed(fill: u8) -> Result<Self, SvmError> {
        let frame = crate::mm::frame::allocate().map_err(|_| SvmError::OutOfFrames)?;
        let Some(mapped) = crate::mm::phys_to_virt(frame.start()) else {
            let _ = crate::mm::frame::deallocate(frame);
            return Err(SvmError::MissingPhysicalMap);
        };
        // SAFETY: the frame was just allocated and is not published elsewhere.
        unsafe { ptr::write_bytes(mapped, fill, FRAME_SIZE as usize) };
        Ok(Self { frame })
    }

    fn physical(&self) -> u64 {
        self.frame.start()
    }

    fn mapped(&self) -> Result<*mut u8, SvmError> {
        crate::mm::phys_to_virt(self.physical()).ok_or(SvmError::MissingPhysicalMap)
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        let _ = crate::mm::frame::deallocate(self.frame);
    }
}

struct ContiguousRegion {
    base: PhysFrame,
    pages: usize,
}

impl ContiguousRegion {
    fn allocate_zeroed(pages: usize, fill: u8) -> Result<Self, SvmError> {
        let base =
            crate::mm::frame::allocate_contiguous(pages).map_err(|_| SvmError::OutOfFrames)?;
        let Some(mapped) = crate::mm::phys_to_virt(base.start()) else {
            let _ = crate::mm::frame::deallocate_contiguous(base, pages);
            return Err(SvmError::MissingPhysicalMap);
        };
        // SAFETY: the contiguous run was just allocated, is not published, and
        // the full-physical map covers every page in it.
        unsafe { ptr::write_bytes(mapped, fill, pages * FRAME_SIZE as usize) };
        Ok(Self { base, pages })
    }

    fn physical(&self) -> u64 {
        self.base.start()
    }

    fn all_bytes(&self, expected: u8) -> bool {
        let Some(mapped) = crate::mm::phys_to_virt(self.physical()) else {
            return false;
        };
        for offset in 0..self.pages * FRAME_SIZE as usize {
            // SAFETY: the whole contiguous region is owned by this object.
            if unsafe { mapped.add(offset).read_volatile() } != expected {
                return false;
            }
        }
        true
    }
}

impl Drop for ContiguousRegion {
    fn drop(&mut self) {
        let _ = crate::mm::frame::deallocate_contiguous(self.base, self.pages);
    }
}

struct Vmcb {
    region: Region,
}

impl Vmcb {
    fn new() -> Result<Self, SvmError> {
        Ok(Self {
            region: Region::allocate_zeroed(0)?,
        })
    }

    fn physical(&self) -> u64 {
        self.region.physical()
    }

    fn write_u8(&mut self, offset: usize, value: u8) {
        assert!(offset < VMCB_SIZE);
        let mapped = self.region.mapped().expect("VMCB physical map");
        // SAFETY: fixed in-page offset, and VMCB is exclusively owned.
        unsafe { mapped.add(offset).write_volatile(value) };
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        assert!(offset + 2 <= VMCB_SIZE);
        let mapped = self.region.mapped().expect("VMCB physical map");
        // SAFETY: fixed in-page, naturally aligned volatile write.
        unsafe { (mapped.add(offset) as *mut u16).write_volatile(value) };
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        assert!(offset + 4 <= VMCB_SIZE);
        let mapped = self.region.mapped().expect("VMCB physical map");
        // SAFETY: fixed in-page, naturally aligned volatile write.
        unsafe { (mapped.add(offset) as *mut u32).write_volatile(value) };
    }

    fn write_u64(&mut self, offset: usize, value: u64) {
        assert!(offset + 8 <= VMCB_SIZE);
        let mapped = self.region.mapped().expect("VMCB physical map");
        // SAFETY: fixed in-page, naturally aligned volatile write.
        unsafe { (mapped.add(offset) as *mut u64).write_volatile(value) };
    }

    fn read_u8(&self, offset: usize) -> u8 {
        assert!(offset < VMCB_SIZE);
        let mapped = self.region.mapped().expect("VMCB physical map");
        // SAFETY: fixed in-page volatile read.
        unsafe { mapped.add(offset).read_volatile() }
    }

    fn read_u16(&self, offset: usize) -> u16 {
        assert!(offset + 2 <= VMCB_SIZE);
        let mapped = self.region.mapped().expect("VMCB physical map");
        // SAFETY: fixed in-page, naturally aligned volatile read.
        unsafe { (mapped.add(offset) as *const u16).read_volatile() }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        assert!(offset + 4 <= VMCB_SIZE);
        let mapped = self.region.mapped().expect("VMCB physical map");
        // SAFETY: fixed in-page, naturally aligned volatile read.
        unsafe { (mapped.add(offset) as *const u32).read_volatile() }
    }

    fn read_u64(&self, offset: usize) -> u64 {
        assert!(offset + 8 <= VMCB_SIZE);
        let mapped = self.region.mapped().expect("VMCB physical map");
        // SAFETY: fixed in-page, naturally aligned volatile read.
        unsafe { (mapped.add(offset) as *const u64).read_volatile() }
    }

    fn write_segment(&mut self, offset: usize, selector: u16, attrib: u16, limit: u32, base: u64) {
        self.write_u16(offset, selector);
        self.write_u16(offset + 2, attrib);
        self.write_u32(offset + 4, limit);
        self.write_u64(offset + 8, base);
    }

    fn write_guest_state(
        &mut self,
        npt_root: u64,
        guest: GuestExecutionState,
        iopm: u64,
        msrpm: u64,
        pat: u64,
    ) -> Result<(), SvmError> {
        if npt_root & 0xfff != 0 || guest.cr3_gpa & 0xfff != 0 {
            return Err(SvmError::InvalidState {
                code: npt_root ^ guest.cr3_gpa,
            });
        }
        let guest_efer = guest.efer | EFER_SVME;
        if guest.state.cr0 & 0x8000_0001 != 0x8000_0001
            || guest.state.cr4 & (1 << 5) == 0
            || guest_efer & (EFER_LME | EFER_LMA) != EFER_LME | EFER_LMA
            || !canonical(guest.state.rip)
            || !canonical(guest.rsp)
        {
            return Err(SvmError::InvalidState {
                code: guest.state.cr0 ^ guest.state.cr4 ^ guest_efer ^ guest.state.rip ^ guest.rsp,
            });
        }

        self.write_u32(CONTROL_INTERCEPTS + 8, EXCEPTION_UD);
        self.write_u32(
            CONTROL_INTERCEPTS + 12,
            INTERCEPT_INTR
                | INTERCEPT_NMI
                | INTERCEPT_RDTSC
                | INTERCEPT_CPUID
                | INTERCEPT_HLT
                | INTERCEPT_IO
                | INTERCEPT_MSR
                | INTERCEPT_SHUTDOWN,
        );
        self.write_u32(
            CONTROL_INTERCEPTS + 16,
            INTERCEPT_VMRUN
                | INTERCEPT_VMMCALL
                | INTERCEPT_VMLOAD
                | INTERCEPT_VMSAVE
                | INTERCEPT_STGI
                | INTERCEPT_CLGI
                | INTERCEPT_SKINIT
                | INTERCEPT_RDTSCP
                | INTERCEPT_ICEBP
                | INTERCEPT_WBINVD
                | INTERCEPT_XSETBV,
        );
        self.write_u64(CONTROL_IOPM_BASE, iopm);
        self.write_u64(CONTROL_MSRPM_BASE, msrpm);
        self.write_u64(CONTROL_TSC_OFFSET, guest.tsc_offset as u64);
        self.write_u32(CONTROL_ASID, 1);
        self.write_u8(CONTROL_TLB_CONTROL, TLB_FLUSH_ALL_ASID);
        self.write_u32(CONTROL_INT_CTL, INT_MASKING);
        self.write_u64(CONTROL_MISC_CTL, MISC_ENABLE_NP);
        self.write_u64(CONTROL_NESTED_CR3, npt_root);
        self.write_u32(CONTROL_CLEAN, 0);

        for segment in [SAVE_ES, SAVE_SS, SAVE_DS, SAVE_FS, SAVE_GS] {
            self.write_segment(segment, 0, SEGMENT_DATA, 0xffff_ffff, 0);
        }
        self.write_segment(SAVE_CS, 0x8, SEGMENT_CODE_64, 0xffff_ffff, 0);
        self.write_segment(SAVE_GDTR, 0, 0, 0xffff, 0);
        self.write_segment(SAVE_IDTR, 0, 0, 0xffff, 0);
        self.write_segment(SAVE_LDTR, 0, SEGMENT_LDT, 0xffff, 0);
        self.write_segment(SAVE_TR, 0, SEGMENT_TR, 0x67, 0);
        self.write_u8(SAVE_CPL, 0);
        self.write_u64(SAVE_EFER, guest_efer);
        self.write_u64(SAVE_CR4, guest.state.cr4);
        self.write_u64(SAVE_CR3, guest.cr3_gpa);
        self.write_u64(SAVE_CR0, guest.state.cr0);
        self.write_u64(SAVE_DR7, 0);
        self.write_u64(SAVE_DR6, 0xffff_0ff0);
        self.write_u64(SAVE_RFLAGS, guest.state.rflags | 2);
        self.write_u64(SAVE_RIP, guest.state.rip);
        self.write_u64(SAVE_RSP, guest.rsp);
        self.write_u64(SAVE_RAX, guest.state.registers[0]);
        self.write_u64(SAVE_CR2, 0);
        self.write_u64(SAVE_PAT, pat);
        Ok(())
    }
}

struct Resources {
    vmcb: Vmcb,
    hsave: Region,
    iopm: ContiguousRegion,
    msrpm: ContiguousRegion,
}

impl Resources {
    fn new() -> Result<Self, SvmError> {
        Ok(Self {
            vmcb: Vmcb::new()?,
            hsave: Region::allocate_zeroed(0)?,
            iopm: ContiguousRegion::allocate_zeroed(3, 0xff)?,
            msrpm: ContiguousRegion::allocate_zeroed(2, 0xff)?,
        })
    }

    fn iopm(&self) -> u64 {
        self.iopm.physical()
    }

    fn msrpm(&self) -> u64 {
        self.msrpm.physical()
    }

    fn hsave(&self) -> u64 {
        self.hsave.physical()
    }
}

pub fn features() -> Result<SvmFeatures, SvmError> {
    let leaf0 = core::arch::x86_64::__cpuid(0);
    let amd = leaf0.ebx == u32::from_le_bytes(*b"Auth")
        && leaf0.edx == u32::from_le_bytes(*b"enti")
        && leaf0.ecx == u32::from_le_bytes(*b"cAMD");
    if !amd {
        return Err(SvmError::CpuUnsupported);
    }
    let ext_max = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    if ext_max < 0x8000_000a {
        return Err(SvmError::CpuUnsupported);
    }
    let ext1 = core::arch::x86_64::__cpuid(0x8000_0001);
    if ext1.ecx & (1 << 2) == 0 {
        return Err(SvmError::CpuUnsupported);
    }
    let leaf = core::arch::x86_64::__cpuid(0x8000_000a);
    Ok(SvmFeatures {
        revision: leaf.eax as u8,
        asid_count: leaf.ebx,
        ecx: leaf.ecx,
        npt: leaf.ecx & (1 << 0) != 0,
        nrips: leaf.ecx & (1 << 3) != 0,
        decode_assists: leaf.ecx & (1 << 7) != 0,
    })
}

pub fn contract_check(
    npt_root: u64,
    guest: GuestExecutionState,
) -> Result<ContractReport, SvmError> {
    if npt_root & 0xfff != 0 {
        return Err(SvmError::InvalidState { code: npt_root });
    }
    let mut resources = Resources::new()?;
    resources.vmcb.write_guest_state(
        npt_root,
        guest,
        resources.iopm(),
        resources.msrpm(),
        0x0007_0406_0007_0406,
    )?;
    let nested_cr3 = resources.vmcb.read_u64(CONTROL_NESTED_CR3);
    let npt_enabled = resources.vmcb.read_u64(CONTROL_MISC_CTL) & MISC_ENABLE_NP != 0;
    let control_valid = resources.vmcb.read_u32(CONTROL_INTERCEPTS + 8) == EXCEPTION_UD
        && resources.vmcb.read_u32(CONTROL_INTERCEPTS + 12)
            & (INTERCEPT_RDTSC
                | INTERCEPT_CPUID
                | INTERCEPT_IO
                | INTERCEPT_MSR
                | INTERCEPT_SHUTDOWN)
            == (INTERCEPT_RDTSC
                | INTERCEPT_CPUID
                | INTERCEPT_IO
                | INTERCEPT_MSR
                | INTERCEPT_SHUTDOWN)
        && resources.vmcb.read_u32(CONTROL_INTERCEPTS + 16) & INTERCEPT_VMRUN != 0
        && resources.vmcb.read_u64(CONTROL_IOPM_BASE) == resources.iopm()
        && resources.vmcb.read_u64(CONTROL_MSRPM_BASE) == resources.msrpm()
        && resources.vmcb.read_u32(CONTROL_ASID) == 1;
    let guest_state_valid = resources.vmcb.read_u64(CONTROL_NESTED_CR3) == npt_root
        && resources.vmcb.read_u64(SAVE_EFER) == guest.efer | EFER_SVME
        && resources.vmcb.read_u64(SAVE_CR3) == guest.cr3_gpa
        && resources.vmcb.read_u64(SAVE_RIP) == guest.state.rip
        && resources.vmcb.read_u64(SAVE_RSP) == guest.rsp
        && resources.vmcb.read_u64(SAVE_RAX) == guest.state.registers[0]
        && resources.vmcb.read_u8(SAVE_CPL) == 0
        && resources.vmcb.read_u16(SAVE_CS + 2) == SEGMENT_CODE_64
        && resources.vmcb.read_u16(SAVE_SS + 2) == SEGMENT_DATA;
    if nested_cr3 != npt_root || !npt_enabled || !control_valid || !guest_state_valid {
        return Err(SvmError::InvalidState {
            code: nested_cr3 ^ npt_root,
        });
    }
    Ok(ContractReport {
        vmcb_size: VMCB_SIZE,
        control_size: VMCB_CONTROL_SIZE,
        save_offset: VMCB_SAVE_OFFSET,
        save_size: VMCB_SAVE_SIZE,
        nested_cr3,
        npt_enabled,
        all_io_intercepted: resources.iopm.all_bytes(0xff),
        all_msr_intercepted: resources.msrpm.all_bytes(0xff),
        control_valid,
        guest_state_valid,
        gprs: guest.state.registers[..16]
            .try_into()
            .expect("16-register contract"),
    })
}

#[derive(Clone, Copy)]
struct HostSvm {
    old_efer: u64,
    old_hsave: u64,
    cr0_ne_added: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSnapshot {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub pat: u64,
    pub hsave: u64,
}

pub fn host_snapshot() -> HostSnapshot {
    // SAFETY: reads architectural state and SVM HSAVE MSR at CPL0.
    unsafe {
        HostSnapshot {
            cr0: read_cr0(),
            cr3: read_cr3(),
            cr4: read_cr4(),
            efer: rdmsr(IA32_EFER),
            pat: rdmsr(IA32_PAT),
            hsave: rdmsr(MSR_VM_HSAVE_PA),
        }
    }
}

pub struct SvmVm {
    host: HostSvm,
    resources: Resources,
    features: SvmFeatures,
    guest: GuestExecutionState,
    gprs: [u64; 16],
    active: bool,
}

impl SvmVm {
    pub fn new(npt_root: u64, guest: GuestExecutionState) -> Result<Self, SvmError> {
        let features = features()?;
        if !features.npt {
            return Err(SvmError::MissingNpt);
        }
        if features.asid_count == 0 {
            return Err(SvmError::InvalidState { code: 0 });
        }
        if npt_root & 0xfff != 0 {
            return Err(SvmError::InvalidState { code: npt_root });
        }
        let mut resources = Resources::new()?;
        // SAFETY: HWV-3 only reaches this path on a verified AMD SVM host.
        let pat = unsafe { rdmsr(IA32_PAT) };
        resources.vmcb.write_guest_state(
            npt_root,
            guest,
            resources.iopm(),
            resources.msrpm(),
            pat,
        )?;
        let host = unsafe { enable_svm(resources.hsave()) }?;
        let mut gprs = [0u64; 16];
        gprs.copy_from_slice(&guest.state.registers[..16]);
        Ok(Self {
            host,
            resources,
            features,
            guest,
            gprs,
            active: true,
        })
    }

    pub fn run(&mut self) -> Result<RunReport, SvmError> {
        let mut report = RunReport::default();
        for _ in 0..256 {
            self.stage_state()?;
            let irq_was_enabled = crate::arch::irq_save_disable();
            let status = unsafe { jsr_svm_run() };
            crate::arch::irq_restore(irq_was_enabled);
            if status != 0 {
                return Err(SvmError::InvalidState { code: status });
            }
            self.collect_gprs();
            report.exits += 1;
            let code = self.resources.vmcb.read_u64(CONTROL_EXIT_CODE);
            match code {
                SVM_EXIT_CPUID => {
                    report.cpuid += 1;
                    self.emulate_cpuid();
                    self.advance(self.next_rip_or(2));
                }
                SVM_EXIT_RDTSC => {
                    report.rdtsc += 1;
                    let (lo, hi) = self.guest_tsc();
                    self.set_gpr(0, u64::from(lo));
                    self.set_gpr(2, u64::from(hi));
                    self.advance(self.next_rip_or(2));
                }
                SVM_EXIT_MSR => {
                    let write = self.resources.vmcb.read_u64(CONTROL_EXIT_INFO_1) != 0;
                    if write || self.gpr(1) as u32 != 0x10 {
                        return Err(SvmError::InvalidState { code: self.gpr(1) });
                    }
                    report.msr_reads += 1;
                    let (lo, hi) = self.guest_tsc();
                    self.set_gpr(0, u64::from(lo));
                    self.set_gpr(2, u64::from(hi));
                    self.advance(self.next_rip_or(2));
                }
                SVM_EXIT_IO => {
                    report.io += 1;
                    let info = self.resources.vmcb.read_u64(CONTROL_EXIT_INFO_1);
                    let port = (info >> IOIO_PORT_SHIFT) as u16;
                    let is_in = info & IOIO_TYPE_IN != 0;
                    let size = (info & IOIO_SIZE_MASK) >> IOIO_SIZE_SHIFT;
                    if port != 0x80 || !is_in || size != 0 {
                        return Err(SvmError::InvalidState { code: info });
                    }
                    self.set_gpr(0, (self.gpr(0) & !0xff) | 0xff);
                    let next = self.resources.vmcb.read_u64(CONTROL_EXIT_INFO_2);
                    if next != 0 {
                        self.guest.state.rip = next;
                    } else {
                        self.advance(1);
                    }
                }
                SVM_EXIT_NPF => {
                    report.npf_violations += 1;
                    let _error = self.resources.vmcb.read_u64(CONTROL_EXIT_INFO_1);
                    let _gpa = self.resources.vmcb.read_u64(CONTROL_EXIT_INFO_2);
                    self.advance(self.next_rip_or(3));
                }
                SVM_EXIT_UD => {
                    report.exceptions += 1;
                    return Ok(report);
                }
                SVM_EXIT_HLT => {
                    report.halted = true;
                    return Ok(report);
                }
                SVM_EXIT_SHUTDOWN => {
                    return Ok(report);
                }
                other => {
                    kprintln!(
                        "[JSR-HWV3-DBG] exit={:#x} rip={:#x} info1={:#x} info2={:#x}",
                        other,
                        self.resources.vmcb.read_u64(SAVE_RIP),
                        self.resources.vmcb.read_u64(CONTROL_EXIT_INFO_1),
                        self.resources.vmcb.read_u64(CONTROL_EXIT_INFO_2)
                    );
                    return Err(SvmError::UnknownExit { code: other });
                }
            }
        }
        Err(SvmError::TooManyExits)
    }

    pub fn guest_state(&self) -> VcpuState {
        let mut state = self.guest.state;
        state.registers[..16].copy_from_slice(&self.gprs);
        state.registers[4] = self.guest.rsp;
        state
    }

    pub fn features(&self) -> SvmFeatures {
        self.features
    }

    pub fn shutdown(&mut self) -> Result<(), SvmError> {
        if !self.active {
            return Ok(());
        }
        unsafe {
            disable_svm(self.host);
        }
        self.active = false;
        Ok(())
    }

    fn stage_state(&mut self) -> Result<(), SvmError> {
        self.gprs[4] = self.guest.rsp;
        self.resources
            .vmcb
            .write_u64(SAVE_RIP, self.guest.state.rip);
        self.resources.vmcb.write_u64(SAVE_RSP, self.guest.rsp);
        self.resources.vmcb.write_u64(SAVE_RAX, self.gprs[0]);
        self.resources
            .vmcb
            .write_u64(SAVE_RFLAGS, self.guest.state.rflags | 2);
        // SAFETY: HWV-3 permits one active guest execution on the boot CPU.
        unsafe {
            JSR_SVM_VMCB_PA = self.resources.vmcb.physical();
            JSR_SVM_HSAVE_PA = self.resources.hsave();
            JSR_SVM_GUEST_GPRS = self.gprs;
        }
        Ok(())
    }

    fn collect_gprs(&mut self) {
        // SAFETY: updated only by jsr_svm_run after returning to the host stack.
        self.gprs = unsafe { JSR_SVM_GUEST_GPRS };
        self.gprs[0] = self.resources.vmcb.read_u64(SAVE_RAX);
        self.guest.rsp = self.resources.vmcb.read_u64(SAVE_RSP);
        self.gprs[4] = self.guest.rsp;
        self.guest.state.rip = self.resources.vmcb.read_u64(SAVE_RIP);
        self.guest.state.rflags = self.resources.vmcb.read_u64(SAVE_RFLAGS);
        self.guest.state.registers[..16].copy_from_slice(&self.gprs);
    }

    fn gpr(&self, index: usize) -> u64 {
        self.gprs[index]
    }

    fn set_gpr(&mut self, index: usize, value: u64) {
        self.gprs[index] = value;
    }

    fn emulate_cpuid(&mut self) {
        let result = core::arch::x86_64::__cpuid_count(self.gpr(0) as u32, self.gpr(1) as u32);
        self.set_gpr(0, u64::from(result.eax));
        self.set_gpr(3, u64::from(result.ebx));
        self.set_gpr(1, u64::from(result.ecx));
        self.set_gpr(2, u64::from(result.edx));
    }

    fn guest_tsc(&self) -> (u32, u32) {
        let value = host_tsc().wrapping_add(self.guest.tsc_offset as u64);
        (value as u32, (value >> 32) as u32)
    }

    fn next_rip_or(&self, fallback: u64) -> u64 {
        if self.features.nrips {
            let next = self.resources.vmcb.read_u64(CONTROL_NEXT_RIP);
            if next != 0 {
                return next;
            }
        }
        self.guest.state.rip.wrapping_add(fallback)
    }

    fn advance(&mut self, next: u64) {
        self.guest.state.rip = next;
    }
}

impl Drop for SvmVm {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

unsafe fn rdmsr(index: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdmsr", in("ecx") index, out("eax") lo, out("edx") hi, options(nostack));
    (u64::from(hi) << 32) | u64::from(lo)
}

unsafe fn wrmsr(index: u32, value: u64) {
    asm!(
        "wrmsr",
        in("ecx") index,
        in("eax") value as u32,
        in("edx") (value >> 32) as u32,
        options(nostack)
    );
}

unsafe fn read_cr0() -> u64 {
    let value: u64;
    asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn write_cr0(value: u64) {
    asm!("mov cr0, {}", in(reg) value, options(nomem, nostack, preserves_flags));
}

unsafe fn read_cr3() -> u64 {
    let value: u64;
    asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn read_cr4() -> u64 {
    let value: u64;
    asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn enable_svm(hsave: u64) -> Result<HostSvm, SvmError> {
    let vm_cr = rdmsr(MSR_VM_CR);
    if vm_cr & SVM_VM_CR_SVM_DIS != 0 {
        return Err(SvmError::SvmDisabled);
    }
    let old_efer = rdmsr(IA32_EFER);
    let old_hsave = rdmsr(MSR_VM_HSAVE_PA);
    let cr0 = read_cr0();
    let cr0_ne_added = cr0 & CR0_NE == 0;
    if cr0_ne_added {
        write_cr0(cr0 | CR0_NE);
    }
    wrmsr(MSR_VM_HSAVE_PA, hsave);
    wrmsr(IA32_EFER, old_efer | EFER_SVME);
    asm!("stgi", options(nostack, preserves_flags));
    Ok(HostSvm {
        old_efer,
        old_hsave,
        cr0_ne_added,
    })
}

unsafe fn disable_svm(host: HostSvm) {
    asm!("clgi", options(nostack, preserves_flags));
    wrmsr(MSR_VM_HSAVE_PA, host.old_hsave);
    wrmsr(IA32_EFER, host.old_efer);
    if host.cr0_ne_added {
        write_cr0(read_cr0() & !CR0_NE);
    }
}

extern "C" {
    fn jsr_svm_run() -> u64;
}

extern "C" {
    static mut JSR_SVM_VMCB_PA: u64;
    static mut JSR_SVM_HSAVE_PA: u64;
    static mut JSR_SVM_GUEST_GPRS: [u64; 16];
    static mut JSR_SVM_RSP_OK: u8;
}

global_asm!(
    r#"
    .section .bss
    .align 16
    .global JSR_SVM_VMCB_PA
JSR_SVM_VMCB_PA:
    .zero 8
    .global JSR_SVM_HSAVE_PA
JSR_SVM_HSAVE_PA:
    .zero 8
    .global JSR_SVM_GUEST_GPRS
JSR_SVM_GUEST_GPRS:
    .zero 128
    .global JSR_SVM_RSP_OK
JSR_SVM_RSP_OK:
    .zero 1
    .global JSR_SVM_RSP_ENTRY
JSR_SVM_RSP_ENTRY:
    .zero 8

    .section .text
    .global jsr_svm_run
    .type jsr_svm_run,@function
jsr_svm_run:
    mov [rip + JSR_SVM_RSP_ENTRY], rsp
    mov byte ptr [rip + JSR_SVM_RSP_OK], 0
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rax, [rip + JSR_SVM_HSAVE_PA]
    vmsave rax
    mov rax, [rip + JSR_SVM_VMCB_PA]
    vmload rax

    mov rcx, [rip + JSR_SVM_GUEST_GPRS + 8]
    mov rdx, [rip + JSR_SVM_GUEST_GPRS + 16]
    mov rbx, [rip + JSR_SVM_GUEST_GPRS + 24]
    mov rbp, [rip + JSR_SVM_GUEST_GPRS + 40]
    mov rsi, [rip + JSR_SVM_GUEST_GPRS + 48]
    mov rdi, [rip + JSR_SVM_GUEST_GPRS + 56]
    mov r8,  [rip + JSR_SVM_GUEST_GPRS + 64]
    mov r9,  [rip + JSR_SVM_GUEST_GPRS + 72]
    mov r10, [rip + JSR_SVM_GUEST_GPRS + 80]
    mov r11, [rip + JSR_SVM_GUEST_GPRS + 88]
    mov r12, [rip + JSR_SVM_GUEST_GPRS + 96]
    mov r13, [rip + JSR_SVM_GUEST_GPRS + 104]
    mov r14, [rip + JSR_SVM_GUEST_GPRS + 112]
    mov r15, [rip + JSR_SVM_GUEST_GPRS + 120]
    mov rax, [rip + JSR_SVM_VMCB_PA]
    vmrun rax

    mov [rip + JSR_SVM_GUEST_GPRS + 8], rcx
    mov [rip + JSR_SVM_GUEST_GPRS + 16], rdx
    mov [rip + JSR_SVM_GUEST_GPRS + 24], rbx
    mov [rip + JSR_SVM_GUEST_GPRS + 40], rbp
    mov [rip + JSR_SVM_GUEST_GPRS + 48], rsi
    mov [rip + JSR_SVM_GUEST_GPRS + 56], rdi
    mov [rip + JSR_SVM_GUEST_GPRS + 64], r8
    mov [rip + JSR_SVM_GUEST_GPRS + 72], r9
    mov [rip + JSR_SVM_GUEST_GPRS + 80], r10
    mov [rip + JSR_SVM_GUEST_GPRS + 88], r11
    mov [rip + JSR_SVM_GUEST_GPRS + 96], r12
    mov [rip + JSR_SVM_GUEST_GPRS + 104], r13
    mov [rip + JSR_SVM_GUEST_GPRS + 112], r14
    mov [rip + JSR_SVM_GUEST_GPRS + 120], r15

    mov rax, [rip + JSR_SVM_VMCB_PA]
    vmsave rax
    mov rax, [rip + JSR_SVM_HSAVE_PA]
    vmload rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    cmp rsp, [rip + JSR_SVM_RSP_ENTRY]
    sete cl
    mov [rip + JSR_SVM_RSP_OK], cl
    xor eax, eax
    ret
    .size jsr_svm_run, . - jsr_svm_run
"#
);

pub(crate) fn stack_pointer_restored() -> bool {
    // SAFETY: updated only by jsr_svm_run after returning to the host stack.
    unsafe { JSR_SVM_RSP_OK != 0 }
}

fn host_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDTSC is available in long mode.
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack)) };
    (u64::from(hi) << 32) | u64::from(lo)
}

fn canonical(value: u64) -> bool {
    let upper = value >> 48;
    if value & (1 << 47) == 0 {
        upper == 0
    } else {
        upper == 0xffff
    }
}
