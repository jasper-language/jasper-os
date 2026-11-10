//! Intel VMX execution backend for HWV-2.
//!
//! The backend owns real VMXON/VMCS/bitmap regions and executes VMLAUNCH or
//! VMRESUME on the current processor. It consumes the EPT root produced by
//! HWV-1. No generic kernel layer interprets VMCS encodings.

use core::arch::{asm, global_asm};
use core::ptr;

use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::hwvirt::Backend;
use kernel_core::hwvirt_vcpu::VcpuState;
use kernel_core::hwvirt_vmm::VmExitEvent;
use kernel_core::pio::{
    PioAccess, PioDirection, PioError, PioProbe, PioWidth, PortMap, PIO_COMMAND_RESET,
    PIO_PROBE_BASE,
};

use crate::kprintln;

const IA32_FEATURE_CONTROL: u32 = 0x03A;
const IA32_PAT: u32 = 0x277;
const IA32_EFER: u32 = 0xC000_0080;
const IA32_FS_BASE: u32 = 0xC000_0100;
const IA32_GS_BASE: u32 = 0xC000_0101;

const IA32_VMX_BASIC: u32 = 0x480;
const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const IA32_VMX_EXIT_CTLS: u32 = 0x483;
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
const IA32_VMX_CR0_FIXED0: u32 = 0x486;
const IA32_VMX_CR0_FIXED1: u32 = 0x487;
const IA32_VMX_CR4_FIXED0: u32 = 0x488;
const IA32_VMX_CR4_FIXED1: u32 = 0x489;
const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;

const FEATURE_LOCK: u64 = 1 << 0;
const FEATURE_VMX_OUTSIDE_SMX: u64 = 1 << 2;
const CR0_NE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_VMXE: u64 = 1 << 13;
const CR4_OSXSAVE: u64 = 1 << 18;

const PROC_USE_TSC_OFFSETTING: u32 = 1 << 3;
const PROC_HLT_EXITING: u32 = 1 << 7;
const PROC_RDTSC_EXITING: u32 = 1 << 12;
const PROC_USE_IO_BITMAPS: u32 = 1 << 25;
const PROC_USE_MSR_BITMAPS: u32 = 1 << 28;
const PROC_ACTIVATE_SECONDARY: u32 = 1 << 31;
const SECOND_ENABLE_EPT: u32 = 1 << 1;
const SECOND_ENABLE_RDTSCP: u32 = 1 << 3;
const EXIT_SAVE_DEBUG_CONTROLS: u32 = 1 << 2;
const EXIT_HOST_ADDR_SPACE_SIZE: u32 = 1 << 9;
const EXIT_ACK_INTERRUPTS: u32 = 1 << 15;
const EXIT_LOAD_IA32_EFER: u32 = 1 << 21;
const ENTRY_LOAD_DEBUG_CONTROLS: u32 = 1 << 2;
const ENTRY_IA32E_MODE: u32 = 1 << 9;
const ENTRY_LOAD_IA32_EFER: u32 = 1 << 15;

const GUEST_ES_SELECTOR: u32 = 0x0800;
const GUEST_CS_SELECTOR: u32 = 0x0802;
const GUEST_SS_SELECTOR: u32 = 0x0804;
const GUEST_DS_SELECTOR: u32 = 0x0806;
const GUEST_FS_SELECTOR: u32 = 0x0808;
const GUEST_GS_SELECTOR: u32 = 0x080A;
const GUEST_LDTR_SELECTOR: u32 = 0x080C;
const GUEST_TR_SELECTOR: u32 = 0x080E;
const HOST_ES_SELECTOR: u32 = 0x0C00;
const HOST_CS_SELECTOR: u32 = 0x0C02;
const HOST_SS_SELECTOR: u32 = 0x0C04;
const HOST_DS_SELECTOR: u32 = 0x0C06;
const HOST_FS_SELECTOR: u32 = 0x0C08;
const HOST_GS_SELECTOR: u32 = 0x0C0A;
const HOST_TR_SELECTOR: u32 = 0x0C0C;
const IO_BITMAP_A: u32 = 0x2000;
const IO_BITMAP_B: u32 = 0x2002;
const MSR_BITMAP: u32 = 0x2004;
const TSC_OFFSET: u32 = 0x2010;
const EPT_POINTER: u32 = 0x201A;
const GUEST_PHYSICAL_ADDRESS: u32 = 0x2400;
const VMCS_LINK_POINTER: u32 = 0x2800;
const GUEST_IA32_DEBUGCTL: u32 = 0x2802;
const GUEST_IA32_PAT: u32 = 0x2804;
const GUEST_IA32_EFER: u32 = 0x2806;
const HOST_IA32_PAT: u32 = 0x2C00;
const HOST_IA32_EFER: u32 = 0x2C02;
const PIN_BASED_CONTROLS: u32 = 0x4000;
const PROC_BASED_CONTROLS: u32 = 0x4002;
const EXCEPTION_BITMAP: u32 = 0x4004;
const EXIT_CONTROLS: u32 = 0x400C;
const ENTRY_CONTROLS: u32 = 0x4012;
const SECONDARY_CONTROLS: u32 = 0x401E;
const ENTRY_INTR_INFO: u32 = 0x4016;
const VM_INSTRUCTION_ERROR: u32 = 0x4400;
const VM_EXIT_REASON: u32 = 0x4402;
const VM_EXIT_INTR_INFO: u32 = 0x4404;
const VM_EXIT_INTR_ERROR_CODE: u32 = 0x4406;
const VM_EXIT_INSTRUCTION_LENGTH: u32 = 0x440C;
const GUEST_ES_LIMIT: u32 = 0x4800;
const GUEST_CS_LIMIT: u32 = 0x4802;
const GUEST_SS_LIMIT: u32 = 0x4804;
const GUEST_DS_LIMIT: u32 = 0x4806;
const GUEST_FS_LIMIT: u32 = 0x4808;
const GUEST_GS_LIMIT: u32 = 0x480A;
const GUEST_LDTR_LIMIT: u32 = 0x480C;
const GUEST_TR_LIMIT: u32 = 0x480E;
const GUEST_GDTR_LIMIT: u32 = 0x4810;
const GUEST_IDTR_LIMIT: u32 = 0x4812;
const GUEST_ES_AR: u32 = 0x4814;
const GUEST_CS_AR: u32 = 0x4816;
const GUEST_SS_AR: u32 = 0x4818;
const GUEST_DS_AR: u32 = 0x481A;
const GUEST_FS_AR: u32 = 0x481C;
const GUEST_GS_AR: u32 = 0x481E;
const GUEST_LDTR_AR: u32 = 0x4820;
const GUEST_TR_AR: u32 = 0x4822;
const GUEST_INTERRUPTIBILITY: u32 = 0x4824;
const GUEST_ACTIVITY_STATE: u32 = 0x4826;
const GUEST_SYSENTER_CS: u32 = 0x482A;
const HOST_SYSENTER_CS: u32 = 0x4C00;
const CR0_GUEST_HOST_MASK: u32 = 0x6000;
const CR4_GUEST_HOST_MASK: u32 = 0x6002;
const CR0_READ_SHADOW: u32 = 0x6004;
const CR4_READ_SHADOW: u32 = 0x6006;
const EXIT_QUALIFICATION: u32 = 0x6400;
const GUEST_CR0: u32 = 0x6800;
const GUEST_CR3: u32 = 0x6802;
const GUEST_CR4: u32 = 0x6804;
const GUEST_ES_BASE: u32 = 0x6806;
const GUEST_CS_BASE: u32 = 0x6808;
const GUEST_SS_BASE: u32 = 0x680A;
const GUEST_DS_BASE: u32 = 0x680C;
const GUEST_FS_BASE: u32 = 0x680E;
const GUEST_GS_BASE: u32 = 0x6810;
const GUEST_LDTR_BASE: u32 = 0x6812;
const GUEST_TR_BASE: u32 = 0x6814;
const GUEST_GDTR_BASE: u32 = 0x6816;
const GUEST_IDTR_BASE: u32 = 0x6818;
const GUEST_DR7: u32 = 0x681A;
const GUEST_RSP: u32 = 0x681C;
const GUEST_RIP: u32 = 0x681E;
const GUEST_RFLAGS: u32 = 0x6820;
const GUEST_PENDING_DEBUG: u32 = 0x6822;
const GUEST_SYSENTER_ESP: u32 = 0x6824;
const GUEST_SYSENTER_EIP: u32 = 0x6826;
const HOST_CR0: u32 = 0x6C00;
const HOST_CR3: u32 = 0x6C02;
const HOST_CR4: u32 = 0x6C04;
const HOST_FS_BASE: u32 = 0x6C06;
const HOST_GS_BASE: u32 = 0x6C08;
const HOST_TR_BASE: u32 = 0x6C0A;
const HOST_GDTR_BASE: u32 = 0x6C0C;
const HOST_IDTR_BASE: u32 = 0x6C0E;
const HOST_SYSENTER_ESP: u32 = 0x6C10;
const HOST_SYSENTER_EIP: u32 = 0x6C12;

const EXIT_EXCEPTION_NMI: u32 = 0;
const EXIT_CPUID: u32 = 10;
const EXIT_HLT: u32 = 12;
const EXIT_RDTSC: u32 = 16;
const EXIT_IO: u32 = 30;
const EXIT_MSR_READ: u32 = 31;
const EXIT_MSR_WRITE: u32 = 32;
const EXIT_EPT_VIOLATION: u32 = 48;
const EXIT_RDTSCP: u32 = 51;
const EXIT_CR_ACCESS: u32 = 28;
const EXIT_CR8_ACCESS: u32 = 44;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmxError {
    CpuUnsupported,
    FeatureControl,
    Vmxon,
    Vmxoff,
    Vmclear,
    Vmptrld,
    Vmwrite { field: u32, code: u64 },
    Vmread { field: u32, code: u64 },
    Launch { code: u64 },
    Resume { code: u64 },
    EntryFailure { reason: u32 },
    InvalidControl { mask: u32 },
    InvalidState { code: u64 },
    MissingPhysicalMap,
    OutOfFrames,
    TooManyExits,
    EventDelivery,
    Pio(PioError),
}

impl VmxError {
    pub const fn name(self) -> &'static str {
        match self {
            VmxError::CpuUnsupported => "hwvirt.vmx.error.cpu_unsupported",
            VmxError::FeatureControl => "hwvirt.vmx.error.feature_control",
            VmxError::Vmxon => "hwvirt.vmx.error.vmxon",
            VmxError::Vmxoff => "hwvirt.vmx.error.vmxoff",
            VmxError::Vmclear => "hwvirt.vmx.error.vmclear",
            VmxError::Vmptrld => "hwvirt.vmx.error.vmptrld",
            VmxError::Vmwrite { .. } => "hwvirt.vmx.error.vmwrite",
            VmxError::Vmread { .. } => "hwvirt.vmx.error.vmread",
            VmxError::Launch { .. } => "hwvirt.vmx.error.launch",
            VmxError::Resume { .. } => "hwvirt.vmx.error.resume",
            VmxError::EntryFailure { .. } => "hwvirt.vmx.error.entry_failure",
            VmxError::InvalidControl { .. } => "hwvirt.vmx.error.invalid_control",
            VmxError::InvalidState { .. } => "hwvirt.vmx.error.invalid_state",
            VmxError::MissingPhysicalMap => "hwvirt.vmx.error.missing_physical_map",
            VmxError::OutOfFrames => "hwvirt.vmx.error.out_of_frames",
            VmxError::TooManyExits => "hwvirt.vmx.error.too_many_exits",
            VmxError::EventDelivery => "hwvirt.vmx.error.event_delivery",
            VmxError::Pio(error) => error.name(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmExit {
    Exception { vector: u8, info: u32 },
    Cpuid,
    Hlt,
    Rdtsc,
    Io { qualification: u64 },
    MsrRead { index: u32 },
    MsrWrite { index: u32 },
    EptViolation { qualification: u64, physical: u64 },
    Rdtscp,
}

#[derive(Clone, Copy)]
pub struct GuestExecutionState {
    pub state: VcpuState,
    pub rsp: u64,
    pub cr3_gpa: u64,
    pub efer: u64,
    pub tsc_offset: i64,
}

struct Region {
    frame: PhysFrame,
}

impl Region {
    fn allocate_zeroed(fill: u8) -> Result<Self, VmxError> {
        let frame = crate::mm::frame::allocate().map_err(|_| VmxError::OutOfFrames)?;
        let Some(ptr) = crate::mm::phys_to_virt(frame.start()) else {
            let _ = crate::mm::frame::deallocate(frame);
            return Err(VmxError::MissingPhysicalMap);
        };
        // SAFETY: the frame was just allocated and is not published elsewhere.
        unsafe { ptr::write_bytes(ptr, fill, FRAME_SIZE as usize) };
        Ok(Self { frame })
    }

    fn physical(&self) -> u64 {
        self.frame.start()
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        let _ = crate::mm::frame::deallocate(self.frame);
    }
}

struct HostRegisters {
    cr0: u64,
    cr3: u64,
    cr4_after: u64,
    efer: u64,
    pat: u64,
    fs_base: u64,
    gs_base: u64,
    tr_base: u64,
    gdtr_base: u64,
    gdtr_limit: u16,
    idtr_base: u64,
    idtr_limit: u16,
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    sfmask: u64,
    kernel_gs_base: u64,
    cs: u16,
    ds: u16,
    es: u16,
    ss: u16,
    fs: u16,
    gs: u16,
    ldtr: u16,
}

#[derive(Clone, Copy)]
struct EntryRestore {
    cr0_ne: bool,
    cr4_vmxe: bool,
    cr4_osxsave: bool,
    cr4_fxsr: bool,
    xcr0: u64,
    xcr0_supported: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostSnapshot {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr2: u64,
    pub cr8: u64,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub efer: u64,
    pub pat: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub gdtr_base: u64,
    pub gdtr_limit: u16,
    pub idtr_base: u64,
    pub idtr_limit: u16,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub ss: u16,
    pub fs: u16,
    pub gs: u16,
    pub ldtr_selector: u16,
    pub tr_selector: u16,
    pub tr_base: u64,
    pub rflags: u64,
}

pub(crate) fn host_snapshot() -> HostSnapshot {
    use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
    use x86_64::instructions::tables::{sgdt, sidt};
    let gdt = sgdt();
    let idt = sidt();
    let mut tr_selector: u16;
    let mut ldtr_selector: u16;
    let rflags: u64;
    // SAFETY: reads architectural state at CPL0 without changing it.
    unsafe {
        asm!("str {0:x}", out(reg) tr_selector, options(nomem, nostack, preserves_flags));
        asm!("sldt {0:x}", out(reg) ldtr_selector, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) rflags, options(nostack));
        HostSnapshot {
            cr0: read_cr0(),
            cr3: read_cr3(),
            cr4: read_cr4(),
            cr2: read_cr2(),
            cr8: read_cr8(),
            dr0: read_dr0(),
            dr1: read_dr1(),
            dr2: read_dr2(),
            dr3: read_dr3(),
            dr6: read_dr6(),
            dr7: read_dr7(),
            efer: rdmsr(IA32_EFER),
            pat: rdmsr(IA32_PAT),
            fs_base: rdmsr(IA32_FS_BASE),
            gs_base: rdmsr(IA32_GS_BASE),
            kernel_gs_base: rdmsr(0xC000_0102),
            sysenter_cs: rdmsr(0x174),
            sysenter_esp: rdmsr(0x175),
            sysenter_eip: rdmsr(0x176),
            gdtr_base: gdt.base.as_u64(),
            gdtr_limit: gdt.limit,
            idtr_base: idt.base.as_u64(),
            idtr_limit: idt.limit,
            cs: CS::get_reg().0,
            ds: DS::get_reg().0,
            es: ES::get_reg().0,
            ss: SS::get_reg().0,
            fs: FS::get_reg().0,
            gs: GS::get_reg().0,
            ldtr_selector,
            tr_selector,
            tr_base: descriptor_base(gdt.base.as_u64(), tr_selector),
            rflags,
        }
    }
}

#[derive(Clone, Copy)]
struct Controls {
    pin: u32,
    primary: u32,
    secondary: u32,
    exit: u32,
    entry: u32,
}

struct HostXsave {
    area: Region,
    mask: u64,
    saved: bool,
}

impl HostXsave {
    fn new(mask: u64) -> Result<Self, VmxError> {
        Ok(Self {
            area: Region::allocate_zeroed(0)?,
            mask,
            saved: false,
        })
    }

    fn save(&mut self) -> Result<(), VmxError> {
        let Some(ptr) = crate::mm::phys_to_virt(self.area.physical()) else {
            return Err(VmxError::MissingPhysicalMap);
        };
        // SAFETY: CR4.OSXSAVE and IA32_XSS have been prepared by enable_vmx;
        // the 4 KiB region covers the CPUID-reported enabled-state size.
        unsafe {
            asm!(
                "xsave64 [{}]",
                in(reg) ptr,
                in("eax") self.mask as u32,
                in("edx") (self.mask >> 32) as u32,
                options(nostack)
            )
        };
        self.saved = true;
        Ok(())
    }

    fn restore(&mut self) {
        if !self.saved {
            return;
        }
        let Some(ptr) = crate::mm::phys_to_virt(self.area.physical()) else {
            return;
        };
        // SAFETY: the area was populated by `save` and remains private.
        unsafe {
            asm!(
                "xrstor64 [{}]",
                in(reg) ptr,
                in("eax") self.mask as u32,
                in("edx") (self.mask >> 32) as u32,
                options(nostack)
            )
        };
        self.saved = false;
    }
}

impl Drop for HostXsave {
    fn drop(&mut self) {
        self.restore();
    }
}

extern "C" {
    fn jsr_vmx_run(resume: u64) -> u64;
}

extern "C" {
    static mut JSR_VMX_GUEST_GPRS: [u64; 16];
    static mut JSR_VMX_RSP_OK: u8;
}

pub(crate) fn stack_pointer_restored() -> bool {
    // SAFETY: updated only by jsr_vmx_run after returning to the host stack.
    unsafe { JSR_VMX_RSP_OK != 0 }
}

global_asm!(
    r#"
    .section .bss
    .global JSR_VMX_GUEST_GPRS
    .align 16
JSR_VMX_GUEST_GPRS:
    .zero 128
    .global JSR_VMX_RESUME
JSR_VMX_RESUME:
    .zero 1
    .align 8
    .global JSR_VMX_HOST_RFLAGS
JSR_VMX_HOST_RFLAGS:
    .zero 8
    .global JSR_VMX_RSP_ENTRY
JSR_VMX_RSP_ENTRY:
    .zero 8
    .global JSR_VMX_RSP_OK
JSR_VMX_RSP_OK:
    .zero 1

    .section .text
    .global jsr_vmx_run
    .type jsr_vmx_run,@function
jsr_vmx_run:
    mov [rip + JSR_VMX_RESUME], dil
    mov [rip + JSR_VMX_RSP_ENTRY], rsp
    pushfq
    pop rax
    mov [rip + JSR_VMX_HOST_RFLAGS], rax
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rdx, rsp
    mov rax, 0x6c14
    vmwrite rax, rdx
    lea rdx, [rip + .Lvmx_exit]
    mov rax, 0x6c16
    vmwrite rax, rdx

    mov rcx, [rip + JSR_VMX_GUEST_GPRS + 8]
    mov rdx, [rip + JSR_VMX_GUEST_GPRS + 16]
    mov rbx, [rip + JSR_VMX_GUEST_GPRS + 24]
    mov rbp, [rip + JSR_VMX_GUEST_GPRS + 40]
    mov rsi, [rip + JSR_VMX_GUEST_GPRS + 48]
    mov rdi, [rip + JSR_VMX_GUEST_GPRS + 56]
    mov r8,  [rip + JSR_VMX_GUEST_GPRS + 64]
    mov r9,  [rip + JSR_VMX_GUEST_GPRS + 72]
    mov r10, [rip + JSR_VMX_GUEST_GPRS + 80]
    mov r11, [rip + JSR_VMX_GUEST_GPRS + 88]
    mov r12, [rip + JSR_VMX_GUEST_GPRS + 96]
    mov r13, [rip + JSR_VMX_GUEST_GPRS + 104]
    mov r14, [rip + JSR_VMX_GUEST_GPRS + 112]
    mov r15, [rip + JSR_VMX_GUEST_GPRS + 120]
    mov rax, [rip + JSR_VMX_GUEST_GPRS + 0]

    cmp byte ptr [rip + JSR_VMX_RESUME], 0
    jnz .Lvmx_resume
    vmlaunch
    jmp .Lvmx_instr_fail
.Lvmx_resume:
    vmresume
.Lvmx_instr_fail:
    mov eax, 1
    jmp .Lvmx_restore_host

.Lvmx_exit:
    mov [rip + JSR_VMX_GUEST_GPRS + 0], rax
    mov [rip + JSR_VMX_GUEST_GPRS + 8], rcx
    mov [rip + JSR_VMX_GUEST_GPRS + 16], rdx
    mov [rip + JSR_VMX_GUEST_GPRS + 24], rbx
    mov [rip + JSR_VMX_GUEST_GPRS + 40], rbp
    mov [rip + JSR_VMX_GUEST_GPRS + 48], rsi
    mov [rip + JSR_VMX_GUEST_GPRS + 56], rdi
    mov [rip + JSR_VMX_GUEST_GPRS + 64], r8
    mov [rip + JSR_VMX_GUEST_GPRS + 72], r9
    mov [rip + JSR_VMX_GUEST_GPRS + 80], r10
    mov [rip + JSR_VMX_GUEST_GPRS + 88], r11
    mov [rip + JSR_VMX_GUEST_GPRS + 96], r12
    mov [rip + JSR_VMX_GUEST_GPRS + 104], r13
    mov [rip + JSR_VMX_GUEST_GPRS + 112], r14
    mov [rip + JSR_VMX_GUEST_GPRS + 120], r15
    xor eax, eax

.Lvmx_restore_host:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    cmp rsp, [rip + JSR_VMX_RSP_ENTRY]
    sete cl
    mov [rip + JSR_VMX_RSP_OK], cl
    push qword ptr [rip + JSR_VMX_HOST_RFLAGS]
    popfq
    ret
    .size jsr_vmx_run, . - jsr_vmx_run
"#
);

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

unsafe fn read_cr2() -> u64 {
    let value: u64;
    asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn read_cr8() -> u64 {
    let value: u64;
    asm!("mov {}, cr8", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn read_dr0() -> u64 {
    let value: u64;
    asm!("mov {}, dr0", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn read_dr1() -> u64 {
    let value: u64;
    asm!("mov {}, dr1", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn read_dr2() -> u64 {
    let value: u64;
    asm!("mov {}, dr2", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn read_dr3() -> u64 {
    let value: u64;
    asm!("mov {}, dr3", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn read_dr6() -> u64 {
    let value: u64;
    asm!("mov {}, dr6", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn read_dr7() -> u64 {
    let value: u64;
    asm!("mov {}, dr7", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

unsafe fn write_cr4(value: u64) {
    asm!("mov cr4, {}", in(reg) value, options(nomem, nostack, preserves_flags));
}

fn read_xcr0() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: called only with CR4.OSXSAVE=1.
    unsafe {
        asm!(
            "xgetbv",
            in("ecx") 0u32,
            out("eax") lo,
            out("edx") hi,
            options(nostack)
        )
    };
    (u64::from(hi) << 32) | u64::from(lo)
}

fn write_xcr0(value: u64) {
    // SAFETY: called only with CR4.OSXSAVE=1 and a supported XCR0 subset.
    unsafe {
        asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack)
        )
    };
}

fn instruction_status(flags: u64) -> Result<(), u64> {
    if flags & 0x40 != 0 {
        // ZF=1 means VMfailValid: read the detailed instruction error.
        Err(1)
    } else if flags & 0x1 != 0 {
        Err(2)
    } else {
        Ok(())
    }
}

fn vmxon(region: u64) -> Result<(), VmxError> {
    let flags: u64;
    // SAFETY: CPL0 and a 4 KiB revision-initialized VMXON region.
    unsafe { asm!("vmxon [{}]", "pushfq", "pop {}", in(reg) &region, out(reg) flags) };
    instruction_status(flags).map_err(|_| VmxError::Vmxon)
}

fn vmxoff() -> Result<(), VmxError> {
    let flags: u64;
    // SAFETY: only called after successful VMXON on this processor.
    unsafe { asm!("vmxoff", "pushfq", "pop {}", out(reg) flags) };
    instruction_status(flags).map_err(|_| VmxError::Vmxoff)
}

fn vmclear(region: u64) -> Result<(), VmxError> {
    let flags: u64;
    // SAFETY: `region` is the allocated, revision-initialized VMCS frame.
    unsafe { asm!("vmclear [{}]", "pushfq", "pop {}", in(reg) &region, out(reg) flags) };
    instruction_status(flags).map_err(|_| VmxError::Vmclear)
}

fn vmptrld(region: u64) -> Result<(), VmxError> {
    let flags: u64;
    // SAFETY: the VMCS region has been cleared and belongs to this processor.
    unsafe { asm!("vmptrld [{}]", "pushfq", "pop {}", in(reg) &region, out(reg) flags) };
    instruction_status(flags).map_err(|_| VmxError::Vmptrld)
}

fn vmwrite(field: u32, value: u64) -> Result<(), VmxError> {
    let flags: u64;
    let field = u64::from(field);
    // SAFETY: the field is fixed by this backend; the current VMCS is loaded.
    unsafe {
        asm!(
            "vmwrite {}, {}",
            "pushfq",
            "pop {}",
            in(reg) field,
            in(reg) value,
            out(reg) flags
        )
    };
    instruction_status(flags).map_err(|_| VmxError::Vmwrite {
        field: field as u32,
        code: read_vm_error(),
    })
}

fn vmread(field: u32) -> Result<u64, VmxError> {
    let value: u64;
    let flags: u64;
    let encoded_field = u64::from(field);
    // SAFETY: the current VMCS is loaded.
    unsafe {
        asm!(
            "vmread {}, {}",
            "pushfq",
            "pop {}",
            out(reg) value,
            in(reg) encoded_field,
            out(reg) flags
        )
    };
    instruction_status(flags).map_err(|_| VmxError::Vmread {
        field,
        code: read_vm_error(),
    })?;
    Ok(value)
}

fn read_vm_error() -> u64 {
    let mut value: u64 = 0;
    // SAFETY: best-effort diagnostic read; failures leave zero.
    unsafe {
        asm!(
            "vmread {}, {}",
            inout(reg) value,
            in(reg) u64::from(VM_INSTRUCTION_ERROR),
            options(nostack)
        );
    }
    value
}

fn host_registers(cr0: u64, cr3: u64, cr4_after: u64) -> HostRegisters {
    use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
    use x86_64::instructions::tables::{sgdt, sidt};
    let gdt = sgdt();
    let idt = sidt();
    let mut tr_selector: u16;
    let mut ldtr_selector: u16;
    // SAFETY: reads the task-register selector.
    unsafe { asm!("str {0:x}", out(reg) tr_selector, options(nomem, nostack, preserves_flags)) };
    unsafe { asm!("sldt {0:x}", out(reg) ldtr_selector, options(nomem, nostack, preserves_flags)) };
    let tr_base = descriptor_base(gdt.base.as_u64(), tr_selector);
    // SAFETY: all reads are architectural state readable at CPL0.
    unsafe {
        HostRegisters {
            cr0,
            cr3,
            cr4_after,
            efer: rdmsr(IA32_EFER),
            pat: rdmsr(IA32_PAT),
            fs_base: rdmsr(IA32_FS_BASE),
            gs_base: rdmsr(IA32_GS_BASE),
            tr_base,
            gdtr_base: gdt.base.as_u64(),
            gdtr_limit: gdt.limit,
            idtr_base: idt.base.as_u64(),
            idtr_limit: idt.limit,
            sysenter_cs: rdmsr(0x174),
            sysenter_esp: rdmsr(0x175),
            sysenter_eip: rdmsr(0x176),
            star: rdmsr(0xc000_0081),
            lstar: rdmsr(0xc000_0082),
            cstar: rdmsr(0xc000_0083),
            sfmask: rdmsr(0xc000_0084),
            kernel_gs_base: rdmsr(0xc000_0102),
            cs: CS::get_reg().0,
            ds: DS::get_reg().0,
            es: ES::get_reg().0,
            ss: SS::get_reg().0,
            fs: FS::get_reg().0,
            gs: GS::get_reg().0,
            ldtr: ldtr_selector,
        }
    }
}

fn descriptor_base(table: u64, selector: u16) -> u64 {
    let index = usize::from(selector >> 3);
    let entry = (table as *const u64).wrapping_add(index);
    // SAFETY: GDT/IDT descriptors referenced by the currently loaded selector.
    let raw = unsafe { entry.read_volatile() };
    ((raw >> 16) & 0x0000_00ff_ffff) | ((raw >> 32) & 0xff00_0000)
}

fn enable_vmx() -> Result<(HostRegisters, EntryRestore), VmxError> {
    // SAFETY: the caller is on the boot processor at CPL0.
    let (cr0, cr3, cr4_before, feature) = unsafe {
        (
            read_cr0(),
            read_cr3(),
            read_cr4(),
            rdmsr(IA32_FEATURE_CONTROL),
        )
    };
    if feature & FEATURE_LOCK == 0 {
        // SAFETY: lock and permit VMX outside SMX, as required on this CPU.
        unsafe {
            wrmsr(
                IA32_FEATURE_CONTROL,
                feature | FEATURE_LOCK | FEATURE_VMX_OUTSIDE_SMX,
            )
        };
    } else if feature & FEATURE_VMX_OUTSIDE_SMX == 0 {
        return Err(VmxError::FeatureControl);
    }
    let had_vmxe = cr4_before & CR4_VMXE != 0;
    let cpu = core::arch::x86_64::__cpuid(1);
    let xsave = cpu.ecx & (1 << 26) != 0;
    let fxsr = cpu.edx & (1 << 24) != 0 && cpu.edx & (1 << 25) != 0;
    let xsave_leaf = core::arch::x86_64::__cpuid_count(0xD, 0);
    if xsave && xsave_leaf.ebx > FRAME_SIZE as u32 {
        return Err(VmxError::InvalidState {
            code: u64::from(xsave_leaf.ebx),
        });
    }
    let add_osxsave = xsave && cr4_before & CR4_OSXSAVE == 0;
    let add_fxsr =
        fxsr && cr4_before & (CR4_OSFXSR | CR4_OSXMMEXCPT) != (CR4_OSFXSR | CR4_OSXMMEXCPT);
    let cr4_after = cr4_before
        | CR4_VMXE
        | if xsave { CR4_OSXSAVE } else { 0 }
        | if fxsr { CR4_OSFXSR | CR4_OSXMMEXCPT } else { 0 };
    let add_ne = cr0 & CR0_NE == 0;
    let cr0_after = cr0 | CR0_NE;
    if add_ne {
        // SAFETY: VMXON requires CR0.NE=1. The kernel contains no x87 user
        // state and VMX operation is restored immediately after VMXOFF.
        unsafe { write_cr0(cr0_after) };
    }
    if !had_vmxe {
        // SAFETY: enabling VMX operation after feature-control admission.
        unsafe { write_cr4(cr4_after) };
    } else if add_osxsave || add_fxsr {
        unsafe { write_cr4(cr4_after) };
    }
    let xcr0 = if xsave { read_xcr0() } else { 0 };
    Ok((
        host_registers(cr0_after, cr3, cr4_after),
        EntryRestore {
            cr0_ne: add_ne,
            cr4_vmxe: !had_vmxe,
            cr4_osxsave: add_osxsave,
            cr4_fxsr: add_fxsr,
            xcr0,
            xcr0_supported: if xsave { u64::from(xsave_leaf.eax) } else { 0 },
        },
    ))
}

fn allowed_control(msr: u32, desired: u32) -> Result<u32, VmxError> {
    // SAFETY: VMX capability MSR read at CPL0.
    let raw = unsafe { rdmsr(msr) };
    let mandatory = raw as u32;
    let optional = (raw >> 32) as u32;
    let missing = desired & !(mandatory | optional);
    if missing != 0 {
        return Err(VmxError::InvalidControl { mask: missing });
    }
    Ok(mandatory | (desired & optional))
}

fn controls() -> Result<(Controls, u64), VmxError> {
    // SAFETY: capability MSRs are read-only at CPL0.
    let basic = unsafe { rdmsr(IA32_VMX_BASIC) };
    if basic & (1 << 55) == 0 {
        return Ok((
            Controls {
                pin: allowed_control(IA32_VMX_PINBASED_CTLS, 0)?,
                primary: allowed_control(
                    IA32_VMX_PROCBASED_CTLS,
                    PROC_USE_TSC_OFFSETTING
                        | PROC_HLT_EXITING
                        | PROC_RDTSC_EXITING
                        | PROC_USE_IO_BITMAPS
                        | PROC_USE_MSR_BITMAPS
                        | PROC_ACTIVATE_SECONDARY,
                )?,
                secondary: allowed_control(
                    IA32_VMX_PROCBASED_CTLS2,
                    SECOND_ENABLE_EPT | SECOND_ENABLE_RDTSCP,
                )?,
                exit: allowed_control(
                    IA32_VMX_EXIT_CTLS,
                    EXIT_SAVE_DEBUG_CONTROLS
                        | EXIT_HOST_ADDR_SPACE_SIZE
                        | EXIT_ACK_INTERRUPTS
                        | EXIT_LOAD_IA32_EFER,
                )?,
                entry: allowed_control(
                    IA32_VMX_ENTRY_CTLS,
                    ENTRY_LOAD_DEBUG_CONTROLS | ENTRY_IA32E_MODE | ENTRY_LOAD_IA32_EFER,
                )?,
            },
            basic,
        ));
    }
    Ok((
        Controls {
            pin: allowed_control(IA32_VMX_TRUE_PINBASED_CTLS, 0)?,
            primary: allowed_control(
                IA32_VMX_TRUE_PROCBASED_CTLS,
                PROC_USE_TSC_OFFSETTING
                    | PROC_HLT_EXITING
                    | PROC_RDTSC_EXITING
                    | PROC_USE_IO_BITMAPS
                    | PROC_USE_MSR_BITMAPS
                    | PROC_ACTIVATE_SECONDARY,
            )?,
            secondary: allowed_control(
                IA32_VMX_PROCBASED_CTLS2,
                SECOND_ENABLE_EPT | SECOND_ENABLE_RDTSCP,
            )?,
            exit: allowed_control(
                IA32_VMX_TRUE_EXIT_CTLS,
                EXIT_SAVE_DEBUG_CONTROLS
                    | EXIT_HOST_ADDR_SPACE_SIZE
                    | EXIT_ACK_INTERRUPTS
                    | EXIT_LOAD_IA32_EFER,
            )?,
            entry: allowed_control(
                IA32_VMX_TRUE_ENTRY_CTLS,
                ENTRY_LOAD_DEBUG_CONTROLS | ENTRY_IA32E_MODE | ENTRY_LOAD_IA32_EFER,
            )?,
        },
        basic,
    ))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunReport {
    pub exits: u32,
    pub cpuid: u32,
    pub rdtsc: u32,
    pub msr_reads: u32,
    pub io: u32,
    pub ept_violations: u32,
    pub exceptions: u32,
    pub halted: bool,
    pub xsave_enabled: bool,
    pub serial_bytes: u32,
    pub linux_marker: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinuxReport {
    pub exits: u32,
    pub serial_bytes: u32,
    pub timer_interrupts: u32,
    pub timer_eois: u32,
    pub pio_reads: u32,
    pub pio_writes: u32,
    pub pio_probe_generation: u16,
    pub pio_requests: u32,
    pub pio_cancels: u32,
    pub pio_marker: bool,
    pub marker: bool,
    pub halted: bool,
}

/// Guest-memory and MMIO services consumed by the Linux run loop.
pub trait LinuxPlatform {
    fn read_guest(&mut self, gpa: u64, out: &mut [u8]) -> bool;
    fn write_guest(&mut self, gpa: u64, bytes: &[u8]) -> bool;
    fn read_mmio(&mut self, gpa: u64, width: u8) -> Option<u64>;
    fn write_mmio(&mut self, gpa: u64, width: u8, value: u64) -> bool;
    fn take_irq(&mut self) -> Option<u8>;
    fn return_irq(&mut self, irq: u8);
}

struct NoLinuxDevices;

impl LinuxPlatform for NoLinuxDevices {
    fn read_guest(&mut self, _: u64, _: &mut [u8]) -> bool {
        false
    }
    fn write_guest(&mut self, _: u64, _: &[u8]) -> bool {
        false
    }
    fn read_mmio(&mut self, _: u64, _: u8) -> Option<u64> {
        None
    }
    fn write_mmio(&mut self, _: u64, _: u8, _: u64) -> bool {
        false
    }
    fn take_irq(&mut self) -> Option<u8> {
        None
    }
    fn return_irq(&mut self, _: u8) {}
}

const LINUX_MARKER: &[u8] = b"[JSR-LINUX-GUEST]";
const PIO_MARKER: &[u8] = b"[JSR-HWV5-PIO]";

const PIO_PIC_MASTER: u16 = 1;
const PIO_PIT: u16 = 2;
const PIO_I8042: u16 = 3;
const PIO_PIC_SLAVE: u16 = 4;
const PIO_UART: u16 = 5;
const PIO_DISCARD: u16 = 6;
const PIO_PROBE: u16 = 7;
const PIO_CMOS: u16 = 8;

struct LinuxRuntime {
    uart_lcr: u8,
    uart_ier: u8,
    uart_mcr: u8,
    serial_match: usize,
    pio_match: usize,
    serial_bytes: u32,
    marker_seen: bool,
    pio_marker_seen: bool,
    pic_master_mask: u8,
    pic_slave_mask: u8,
    pic_master_vector: u8,
    pic_slave_vector: u8,
    pic_init_stage: [u8; 2],
    pic_in_service: u16,
    pic_eois: u32,
    timer_injections: u32,
    kernel_gs_base: u64,
    pit_access: u8,
    pit_write_high: bool,
    pit_latch: u16,
    pit_reload: u32,
    pit_remaining: u32,
    pit_active: bool,
    timer_countdown: u32,
    cmos_index: u8,
    cmos_value: u8,
    pio_map: PortMap<12>,
    pio_probe: PioProbe,
    pio_reads: u32,
    pio_writes: u32,
    last_pio_port: u16,
    last_pio_qualification: u64,
    last_pio_width: u8,
    msrs: [(u32, u64); 64],
    msr_count: usize,
}

impl LinuxRuntime {
    const fn new() -> Self {
        Self {
            uart_lcr: 0,
            uart_ier: 0,
            uart_mcr: 0,
            serial_match: 0,
            pio_match: 0,
            serial_bytes: 0,
            marker_seen: false,
            pio_marker_seen: false,
            pic_master_mask: 0xff,
            pic_slave_mask: 0xff,
            pic_master_vector: 0x20,
            pic_slave_vector: 0x28,
            pic_init_stage: [0; 2],
            pic_in_service: 0,
            pic_eois: 0,
            timer_injections: 0,
            kernel_gs_base: 0,
            pit_access: 3,
            pit_write_high: false,
            pit_latch: 0,
            pit_reload: 0,
            pit_remaining: 0,
            pit_active: false,
            timer_countdown: 1024,
            cmos_index: 0,
            cmos_value: 0,
            pio_map: PortMap::<12>::new()
                .with_claim(0x20, 2, PIO_PIC_MASTER)
                .with_claim(0x40, 4, PIO_PIT)
                .with_claim(0x70, 2, PIO_CMOS)
                .with_claim(0x60, 5, PIO_I8042)
                .with_claim(0x80, 16, PIO_DISCARD)
                .with_claim(0x2e8, 8, PIO_DISCARD)
                .with_claim(0x2f8, 8, PIO_DISCARD)
                .with_claim(0x3e8, 8, PIO_DISCARD)
                .with_claim(0xa0, 2, PIO_PIC_SLAVE)
                .with_claim(0x3f8, 8, PIO_UART)
                .with_claim(PIO_PROBE_BASE, 32, PIO_PROBE),
            pio_probe: PioProbe::new(),
            pio_reads: 0,
            pio_writes: 0,
            last_pio_port: 0,
            last_pio_qualification: 0,
            last_pio_width: 0,
            msrs: [(0, 0); 64],
            msr_count: 0,
        }
    }

    fn serial_byte(&mut self, byte: u8) {
        self.serial_bytes = self.serial_bytes.saturating_add(1);
        if !self.marker_seen {
            if byte == LINUX_MARKER[self.serial_match] {
                self.serial_match += 1;
                if self.serial_match == LINUX_MARKER.len() {
                    self.marker_seen = true;
                }
            } else {
                self.serial_match = usize::from(byte == LINUX_MARKER[0]);
            }
        }
        if !self.pio_marker_seen {
            if byte == PIO_MARKER[self.pio_match] {
                self.pio_match += 1;
                if self.pio_match == PIO_MARKER.len() {
                    self.pio_marker_seen = true;
                }
            } else {
                self.pio_match = usize::from(byte == PIO_MARKER[0]);
            }
        }
        if byte == b'\n' {
            crate::arch::console_write_byte(b'\r');
        }
        crate::arch::console_write_byte(byte);
    }

    fn msr_read(&self, index: u32) -> Option<u64> {
        self.msrs[..self.msr_count]
            .iter()
            .rev()
            .find_map(|(saved, value)| (*saved == index).then_some(*value))
    }

    fn msr_write(&mut self, index: u32, value: u64) -> bool {
        if let Some((_, saved)) = self.msrs[..self.msr_count]
            .iter_mut()
            .rev()
            .find(|(saved, _)| *saved == index)
        {
            *saved = value;
            return true;
        }
        if self.msr_count == self.msrs.len() {
            return false;
        }
        self.msrs[self.msr_count] = (index, value);
        self.msr_count += 1;
        true
    }

    fn syscall_msr(&self, index: u32) -> u64 {
        match index {
            0xc000_0081 | 0xc000_0082 | 0xc000_0083 | 0xc000_0084 => {
                self.msr_read(index).unwrap_or(0)
            }
            0xc000_0102 => self.kernel_gs_base,
            _ => 0,
        }
    }

    fn pic_out(&mut self, port: u16, value: u8) {
        let slave = port >= 0xa0;
        let index = usize::from(slave);
        if self.pic_init_stage[index] != 0 {
            match self.pic_init_stage[index] {
                1 => {
                    if slave {
                        self.pic_slave_vector = value & 0xf8;
                    } else {
                        self.pic_master_vector = value & 0xf8;
                    }
                    self.pic_init_stage[index] = 2;
                }
                2 => self.pic_init_stage[index] = 3,
                _ => self.pic_init_stage[index] = 0,
            }
            return;
        }
        match port {
            0x20 => {
                if value & 0x10 != 0 {
                    self.pic_init_stage[0] = 1;
                    self.pic_master_mask = 0xff;
                } else if value & 0x20 != 0 {
                    let irq = if value & 0xe0 == 0x60 {
                        (value & 7) as u8
                    } else {
                        self.pic_in_service.trailing_zeros().min(15) as u8
                    };
                    self.pic_in_service &= !(1u16 << irq);
                    self.pic_eois = self.pic_eois.saturating_add(1);
                }
            }
            0x21 => self.pic_master_mask = value,
            0xa0 => {
                if value & 0x10 != 0 {
                    self.pic_init_stage[1] = 1;
                    self.pic_slave_mask = 0xff;
                } else if value & 0x20 != 0 {
                    // Slave EOI is not needed for the UP timer path.
                }
            }
            0xa1 => self.pic_slave_mask = value,
            _ => {}
        }
    }

    fn pic_in(&self, port: u16) -> u8 {
        match port {
            0x21 => self.pic_master_mask,
            0xa1 => self.pic_slave_mask,
            0x20 | 0xa0 => 0,
            _ => 0,
        }
    }

    fn pit_out_command(&mut self, value: u8) {
        let channel = value >> 6;
        if channel == 0 {
            self.pit_access = (value >> 4) & 3;
            self.pit_write_high = false;
            self.pit_latch = 0;
        }
    }

    fn pit_out_data(&mut self, value: u8) {
        match self.pit_access {
            1 => {
                self.pit_reload = u32::from(value);
                self.pit_write_high = false;
            }
            2 => {
                self.pit_reload = u32::from(value) << 8;
                self.pit_write_high = false;
            }
            3 => {
                if !self.pit_write_high {
                    self.pit_latch = u16::from(value);
                    self.pit_write_high = true;
                } else {
                    self.pit_reload = (u32::from(value) << 8) | u32::from(self.pit_latch);
                    self.pit_write_high = false;
                }
            }
            _ => {}
        }
        if self.pit_reload != 0 {
            self.pit_remaining = self.pit_reload;
            self.pit_active = true;
        }
    }

    fn pit_in_data(&mut self) -> u8 {
        if !self.pit_active || self.pit_reload == 0 {
            return 0xff;
        }
        let value = self.pit_remaining & 0xffff;
        if !self.pit_write_high {
            self.pit_write_high = true;
            value as u8
        } else {
            self.pit_write_high = false;
            (value >> 8) as u8
        }
    }

    fn pio_in(&mut self, port: u16, width: PioWidth) -> Result<u64, PioError> {
        let token = self.pio_map.route(port).ok_or(PioError::UnmappedPort)?;
        let value = match token {
            PIO_UART => {
                byte_width(width)?;
                u64::from(match (port - 0x3f8) as u8 {
                    0 => {
                        if self.uart_lcr & 0x80 != 0 {
                            1
                        } else {
                            0
                        }
                    }
                    1 => {
                        if self.uart_lcr & 0x80 != 0 {
                            0
                        } else {
                            self.uart_ier
                        }
                    }
                    2 => 1,
                    3 => self.uart_lcr,
                    4 => self.uart_mcr,
                    5 => 0x60,
                    6 => 0xb0,
                    _ => 0,
                })
            }
            PIO_PIC_MASTER | PIO_PIC_SLAVE => {
                byte_width(width)?;
                u64::from(self.pic_in(port))
            }
            PIO_PIT => {
                byte_width(width)?;
                if port == 0x40 {
                    u64::from(self.pit_in_data())
                } else {
                    0
                }
            }
            PIO_I8042 => {
                byte_width(width)?;
                if port == 0x64 {
                    0x14
                } else {
                    0
                }
            }
            PIO_CMOS => {
                byte_width(width)?;
                if port == 0x70 {
                    u64::from(self.cmos_index)
                } else {
                    u64::from(self.cmos_value)
                }
            }
            PIO_DISCARD => {
                byte_width(width)?;
                0
            }
            PIO_PROBE => {
                let offset = u64::from(port - PIO_PROBE_BASE);
                self.pio_probe.read(offset, width)?
            }
            _ => return Err(PioError::UnmappedPort),
        };
        self.pio_reads = self.pio_reads.saturating_add(1);
        Ok(value & width.mask())
    }

    fn pio_out(&mut self, port: u16, width: PioWidth, value: u64) -> Result<(), PioError> {
        let token = self.pio_map.route(port).ok_or(PioError::UnmappedPort)?;
        match token {
            PIO_UART => {
                byte_width(width)?;
                match (port - 0x3f8) as u8 {
                    0 if self.uart_lcr & 0x80 == 0 => self.serial_byte(value as u8),
                    1 if self.uart_lcr & 0x80 == 0 => self.uart_ier = value as u8,
                    3 => self.uart_lcr = value as u8,
                    4 => self.uart_mcr = value as u8,
                    _ => {}
                }
            }
            PIO_PIC_MASTER | PIO_PIC_SLAVE => {
                byte_width(width)?;
                self.pic_out(port, value as u8);
            }
            PIO_PIT => {
                byte_width(width)?;
                if port == 0x40 {
                    self.pit_out_data(value as u8);
                } else if port == 0x43 {
                    self.pit_out_command(value as u8);
                }
            }
            PIO_I8042 => {
                byte_width(width)?;
                // The minimal guest only probes the controller status. A
                // command write is accepted as an observation point but does
                // not invent a keyboard reset or interrupt.
            }
            PIO_CMOS => {
                byte_width(width)?;
                if port == 0x70 {
                    self.cmos_index = value as u8 & 0x7f;
                } else {
                    self.cmos_value = value as u8;
                }
            }
            PIO_DISCARD => {
                byte_width(width)?;
            }
            PIO_PROBE => {
                let offset = u64::from(port - PIO_PROBE_BASE);
                self.pio_probe.write(offset, width, value)?;
            }
            _ => return Err(PioError::UnmappedPort),
        }
        self.pio_writes = self.pio_writes.saturating_add(1);
        Ok(())
    }

    fn timer_interrupt(&mut self) -> Option<u8> {
        // The minimal guest installs its vector table after probing PIC/PIT.
        // Delivering an early timer vectors causes an unhandled 0x20 IRQ and
        // traps the guest before userspace; HLT remains the single forced
        // wake-up point.
        if !self.marker_seen {
            return None;
        }
        if !self.pit_active || self.pic_in_service & 1 != 0 {
            return None;
        }
        // The minimal-guest acceptance uses exits as deterministic virtual
        // time. Frequency is not used as a performance measurement.
        self.timer_countdown = self.timer_countdown.saturating_sub(1);
        if self.timer_countdown != 0 {
            return None;
        }
        self.timer_countdown = 1024;
        if self.pic_master_mask & 1 != 0 {
            return None;
        }
        self.pit_remaining = self.pit_reload;
        self.pic_in_service |= 1;
        self.timer_injections = self.timer_injections.saturating_add(1);
        Some(self.pic_master_vector.wrapping_add(0))
    }

    fn force_timer_interrupt(&mut self) -> Option<u8> {
        if !self.pit_active || self.pic_in_service & 1 != 0 || self.pic_master_mask & 1 != 0 {
            return None;
        }
        self.pit_remaining = self.pit_reload;
        self.pic_in_service |= 1;
        self.timer_injections = self.timer_injections.saturating_add(1);
        Some(self.pic_master_vector)
    }

    fn raise_irq(&mut self, irq: u8) -> Option<u8> {
        if irq >= 8
            || self.pic_master_mask & (1u8 << irq) != 0
            || self.pic_in_service & (1u16 << irq) != 0
        {
            return None;
        }
        self.pic_in_service |= 1u16 << irq;
        Some(self.pic_master_vector.wrapping_add(irq))
    }
}

fn byte_width(width: PioWidth) -> Result<(), PioError> {
    if width == PioWidth::Byte {
        Ok(())
    } else {
        Err(PioError::UnsupportedWidth)
    }
}

pub struct VmxVm {
    host: HostRegisters,
    restore: EntryRestore,
    _vmxon: Region,
    vmcs: Region,
    _msr_bitmap: Region,
    _io_bitmap_a: Region,
    _io_bitmap_b: Region,
    _host_xsave: Option<HostXsave>,
    controls: Controls,
    basic: u64,
    guest: GuestExecutionState,
    gprs: [u64; 16],
    pending_interrupt: Option<u8>,
    /// PIO security generation captured when this VM execution context starts.
    ///
    /// 设备面复位后旧上下文保留失效租约，下一次 I/O 必须失败关闭。
    pio_lease: Option<crate::hwv5_policy::Hwv5Lease>,
    launched: bool,
    active: bool,
}

impl VmxVm {
    pub fn new(ept_root: u64, guest: GuestExecutionState) -> Result<Self, VmxError> {
        if ept_root & 0xfff != 0 {
            return Err(VmxError::InvalidState { code: ept_root });
        }
        let (controls, basic) = controls()?;
        let vmxon_region = Region::allocate_zeroed(0)?;
        let vmcs = Region::allocate_zeroed(0)?;
        let msr_bitmap = Region::allocate_zeroed(0xff)?;
        let io_bitmap_a = Region::allocate_zeroed(0xff)?;
        let io_bitmap_b = Region::allocate_zeroed(0xff)?;
        let revision = (basic & 0x7fff_ffff) as u32;
        write_revision(&vmxon_region, revision)?;
        write_revision(&vmcs, revision)?;

        let (host, restore) = enable_vmx()?;
        if guest.state.xcr0 & !restore.xcr0_supported != 0 {
            restore_entry(restore);
            return Err(VmxError::InvalidState {
                code: guest.state.xcr0,
            });
        }
        if restore.cr4_osxsave {
            write_xcr0(guest.state.xcr0);
        }
        let mut host_xsave = if restore.cr4_osxsave {
            match HostXsave::new(guest.state.xcr0) {
                Ok(mut state) => {
                    if let Err(error) = state.save() {
                        restore_entry(restore);
                        return Err(error);
                    }
                    Some(state)
                }
                Err(error) => {
                    restore_entry(restore);
                    return Err(error);
                }
            }
        } else {
            None
        };
        if let Err(error) = vmxon(vmxon_region.physical()) {
            if let Some(state) = host_xsave.as_mut() {
                state.restore();
            }
            restore_entry(restore);
            return Err(error);
        }
        let initialized = vmclear(vmcs.physical())
            .and_then(|_| vmptrld(vmcs.physical()))
            .and_then(|_| {
                initialize_vmcs(
                    ept_root,
                    guest,
                    &host,
                    controls,
                    msr_bitmap.physical(),
                    io_bitmap_a.physical(),
                    io_bitmap_b.physical(),
                )
            });
        if let Err(error) = initialized {
            let _ = vmxoff();
            if let Some(state) = host_xsave.as_mut() {
                state.restore();
            }
            restore_entry(restore);
            return Err(error);
        }

        let mut gprs = [0u64; 16];
        gprs.copy_from_slice(&guest.state.registers[..16]);
        Ok(Self {
            host,
            restore,
            _vmxon: vmxon_region,
            vmcs,
            _msr_bitmap: msr_bitmap,
            _io_bitmap_a: io_bitmap_a,
            _io_bitmap_b: io_bitmap_b,
            _host_xsave: host_xsave,
            controls,
            basic,
            guest,
            gprs,
            pending_interrupt: None,
            pio_lease: crate::hwv5_policy::lease(crate::hwv5_policy::Hwv5Surface::Pio),
            launched: false,
            active: true,
        })
    }

    /// Enter a native Linux guest through the x86 64-bit boot protocol.
    /// Exceptions remain owned by the guest kernel instead of terminating the
    /// VMM run loop; I/O and architectural MSRs are virtualized below.
    pub fn new_linux(ept_root: u64, guest: GuestExecutionState) -> Result<Self, VmxError> {
        let mut vm = Self::new(ept_root, guest)?;
        vm.controls.primary &= !PROC_RDTSC_EXITING;
        let configured = vmwrite(EXCEPTION_BITMAP, 0)
            .and_then(|_| vmwrite(PROC_BASED_CONTROLS, u64::from(vm.controls.primary)))
            .and_then(|_| vmwrite(CR0_GUEST_HOST_MASK, u64::from(u32::MAX)))
            .and_then(|_| vmwrite(CR4_GUEST_HOST_MASK, u64::from(u32::MAX)));
        if let Err(error) = configured {
            let _ = vm.shutdown();
            return Err(error);
        }
        Ok(vm)
    }

    pub fn run(&mut self) -> Result<RunReport, VmxError> {
        self.run_with_observer(&mut |_| Ok(VmxObserverAction::Continue))
    }

    /// Run the minimal Linux guest until it halts or reaches the bounded exit
    /// budget. The serial marker is derived only from bytes emitted by the
    /// guest through COM1.
    pub fn run_linux(&mut self) -> Result<LinuxReport, VmxError> {
        self.run_linux_with(&mut NoLinuxDevices)
    }

    pub fn run_linux_with<B: LinuxPlatform>(
        &mut self,
        devices: &mut B,
    ) -> Result<LinuxReport, VmxError> {
        let mut linux = LinuxRuntime::new();
        let mut report = RunReport {
            xsave_enabled: self._host_xsave.is_some(),
            ..RunReport::default()
        };
        for _ in 0..2_000_000 {
            if self.pending_interrupt.is_none()
                && self.guest.state.rflags & 0x200 != 0
                && vmread(GUEST_INTERRUPTIBILITY).unwrap_or(1) == 0
            {
                self.pending_interrupt = devices
                    .take_irq()
                    .and_then(|irq| {
                        let vector = linux.raise_irq(irq);
                        if vector.is_none() {
                            devices.return_irq(irq);
                        }
                        vector
                    })
                    .or_else(|| linux.timer_interrupt());
            }
            self.stage_state()?;
            self.load_linux_syscall_msrs(&linux);
            let resume = self.launched;
            let status = unsafe { jsr_vmx_run(u64::from(resume)) };
            if status == 0 {
                linux.kernel_gs_base = unsafe { rdmsr(0xc000_0102) };
            }
            self.restore_host_syscall_msrs();
            if status != 0 {
                let code = read_vm_error();
                return Err(if resume {
                    VmxError::Resume { code }
                } else {
                    VmxError::Launch { code }
                });
            }
            self.pending_interrupt = None;
            self.launched = true;
            self.collect_gprs();
            report.exits += 1;
            let raw_reason = vmread(VM_EXIT_REASON)? as u32;
            if raw_reason & 0x8000_0000 != 0 {
                self.dump_entry_failure(raw_reason);
                return Err(VmxError::EntryFailure { reason: raw_reason });
            }
            self.guest.state.rip = vmread(GUEST_RIP)?;
            self.guest.rsp = vmread(GUEST_RSP)?;
            self.guest.state.rflags = vmread(GUEST_RFLAGS)?;
            let reason = raw_reason & 0xffff;
            let length = vmread(VM_EXIT_INSTRUCTION_LENGTH).unwrap_or(0);
            match reason {
                EXIT_CPUID => {
                    report.cpuid += 1;
                    self.emulate_linux_cpuid();
                    self.advance_rip(length);
                }
                EXIT_RDTSC | EXIT_RDTSCP => {
                    report.rdtsc += 1;
                    let (lo, hi) = self.guest_tsc();
                    self.set_gpr(0, u64::from(lo));
                    self.set_gpr(2, u64::from(hi));
                    self.advance_rip(length);
                }
                EXIT_MSR_READ => {
                    report.msr_reads += 1;
                    let index = self.gpr(1) as u32;
                    let value = self.linux_msr_read(index, &linux);
                    self.set_gpr(0, value as u32 as u64);
                    self.set_gpr(2, (value >> 32) as u32 as u64);
                    self.advance_rip(length);
                }
                EXIT_MSR_WRITE => {
                    let index = self.gpr(1) as u32;
                    let value =
                        u64::from(self.gpr(0) as u32) | (u64::from(self.gpr(2) as u32) << 32);
                    self.linux_msr_write(index, value, &mut linux)?;
                    self.advance_rip(length);
                }
                EXIT_IO => {
                    report.io += 1;
                    let qualification = vmread(EXIT_QUALIFICATION)?;
                    if let Err(error) = self.emulate_linux_io(qualification, length, &mut linux) {
                        kprintln!(
                            "[JSR-HWV5-PIO-FAIL] error={} qualification={:#x} length={} rip={:#x}",
                            error.name(),
                            qualification,
                            length,
                            self.guest.state.rip
                        );
                        return Err(VmxError::Pio(error));
                    }
                    self.advance_rip(length);
                }
                EXIT_CR_ACCESS => {
                    self.emulate_linux_cr_access(vmread(EXIT_QUALIFICATION)?, length)?;
                }
                EXIT_CR8_ACCESS => {
                    return Err(VmxError::InvalidState {
                        code: 0x8_0000_0000 | vmread(EXIT_QUALIFICATION).unwrap_or(0),
                    });
                }
                EXIT_EPT_VIOLATION => {
                    let physical = vmread(GUEST_PHYSICAL_ADDRESS).unwrap_or(u64::MAX);
                    let qualification = vmread(EXIT_QUALIFICATION).unwrap_or(u64::MAX);
                    if self.emulate_linux_mmio(physical, qualification, length, devices)? {
                        continue;
                    }
                    kprintln!(
                        "[JSR-HWV4-LINUX-FAIL] ept physical={:#x} qualification={:#x} rip={:#x} rsp={:#x} cr3={:#x}",
                        physical,
                        qualification,
                        self.guest.state.rip,
                        self.guest.rsp,
                        self.guest.state.cr3
                    );
                    return Err(VmxError::InvalidState {
                        code: 0xe000_0000_0000_0000
                            | ((physical & 0xffff_ffff) << 32)
                            | (qualification & 0xffff_ffff),
                    });
                }
                EXIT_HLT => {
                    if !linux.marker_seen {
                        self.pending_interrupt = linux.force_timer_interrupt();
                        if self.pending_interrupt.is_some() {
                            vmwrite(GUEST_INTERRUPTIBILITY, 0)?;
                            vmwrite(GUEST_ACTIVITY_STATE, 0)?;
                            continue;
                        }
                    }
                    report.halted = true;
                    report.serial_bytes = linux.serial_bytes;
                    report.linux_marker = linux.marker_seen;
                    return Ok(LinuxReport {
                        exits: report.exits,
                        serial_bytes: report.serial_bytes,
                        timer_interrupts: linux.timer_injections,
                        timer_eois: linux.pic_eois,
                        pio_reads: linux.pio_reads,
                        pio_writes: linux.pio_writes,
                        pio_probe_generation: linux.pio_probe.generation(),
                        pio_requests: linux.pio_probe.requests(),
                        pio_cancels: linux.pio_probe.cancels(),
                        pio_marker: linux.pio_marker_seen,
                        marker: report.linux_marker,
                        halted: true,
                    });
                }
                EXIT_EXCEPTION_NMI => {
                    let info = vmread(VM_EXIT_INTR_INFO)? as u32;
                    return Err(VmxError::InvalidState {
                        code: 0xf_0000_0000 | u64::from(info),
                    });
                }
                other => {
                    kprintln!(
                        "[JSR-HWV4-LINUX-FAIL] exit={} rip={:#x} rsp={:#x} cr3={:#x} rax={:#x} rbx={:#x} rbp={:#x} rsi={:#x} rdi={:#x} cr4={:#x}",
                        other,
                        vmread(GUEST_RIP).unwrap_or(u64::MAX),
                        vmread(GUEST_RSP).unwrap_or(u64::MAX),
                        vmread(GUEST_CR3).unwrap_or(u64::MAX),
                        self.gpr(0),
                        self.gpr(3),
                        self.gpr(5),
                        self.gpr(6),
                        self.gpr(7),
                        vmread(GUEST_CR4).unwrap_or(u64::MAX)
                    );
                    return Err(VmxError::InvalidState {
                        code: u64::from(other),
                    });
                }
            }
        }
        kprintln!(
            "[JSR-HWV4-LINUX-FAIL] exit_budget cpuid={} io={} msr={} rdtsc={} ept={} rip={:#x} rsp={:#x}",
            report.cpuid,
            report.io,
            report.msr_reads,
            report.rdtsc,
            report.ept_violations,
            self.guest.state.rip,
            self.guest.rsp
        );
        kprintln!(
            "[JSR-HWV4-LINUX-FAIL] last_pio port={:#x} qualification={:#x} width={} reads={} writes={} pit_remaining={} pit_reload={} irq_masked={}",
            linux.last_pio_port,
            linux.last_pio_qualification,
            linux.last_pio_width,
            linux.pio_reads,
            linux.pio_writes,
            linux.pit_remaining,
            linux.pit_reload,
            linux.pic_master_mask & 1 != 0
        );
        Err(VmxError::TooManyExits)
    }

    /// Run the guest while publishing every architectural exit to the caller.
    /// The observer runs after hardware state has been collected and before
    /// the backend emulates the exit. A delivery failure aborts the run; the
    /// caller must still shut the backend down and fail the vCPU lifecycle.
    pub fn run_with_observer<F>(&mut self, observer: &mut F) -> Result<RunReport, VmxError>
    where
        F: FnMut(VmExitEvent) -> Result<VmxObserverAction, VmxError>,
    {
        let mut report = RunReport {
            xsave_enabled: self._host_xsave.is_some(),
            ..RunReport::default()
        };
        for _ in 0..256 {
            self.stage_state()?;
            let resume = self.launched;
            let status = unsafe { jsr_vmx_run(u64::from(resume)) };
            if status != 0 {
                let code = read_vm_error();
                return Err(if resume {
                    VmxError::Resume { code }
                } else {
                    VmxError::Launch { code }
                });
            }
            self.pending_interrupt = None;
            self.launched = true;
            self.collect_gprs();
            report.exits += 1;
            let raw_reason = vmread(VM_EXIT_REASON)? as u32;
            if raw_reason & 0x8000_0000 != 0 {
                self.dump_entry_failure(raw_reason);
                return Err(VmxError::EntryFailure { reason: raw_reason });
            }
            self.guest.state.rip = vmread(GUEST_RIP)?;
            self.guest.rsp = vmread(GUEST_RSP)?;
            let reason = raw_reason & 0xffff;
            let length = vmread(VM_EXIT_INSTRUCTION_LENGTH).unwrap_or(0);
            let intr = vmread(VM_EXIT_INTR_INFO).unwrap_or(0);
            let action = observer(VmExitEvent {
                backend: Backend::Vmx,
                reason,
                qualification: vmread(EXIT_QUALIFICATION).unwrap_or(0),
                guest_physical: vmread(GUEST_PHYSICAL_ADDRESS).unwrap_or(0),
                vector: intr as u8,
                instruction_length: length as u8,
            })?;
            if let VmxObserverAction::Inject(vector) = action {
                self.pending_interrupt = Some(vector);
            }
            match reason {
                EXIT_CPUID => {
                    report.cpuid += 1;
                    self.emulate_cpuid();
                    self.advance_rip(length);
                }
                EXIT_RDTSC => {
                    report.rdtsc += 1;
                    let (lo, hi) = self.guest_tsc();
                    self.set_gpr(0, u64::from(lo));
                    self.set_gpr(2, u64::from(hi));
                    self.advance_rip(length);
                }
                EXIT_MSR_READ => {
                    report.msr_reads += 1;
                    if self.gpr(1) as u32 != 0x10 {
                        return Err(VmxError::InvalidState { code: self.gpr(1) });
                    }
                    let (lo, hi) = self.guest_tsc();
                    self.set_gpr(0, u64::from(lo));
                    self.set_gpr(2, u64::from(hi));
                    self.advance_rip(length);
                }
                EXIT_MSR_WRITE => {
                    return Err(VmxError::InvalidState { code: self.gpr(1) });
                }
                EXIT_IO => {
                    report.io += 1;
                    let qualification = vmread(EXIT_QUALIFICATION)?;
                    if (qualification >> 16) as u16 != 0x80 {
                        return Err(VmxError::InvalidState {
                            code: qualification,
                        });
                    }
                    if qualification & (1 << 3) != 0 {
                        self.set_gpr(0, 0xff);
                    }
                    self.advance_rip(length);
                }
                EXIT_EPT_VIOLATION => {
                    report.ept_violations += 1;
                    let _qualification = vmread(EXIT_QUALIFICATION)?;
                    let _physical = vmread(GUEST_PHYSICAL_ADDRESS)?;
                    self.advance_rip(if length == 0 { 3 } else { length });
                }
                EXIT_EXCEPTION_NMI => {
                    let info = vmread(VM_EXIT_INTR_INFO)? as u32;
                    let vector = (info & 0xff) as u8;
                    report.exceptions += 1;
                    kprintln!(
                        "[JSR-HWV4-DBG] exception vector={} info={:#x} error={:#x} rip={:#x}",
                        vector,
                        info,
                        vmread(VM_EXIT_INTR_ERROR_CODE).unwrap_or(0),
                        self.guest.state.rip
                    );
                    if vector == 6 {
                        return Ok(report);
                    }
                    return Err(VmxError::InvalidState {
                        code: u64::from(info),
                    });
                }
                EXIT_RDTSCP => {
                    let (lo, hi) = self.guest_tsc();
                    self.set_gpr(0, u64::from(lo));
                    self.set_gpr(2, u64::from(hi));
                    self.advance_rip(length);
                }
                EXIT_HLT => {
                    report.halted = true;
                    return Ok(report);
                }
                other => {
                    kprintln!(
                        "[JSR-HWV2-DBG] exit reason={} rip={:#x} rsp={:#x} cr3={:#x} intr={:#x}",
                        other,
                        vmread(GUEST_RIP).unwrap_or(u64::MAX),
                        vmread(GUEST_RSP).unwrap_or(u64::MAX),
                        vmread(GUEST_CR3).unwrap_or(u64::MAX),
                        vmread(VM_EXIT_INTR_INFO).unwrap_or(u64::MAX)
                    );
                    return Err(VmxError::InvalidState {
                        code: u64::from(other),
                    });
                }
            }
        }
        Err(VmxError::TooManyExits)
    }

    pub fn report(&self) -> (u64, u64, u64) {
        (
            self.controls.primary.into(),
            self.controls.secondary.into(),
            self.basic,
        )
    }

    fn emulate_linux_mmio<B: LinuxPlatform>(
        &mut self,
        physical: u64,
        qualification: u64,
        length: u64,
        devices: &mut B,
    ) -> Result<bool, VmxError> {
        if qualification & (1 << 2) != 0 {
            return Ok(false);
        }
        let mut bytes = [0u8; 15];
        if !self.read_guest_va(devices, self.guest.state.rip, &mut bytes) {
            return Ok(false);
        }
        let Some(access) = decode_memory_data_access(&bytes) else {
            return Ok(false);
        };
        let write = qualification & (1 << 1) != 0;
        if write != access.store {
            return Ok(false);
        }
        if access.store {
            if !devices.write_mmio(physical, access.width, self.gpr(access.register)) {
                return Ok(false);
            }
        } else {
            let Some(value) = devices.read_mmio(physical, access.width) else {
                return Ok(false);
            };
            self.set_gpr(access.register, value);
        }
        self.advance_rip(if length == 0 {
            access.length as u64
        } else {
            length
        });
        Ok(true)
    }

    fn read_guest_va<B: LinuxPlatform>(&self, devices: &mut B, va: u64, out: &mut [u8]) -> bool {
        let mut done = 0;
        let mut address = va;
        let cr3 = vmread(GUEST_CR3).unwrap_or(self.guest.state.cr3);
        while done < out.len() {
            let Some(gpa) = guest_va_to_gpa(cr3, address, devices) else {
                return false;
            };
            let page_left = 4096 - (address & 0xfff) as usize;
            let count = (out.len() - done).min(page_left);
            if !devices.read_guest(gpa, &mut out[done..done + count]) {
                return false;
            }
            done += count;
            address = address.wrapping_add(count as u64);
        }
        true
    }

    fn emulate_linux_cpuid(&mut self) {
        let leaf = self.gpr(0) as u32;
        let subleaf = self.gpr(1) as u32;
        let result = match leaf {
            0 => {
                let mut value = cpuid(0, 0);
                value.eax = 0x16;
                value
            }
            1 => {
                let mut value = cpuid(1, 0);
                // Native PIC/PIT boot with an explicit device model. VMX,
                // APIC, x2APIC, XSAVE and hypervisor leaves are not exposed.
                value.ecx &= (1 << 0) | (1 << 1) | (1 << 9);
                value.edx &= (1 << 0)
                    | (1 << 3)
                    | (1 << 4)
                    | (1 << 5)
                    | (1 << 6)
                    | (1 << 7)
                    | (1 << 8)
                    | (1 << 11)
                    | (1 << 12)
                    | (1 << 13)
                    | (1 << 15)
                    | (1 << 16)
                    | (1 << 19)
                    | (1 << 23)
                    | (1 << 24)
                    | (1 << 25)
                    | (1 << 26);
                value
            }
            7 => core::arch::x86_64::CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
            0x15 => core::arch::x86_64::CpuidResult {
                eax: 1,
                ebx: 100,
                ecx: 20_000_000,
                edx: 0,
            },
            0x16 => core::arch::x86_64::CpuidResult {
                eax: 2_000,
                ebx: 2_000,
                ecx: 100,
                edx: 0,
            },
            0x8000_0000 => {
                let mut value = cpuid(0x8000_0000, 0);
                value.eax = 0x8000_0008;
                value
            }
            0x8000_0001 => {
                let mut value = cpuid(0x8000_0001, 0);
                value.ecx &= (1 << 0) | (1 << 5) | (1 << 6) | (1 << 11);
                value.edx &= (1 << 11) | (1 << 20) | (1 << 26) | (1 << 27) | (1 << 29) | (1 << 30);
                value
            }
            0x8000_0008 => core::arch::x86_64::CpuidResult {
                eax: 48,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
            0x4000_0000..=0x4fff_ffff => core::arch::x86_64::CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
            _ => cpuid(leaf, subleaf),
        };
        self.set_gpr(0, u64::from(result.eax));
        self.set_gpr(1, u64::from(result.ecx));
        self.set_gpr(2, u64::from(result.edx));
        self.set_gpr(3, u64::from(result.ebx));
    }

    fn load_linux_syscall_msrs(&self, linux: &LinuxRuntime) {
        // SAFETY: these are the architectural MSRs used by SYSCALL/SWAPGS.
        // Host values are restored immediately after every VM exit.
        unsafe {
            wrmsr(0xc000_0081, linux.syscall_msr(0xc000_0081));
            wrmsr(0xc000_0082, linux.syscall_msr(0xc000_0082));
            wrmsr(0xc000_0083, linux.syscall_msr(0xc000_0083));
            wrmsr(0xc000_0084, linux.syscall_msr(0xc000_0084));
            wrmsr(0xc000_0102, linux.kernel_gs_base);
        }
    }

    fn restore_host_syscall_msrs(&self) {
        // SAFETY: restore the exact hardware values captured before VM entry.
        unsafe {
            wrmsr(0xc000_0081, self.host.star);
            wrmsr(0xc000_0082, self.host.lstar);
            wrmsr(0xc000_0083, self.host.cstar);
            wrmsr(0xc000_0084, self.host.sfmask);
            wrmsr(0xc000_0102, self.host.kernel_gs_base);
        }
    }

    fn linux_msr_read(&self, index: u32, linux: &LinuxRuntime) -> u64 {
        if let Some(value) = linux.msr_read(index) {
            return value;
        }
        match index {
            0x10 => {
                let (lo, hi) = self.guest_tsc();
                (u64::from(hi) << 32) | u64::from(lo)
            }
            0x1b => 0,
            0xfe => 0x500,
            0x2ff => 0x800,
            0xc000_0080 => self.guest.efer,
            0xc000_0102 => linux.kernel_gs_base,
            _ => 0,
        }
    }

    fn linux_msr_write(
        &mut self,
        index: u32,
        mut value: u64,
        linux: &mut LinuxRuntime,
    ) -> Result<(), VmxError> {
        if !linux.msr_write(index, value) {
            return Err(VmxError::InvalidState {
                code: u64::from(index),
            });
        }
        match index {
            0x277 => vmwrite(GUEST_IA32_PAT, value)?,
            0xc000_0080 => {
                value |= 0x500;
                self.guest.efer = value;
                if !linux.msr_write(index, value) {
                    return Err(VmxError::InvalidState {
                        code: u64::from(index),
                    });
                }
                vmwrite(GUEST_IA32_EFER, value)?;
            }
            0xc000_0100 => vmwrite(GUEST_FS_BASE, value)?,
            0xc000_0101 => vmwrite(GUEST_GS_BASE, value)?,
            0xc000_0102 => linux.kernel_gs_base = value,
            _ => {}
        }
        Ok(())
    }

    fn emulate_linux_io(
        &mut self,
        qualification: u64,
        length: u64,
        linux: &mut LinuxRuntime,
    ) -> Result<(), PioError> {
        let register = ((qualification >> 8) & 0xf) as usize;
        let access = PioAccess::decode_vmx(qualification, length, self.gpr(register))?;
        linux.last_pio_port = access.port;
        linux.last_pio_qualification = qualification;
        linux.last_pio_width = access.width.bytes();
        let allowed = match access.direction {
            PioDirection::In => crate::hwv5_policy::pio_read_at(self.pio_lease),
            PioDirection::Out => crate::hwv5_policy::pio_write_at(self.pio_lease),
        };
        if !allowed {
            return Err(PioError::NotReady);
        }
        match access.direction {
            PioDirection::In => {
                let value = linux.pio_in(access.port, access.width)?;
                self.set_gpr(usize::from(access.register), value);
            }
            PioDirection::Out => {
                linux.pio_out(access.port, access.width, access.value)?;
            }
        }
        // JPIO reset advances the device generation. Only this active context
        // adopts the replacement lease; another stale VM context remains
        // bound to the revoked generation.
        if access.direction == PioDirection::Out
            && access.port == PIO_PROBE_BASE + 8
            && access.value == u64::from(PIO_COMMAND_RESET)
        {
            self.pio_lease = Some(
                crate::hwv5_policy::rotate_surface(crate::hwv5_policy::Hwv5Surface::Pio)
                    .ok_or(PioError::NotReady)?,
            );
        }
        Ok(())
    }

    fn emulate_linux_cr_access(&mut self, qualification: u64, length: u64) -> Result<(), VmxError> {
        let cr = (qualification & 0xf) as u8;
        let access = ((qualification >> 4) & 3) as u8;
        let register = ((qualification >> 8) & 0xf) as usize;
        let cr0_fixed0 = unsafe { rdmsr(IA32_VMX_CR0_FIXED0) };
        let cr0_fixed1 = unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };
        let cr4_fixed0 = unsafe { rdmsr(IA32_VMX_CR4_FIXED0) };
        let cr4_fixed1 = unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };
        match access {
            0 => {
                let value = self.gpr(register);
                match cr {
                    0 => {
                        let value = (value & cr0_fixed1) | cr0_fixed0;
                        self.guest.state.cr0 = value;
                        vmwrite(GUEST_CR0, value)?;
                        vmwrite(CR0_READ_SHADOW, value)?;
                    }
                    3 => {
                        self.guest.state.cr3 = value;
                        vmwrite(GUEST_CR3, value)?;
                    }
                    4 => {
                        let value = (value & cr4_fixed1) | cr4_fixed0;
                        self.guest.state.cr4 = value;
                        vmwrite(GUEST_CR4, value)?;
                        vmwrite(CR4_READ_SHADOW, value)?;
                    }
                    8 => {}
                    _ => {
                        return Err(VmxError::InvalidState {
                            code: qualification,
                        })
                    }
                }
            }
            1 => {
                let value = match cr {
                    0 => self.guest.state.cr0,
                    3 => self.guest.state.cr3,
                    4 => self.guest.state.cr4,
                    8 => 0,
                    _ => {
                        return Err(VmxError::InvalidState {
                            code: qualification,
                        })
                    }
                };
                self.set_gpr(register, value);
            }
            2 => {
                let value = self.guest.state.cr0 & !(1 << 3);
                self.guest.state.cr0 = value;
                vmwrite(GUEST_CR0, value)?;
            }
            3 => {
                let value = qualification >> 16;
                let cr0 = (self.guest.state.cr0 & !0xffff) | (value & 0xffff) | cr0_fixed0;
                self.guest.state.cr0 = cr0;
                vmwrite(GUEST_CR0, cr0)?;
            }
            _ => {
                return Err(VmxError::InvalidState {
                    code: qualification,
                })
            }
        }
        self.advance_rip(if length == 0 { 3 } else { length });
        Ok(())
    }

    /// Override the guest IDT used for hardware event injection.
    pub fn set_guest_idt(&mut self, base: u64, limit: u16) -> Result<(), VmxError> {
        if base & 0xf != 0 {
            return Err(VmxError::InvalidState { code: base });
        }
        vmwrite(GUEST_IDTR_BASE, base)?;
        vmwrite(GUEST_IDTR_LIMIT, u64::from(limit))?;
        Ok(())
    }

    /// Override the guest GDT used by interrupt-gate selectors.
    pub fn set_guest_gdt(&mut self, base: u64, limit: u16) -> Result<(), VmxError> {
        if base & 0xf != 0 {
            return Err(VmxError::InvalidState { code: base });
        }
        vmwrite(GUEST_GDTR_BASE, base)?;
        vmwrite(GUEST_GDTR_LIMIT, u64::from(limit))?;
        Ok(())
    }

    /// Queue an external interrupt for the next VM entry.
    pub fn inject_external_interrupt(&mut self, vector: u8) -> Result<(), VmxError> {
        if vector < 32 {
            return Err(VmxError::InvalidState {
                code: u64::from(vector),
            });
        }
        self.pending_interrupt = Some(vector);
        Ok(())
    }

    pub fn guest_state(&self) -> VcpuState {
        let mut state = self.guest.state;
        state.registers[..16].copy_from_slice(&self.gprs);
        state.registers[4] = self.guest.rsp;
        state
    }

    pub fn shutdown(&mut self) -> Result<(), VmxError> {
        if !self.active {
            return Ok(());
        }
        let clear = vmclear(self.vmcs.physical());
        let off = vmxoff();
        if off.is_ok() {
            if let Some(state) = self._host_xsave.as_mut() {
                state.restore();
            }
            restore_entry(self.restore);
            restore_descriptor_tables(&self.host);
        }
        self.active = false;
        clear.and(off)
    }

    fn stage_state(&mut self) -> Result<(), VmxError> {
        vmwrite(GUEST_RIP, self.guest.state.rip)?;
        vmwrite(GUEST_RSP, self.guest.rsp)?;
        let pending_if = if self.pending_interrupt.is_some() {
            1 << 9
        } else {
            0
        };
        vmwrite(GUEST_RFLAGS, (self.guest.state.rflags | pending_if) | 2)?;
        let interruption = self
            .pending_interrupt
            .map(u64::from)
            .map(|vector| (1u64 << 31) | vector)
            .unwrap_or(0);
        vmwrite(ENTRY_INTR_INFO, interruption)?;
        // SAFETY: HWV-2 intentionally permits one active VM entry on the
        // boot processor; VmxVm owns that execution until run() returns.
        unsafe { JSR_VMX_GUEST_GPRS = self.gprs };
        Ok(())
    }

    fn collect_gprs(&mut self) {
        // SAFETY: same single-active-execution invariant as stage_state.
        self.gprs = unsafe { JSR_VMX_GUEST_GPRS };
        self.guest.state.registers[..16].copy_from_slice(&self.gprs);
    }

    fn gpr(&self, index: usize) -> u64 {
        self.gprs[index]
    }

    fn set_gpr(&mut self, index: usize, value: u64) {
        self.gprs[index] = value;
    }

    fn emulate_cpuid(&mut self) {
        let leaf = self.gpr(0) as u32;
        let subleaf = self.gpr(1) as u32;
        let result = cpuid(leaf, subleaf);
        self.set_gpr(0, u64::from(result.eax));
        self.set_gpr(3, u64::from(result.ebx));
        self.set_gpr(1, u64::from(result.ecx));
        self.set_gpr(2, u64::from(result.edx));
    }

    fn guest_tsc(&self) -> (u32, u32) {
        let value = host_tsc().wrapping_add(self.guest.tsc_offset as u64);
        (value as u32, (value >> 32) as u32)
    }

    fn advance_rip(&mut self, length: u64) {
        self.guest.state.rip = self.guest.state.rip.wrapping_add(length);
    }

    fn dump_entry_failure(&self, reason: u32) {
        kprintln!("[JSR-HWV2-DBG] entry_failure_begin reason={:#x}", reason);
        let instruction_error = vmread(VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);
        let cr0 = vmread(GUEST_CR0).unwrap_or(u64::MAX);
        let cr4 = vmread(GUEST_CR4).unwrap_or(u64::MAX);
        let efer = vmread(GUEST_IA32_EFER).unwrap_or(u64::MAX);
        let cs_ar = vmread(GUEST_CS_AR).unwrap_or(u64::MAX);
        let ss_ar = vmread(GUEST_SS_AR).unwrap_or(u64::MAX);
        let tr_ar = vmread(GUEST_TR_AR).unwrap_or(u64::MAX);
        let activity = vmread(GUEST_ACTIVITY_STATE).unwrap_or(u64::MAX);
        let interruptibility = vmread(GUEST_INTERRUPTIBILITY).unwrap_or(u64::MAX);
        kprintln!(
            "[JSR-HWV2-DBG] entry_failure reason={:#x} inst={} cr0={:#x} cr4={:#x} efer={:#x} cs_ar={:#x} ss_ar={:#x} tr_ar={:#x} activity={} interruptibility={:#x}",
            reason,
            instruction_error,
            cr0,
            cr4,
            efer,
            cs_ar,
            ss_ar,
            tr_ar,
            activity,
            interruptibility
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmxObserverAction {
    Continue,
    Inject(u8),
}

impl Drop for VmxVm {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn write_revision(region: &Region, revision: u32) -> Result<(), VmxError> {
    let Some(ptr) = crate::mm::phys_to_virt(region.physical()) else {
        return Err(VmxError::MissingPhysicalMap);
    };
    // SAFETY: private 4 KiB region allocated by Region.
    unsafe { (ptr as *mut u32).write_volatile(revision) };
    Ok(())
}

fn restore_entry(restore: EntryRestore) {
    // SAFETY: restore the exact CR0/CR4 bits changed for VMX operation.
    unsafe {
        if restore.cr4_osxsave {
            write_xcr0(restore.xcr0);
            write_cr4(read_cr4() & !CR4_OSXSAVE);
        }
        if restore.cr4_fxsr {
            write_cr4(read_cr4() & !(CR4_OSFXSR | CR4_OSXMMEXCPT));
        }
        if restore.cr4_vmxe {
            write_cr4(read_cr4() & !CR4_VMXE);
        }
        if restore.cr0_ne {
            write_cr0(read_cr0() & !CR0_NE);
        }
    }
}

fn restore_descriptor_tables(host: &HostRegisters) {
    use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
    use x86_64::instructions::tables::{lgdt, lidt};
    use x86_64::structures::gdt::SegmentSelector;
    use x86_64::structures::DescriptorTablePointer;
    use x86_64::VirtAddr;
    let gdtr = DescriptorTablePointer {
        base: VirtAddr::new(host.gdtr_base),
        limit: host.gdtr_limit,
    };
    let idtr = DescriptorTablePointer {
        base: VirtAddr::new(host.idtr_base),
        limit: host.idtr_limit,
    };
    // SAFETY: these are the exact descriptor table pointers active before the
    // VM entry; reloading them repairs limits that VMX does not restore.
    unsafe {
        lgdt(&gdtr);
        lidt(&idtr);
        DS::set_reg(SegmentSelector(host.ds));
        ES::set_reg(SegmentSelector(host.es));
        FS::set_reg(SegmentSelector(host.fs));
        GS::set_reg(SegmentSelector(host.gs));
        SS::set_reg(SegmentSelector(host.ss));
        CS::set_reg(SegmentSelector(host.cs));
        asm!("lldt {0:x}", in(reg) host.ldtr, options(nomem, nostack, preserves_flags));
    }
}

fn initialize_vmcs(
    ept_root: u64,
    guest: GuestExecutionState,
    host: &HostRegisters,
    controls: Controls,
    msr_bitmap: u64,
    io_bitmap_a: u64,
    io_bitmap_b: u64,
) -> Result<(), VmxError> {
    use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
    let mut tr_selector: u16;
    // SAFETY: reads the host task register selector.
    unsafe { asm!("str {0:x}", out(reg) tr_selector, options(nomem, nostack, preserves_flags)) };
    let host_cs = CS::get_reg().0;
    let host_ds = DS::get_reg().0;
    vmwrite(PIN_BASED_CONTROLS, u64::from(controls.pin))?;
    vmwrite(PROC_BASED_CONTROLS, u64::from(controls.primary))?;
    vmwrite(SECONDARY_CONTROLS, u64::from(controls.secondary))?;
    vmwrite(EXIT_CONTROLS, u64::from(controls.exit))?;
    vmwrite(ENTRY_CONTROLS, u64::from(controls.entry))?;
    vmwrite(
        EXCEPTION_BITMAP,
        (1 << 6) | (1 << 8) | (1 << 13) | (1 << 14),
    )?;
    vmwrite(IO_BITMAP_A, io_bitmap_a)?;
    vmwrite(IO_BITMAP_B, io_bitmap_b)?;
    vmwrite(MSR_BITMAP, msr_bitmap)?;
    vmwrite(EPT_POINTER, ept_root | 0x1e)?;
    vmwrite(VMCS_LINK_POINTER, u64::MAX)?;
    vmwrite(TSC_OFFSET, guest.tsc_offset as u64)?;
    vmwrite(GUEST_IA32_DEBUGCTL, 0)?;
    vmwrite(GUEST_IA32_PAT, host.pat)?;
    vmwrite(HOST_IA32_PAT, host.pat)?;
    vmwrite(GUEST_IA32_EFER, guest.efer)?;
    vmwrite(HOST_IA32_EFER, host.efer)?;

    let cr0_fixed0 = unsafe { rdmsr(IA32_VMX_CR0_FIXED0) };
    let cr0_fixed1 = unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };
    let cr4_fixed0 = unsafe { rdmsr(IA32_VMX_CR4_FIXED0) };
    let cr4_fixed1 = unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };
    let guest_cr0 = (guest.state.cr0 & cr0_fixed1) | cr0_fixed0;
    let guest_cr4 = ((guest.state.cr4
        | (host.cr4_after & (CR4_OSXSAVE | CR4_OSFXSR | CR4_OSXMMEXCPT)))
        & cr4_fixed1)
        | cr4_fixed0;
    if guest_cr0 & 0x8000_0001 != 0x8000_0001
        || guest_cr4 & 0x20 == 0
        || guest.efer & 0x500 != 0x500
        || !canonical(guest.state.rip)
        || !canonical(guest.rsp)
    {
        return Err(VmxError::InvalidState {
            code: guest_cr0 ^ guest_cr4 ^ guest.efer ^ guest.state.rip ^ guest.rsp,
        });
    }
    vmwrite(
        CR0_GUEST_HOST_MASK,
        (guest_cr0 ^ host.cr0) | cr0_fixed0 | !cr0_fixed1,
    )?;
    vmwrite(CR4_GUEST_HOST_MASK, guest_cr4 ^ host.cr4_after)?;
    vmwrite(CR0_READ_SHADOW, guest_cr0)?;
    vmwrite(CR4_READ_SHADOW, guest_cr4)?;
    vmwrite(GUEST_CR0, guest_cr0)?;
    vmwrite(GUEST_CR3, guest.cr3_gpa)?;
    vmwrite(GUEST_CR4, guest_cr4)?;
    vmwrite(HOST_CR0, host.cr0)?;
    vmwrite(HOST_CR3, host.cr3)?;
    vmwrite(HOST_CR4, host.cr4_after)?;

    let flat_data_ar = 0xC093u64;
    let code_ar = 0xA09Bu64;
    for (selector, limit, ar, base) in [(
        GUEST_SS_SELECTOR,
        GUEST_SS_LIMIT,
        GUEST_SS_AR,
        GUEST_SS_BASE,
    )] {
        vmwrite(selector, u64::from(host_ds))?;
        vmwrite(limit, 0xffff_ffff)?;
        vmwrite(ar, flat_data_ar)?;
        vmwrite(base, 0)?;
    }
    for (selector, limit, ar, base) in [
        (
            GUEST_ES_SELECTOR,
            GUEST_ES_LIMIT,
            GUEST_ES_AR,
            GUEST_ES_BASE,
        ),
        (
            GUEST_DS_SELECTOR,
            GUEST_DS_LIMIT,
            GUEST_DS_AR,
            GUEST_DS_BASE,
        ),
        (
            GUEST_FS_SELECTOR,
            GUEST_FS_LIMIT,
            GUEST_FS_AR,
            GUEST_FS_BASE,
        ),
        (
            GUEST_GS_SELECTOR,
            GUEST_GS_LIMIT,
            GUEST_GS_AR,
            GUEST_GS_BASE,
        ),
    ] {
        vmwrite(selector, 0)?;
        vmwrite(limit, 0xffff)?;
        vmwrite(ar, 0x1_0000)?;
        vmwrite(base, 0)?;
    }
    vmwrite(GUEST_CS_SELECTOR, u64::from(host_cs))?;
    vmwrite(GUEST_CS_LIMIT, 0xffff_ffff)?;
    vmwrite(GUEST_CS_AR, code_ar)?;
    vmwrite(GUEST_CS_BASE, 0)?;
    vmwrite(GUEST_LDTR_SELECTOR, 0)?;
    vmwrite(GUEST_LDTR_LIMIT, 0xffff)?;
    vmwrite(GUEST_LDTR_AR, 0x1_0000)?;
    vmwrite(GUEST_LDTR_BASE, 0)?;
    vmwrite(GUEST_TR_SELECTOR, u64::from(tr_selector))?;
    vmwrite(GUEST_TR_LIMIT, 0x67)?;
    vmwrite(GUEST_TR_AR, 0x8b)?;
    vmwrite(GUEST_TR_BASE, host.tr_base)?;
    vmwrite(GUEST_GDTR_BASE, host.gdtr_base)?;
    vmwrite(GUEST_GDTR_LIMIT, u64::from(host.gdtr_limit))?;
    vmwrite(GUEST_IDTR_BASE, host.idtr_base)?;
    vmwrite(GUEST_IDTR_LIMIT, u64::from(host.idtr_limit))?;
    vmwrite(GUEST_INTERRUPTIBILITY, 0)?;
    vmwrite(GUEST_ACTIVITY_STATE, 0)?;
    vmwrite(GUEST_SYSENTER_CS, u64::from(host_cs))?;
    vmwrite(GUEST_SYSENTER_ESP, host.sysenter_esp)?;
    vmwrite(GUEST_SYSENTER_EIP, host.sysenter_eip)?;
    vmwrite(GUEST_DR7, 0)?;
    vmwrite(GUEST_RSP, guest.rsp)?;
    vmwrite(GUEST_RIP, guest.state.rip)?;
    vmwrite(GUEST_RFLAGS, guest.state.rflags | 2)?;
    vmwrite(GUEST_PENDING_DEBUG, 0)?;

    vmwrite(HOST_ES_SELECTOR, u64::from(ES::get_reg().0))?;
    vmwrite(HOST_CS_SELECTOR, u64::from(CS::get_reg().0))?;
    vmwrite(HOST_SS_SELECTOR, u64::from(SS::get_reg().0))?;
    vmwrite(HOST_DS_SELECTOR, u64::from(DS::get_reg().0))?;
    vmwrite(HOST_FS_SELECTOR, u64::from(FS::get_reg().0))?;
    vmwrite(HOST_GS_SELECTOR, u64::from(GS::get_reg().0))?;
    vmwrite(HOST_TR_SELECTOR, u64::from(tr_selector))?;
    vmwrite(HOST_FS_BASE, host.fs_base)?;
    vmwrite(HOST_GS_BASE, host.gs_base)?;
    vmwrite(HOST_TR_BASE, host.tr_base)?;
    vmwrite(HOST_GDTR_BASE, host.gdtr_base)?;
    vmwrite(HOST_IDTR_BASE, host.idtr_base)?;
    vmwrite(HOST_SYSENTER_CS, host.sysenter_cs)?;
    vmwrite(HOST_SYSENTER_ESP, host.sysenter_esp)?;
    vmwrite(HOST_SYSENTER_EIP, host.sysenter_eip)?;

    if vmread(PROC_BASED_CONTROLS)? != u64::from(controls.primary)
        || vmread(SECONDARY_CONTROLS)? != u64::from(controls.secondary)
        || vmread(EPT_POINTER)? != ept_root | 0x1e
        || vmread(GUEST_RIP)? != guest.state.rip
    {
        return Err(VmxError::InvalidState { code: 1 });
    }
    Ok(())
}

fn cpuid(leaf: u32, subleaf: u32) -> core::arch::x86_64::CpuidResult {
    core::arch::x86_64::__cpuid_count(leaf, subleaf)
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
    let sign = (value >> 47) & 1;
    if sign == 0 {
        upper == 0
    } else {
        upper == 0xffff
    }
}

#[derive(Clone, Copy)]
struct MemoryDataAccess {
    register: usize,
    width: u8,
    store: bool,
    length: usize,
}

fn decode_memory_data_access(bytes: &[u8; 15]) -> Option<MemoryDataAccess> {
    let mut pos = 0usize;
    let mut operand_16 = false;
    let mut rex = 0u8;
    while pos < bytes.len() {
        match bytes[pos] {
            0x40..=0x4f => {
                rex = bytes[pos];
                pos += 1;
            }
            0x66 => {
                operand_16 = true;
                pos += 1;
            }
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x67 | 0xf0 | 0xf2 | 0xf3 => pos += 1,
            _ => break,
        }
    }
    let opcode = *bytes.get(pos)?;
    let (store, byte, zero_extend) = match opcode {
        0x8a => (false, true, false),
        0x88 => (true, true, false),
        0x8b => (false, false, false),
        0x89 => (true, false, false),
        0x0f => match *bytes.get(pos + 1)? {
            0xb6 => (false, true, true),
            0xb7 => (false, false, true),
            0xbe | 0xbf => return None,
            _ => return None,
        },
        _ => return None,
    };
    let modrm_at = pos + if opcode == 0x0f { 2 } else { 1 };
    let modrm = *bytes.get(modrm_at)?;
    if modrm >> 6 == 3 {
        return None;
    }
    let register = usize::from((modrm >> 3) & 7) | (usize::from(rex & 4 != 0) << 3);
    let width = if byte || (zero_extend && opcode == 0x0f && *bytes.get(pos + 1)? == 0xb6) {
        1
    } else if operand_16 || (zero_extend && *bytes.get(pos + 1)? == 0xb7) {
        2
    } else if rex & 8 != 0 {
        8
    } else {
        4
    };
    Some(MemoryDataAccess {
        register,
        width,
        store,
        length: modrm_at + 1,
    })
}

fn guest_va_to_gpa<B: LinuxPlatform>(cr3: u64, va: u64, devices: &mut B) -> Option<u64> {
    let pml4 = cr3 & 0x000f_ffff_ffff_f000;
    let pml4e = guest_read_u64(devices, pml4 + ((va >> 39) & 0x1ff) * 8)?;
    if pml4e & 1 == 0 {
        return None;
    }
    let pdpt = pml4e & 0x000f_ffff_ffff_f000;
    let pdpte = guest_read_u64(devices, pdpt + ((va >> 30) & 0x1ff) * 8)?;
    if pdpte & 1 == 0 {
        return None;
    }
    if pdpte & (1 << 7) != 0 {
        return Some((pdpte & 0x000f_ffff_c000_0000) + (va & 0x3fff_ffff));
    }
    let pd = pdpte & 0x000f_ffff_ffff_f000;
    let pde = guest_read_u64(devices, pd + ((va >> 21) & 0x1ff) * 8)?;
    if pde & 1 == 0 {
        return None;
    }
    if pde & (1 << 7) != 0 {
        return Some((pde & 0x000f_ffff_ffe0_0000) + (va & 0x1f_ffff));
    }
    let pt = pde & 0x000f_ffff_ffff_f000;
    let pte = guest_read_u64(devices, pt + ((va >> 12) & 0x1ff) * 8)?;
    if pte & 1 == 0 {
        return None;
    }
    Some((pte & 0x000f_ffff_ffff_f000) + (va & 0xfff))
}

fn guest_read_u64<B: LinuxPlatform>(devices: &mut B, gpa: u64) -> Option<u64> {
    let mut bytes = [0u8; 8];
    devices
        .read_guest(gpa, &mut bytes)
        .then_some(u64::from_le_bytes(bytes))
}
