//! x86_64 多处理器启动：处理器发现（ACPI MADT）、实模式启动代码、INIT/启动核间中断、其他处理器的入口。
//! x86_64 multiprocessor bring-up: discovery via the MADT, real-mode trampoline, INIT/start-up IPIs, AP entry.
//!
//! # 启动流程
//! 1. 引导处理器：启用本地 APIC、读出自己的 APIC 标识、以 PIT 校准本地定时器、解析 MADT 得到拓扑。
//! 2. 对每个其他处理器：Core 给出低端启动帧（已恒等映射）、栈与内核地址空间；这里把启动代码复制进该帧、
//!    写入数据区（CR3 / CR4 / EFER / CR0 取自引导处理器，保证分页与不可执行位等设置一致），发 INIT + 两次启动。
//! 3. 被启动的处理器：实模式 → 保护模式 → 长模式（临时 GDT 位于启动帧内），换到给定的栈，调用 [`ap_entry`]：
//!    加载自己的 GDT/TSS 与共享 IDT、设置系统调用 MSR、启用本地 APIC 与本地定时器，然后交给 Core。
//!
//! # 边界
//! 启动代码与位置无关：实模式下以 CS 推出所在帧的线性地址，之后一律相对它寻址；只有 GDTR 的基址由这里在复制时填入。

use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use kernel_core::acpi::{self, PhysRead};
use kernel_core::frame::PhysFrame;
use kernel_core::smp::{IpiKind, SmpError, Topology, MAX_CPUS};
use x86_64::registers::control::{Cr0, Cr4};
use x86_64::registers::model_specific::Msr;

use super::{apic, gdt, idt, space, syscall};
use crate::arch::{CpuDiscovery, CpuStart};
use crate::boot::BootSpec;

/// 启动代码必须位于 1 MiB 以下（启动核间中断只携带 8 位页号）。
pub const START_FRAME_LIMIT: u64 = 0x10_0000;

/// APIC 标识 → 逻辑下标 + 1（0 = 未知）。xAPIC 模式下标识只有 8 位。
static INDEX_OF: [AtomicU8; 256] = [const { AtomicU8::new(0) }; 256];
/// 逻辑下标 → APIC 标识。
static HW_ID: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];
/// 其他处理器本地定时器的频率（启动前写入）。
static AP_TIMER_HZ: AtomicU32 = AtomicU32::new(0);

const MSR_EFER: u32 = 0xC000_0080;
/// CR4.PCIDE：只能在长模式下置位，启动代码在进入长模式之前写 CR4，必须去掉。
const CR4_PCIDE: u64 = 1 << 17;

// 启动代码（AT&T 语法）。数据区布局必须与 [`StartData`] 一致。
global_asm!(
    r#"
    .pushsection .rodata.jsr_ap_start, "a"
    .balign 16
    .global jsr_ap_start_begin
jsr_ap_start_begin:
    .code16
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    movw %ax, %ss
    movw $0x0ff0, %sp
    xorl %ebx, %ebx
    movw %ax, %bx
    shll $4, %ebx
    lgdtl (jsr_ap_start_gdtr - jsr_ap_start_begin)
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    leal (2f - jsr_ap_start_begin)(%ebx), %eax
    pushl $0x08
    pushl %eax
    lretl

    .code32
2:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    leal 0x0ff0(%ebx), %esp
    movl (jsr_ap_start_data + 8 - jsr_ap_start_begin)(%ebx), %eax
    movl %eax, %cr4
    movl (jsr_ap_start_data + 0 - jsr_ap_start_begin)(%ebx), %eax
    movl %eax, %cr3
    movl $0xC0000080, %ecx
    movl (jsr_ap_start_data + 16 - jsr_ap_start_begin)(%ebx), %eax
    movl (jsr_ap_start_data + 20 - jsr_ap_start_begin)(%ebx), %edx
    wrmsr
    movl (jsr_ap_start_data + 24 - jsr_ap_start_begin)(%ebx), %eax
    movl %eax, %cr0
    leal (3f - jsr_ap_start_begin)(%ebx), %eax
    pushl $0x18
    pushl %eax
    lretl

    .code64
3:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl %ebx, %ebx
    movq (jsr_ap_start_data + 32 - jsr_ap_start_begin)(%rbx), %rsp
    movq (jsr_ap_start_data + 48 - jsr_ap_start_begin)(%rbx), %rdi
    movq (jsr_ap_start_data + 40 - jsr_ap_start_begin)(%rbx), %rax
    callq *%rax
4:
    cli
    hlt
    jmp 4b

    .balign 8
jsr_ap_start_gdt:
    .quad 0
    .quad 0x00CF9B000000FFFF
    .quad 0x00CF93000000FFFF
    .quad 0x00AF9B000000FFFF
    .global jsr_ap_start_gdtr
jsr_ap_start_gdtr:
    .word 4 * 8 - 1
    .long 0
    .balign 8
    .global jsr_ap_start_data
jsr_ap_start_data:
    .fill 7, 8, 0
    .global jsr_ap_start_end
jsr_ap_start_end:
    .popsection
    "#,
    options(att_syntax)
);

extern "C" {
    static jsr_ap_start_begin: u8;
    static jsr_ap_start_gdtr: u8;
    static jsr_ap_start_data: u8;
    static jsr_ap_start_end: u8;
}

/// 启动代码数据区（偏移见上方汇编）。
#[repr(C)]
struct StartData {
    cr3: u64,
    cr4: u64,
    efer: u64,
    cr0: u64,
    stack: u64,
    entry: u64,
    index: u64,
}

/// 临时 GDT 在启动代码内的偏移（GDTR 基址 = 帧地址 + 它）。
fn offset_of(sym: &u8) -> usize {
    // SAFETY：只取符号地址，不解引用。
    (sym as *const u8 as usize) - unsafe { &jsr_ap_start_begin as *const u8 as usize }
}

/// 经全物理内存映射读取固件表（只读低 4 GiB，引导器保证这段已映射）。
/// 同平台的 PCI / MCFG 解析共用这一实现。
pub(crate) struct PhysWindow(pub(crate) u64);

impl PhysRead for PhysWindow {
    fn read(&self, phys: u64, buf: &mut [u8]) -> bool {
        match phys.checked_add(buf.len() as u64) {
            Some(end) if end <= 1 << 32 => {
                // SAFETY：[phys, end) 位于引导器映射的低 4 GiB 内；只读拷贝。
                unsafe { core::ptr::copy_nonoverlapping((self.0 + phys) as *const u8, buf.as_mut_ptr(), buf.len()) };
                true
            }
            _ => false,
        }
    }
}

/// 引导处理器：启用本地 APIC、校准本地定时器、解析 MADT。没有物理映射或 APIC 不可用时只报告引导处理器。
pub fn init_boot(boot: &BootSpec) -> CpuDiscovery {
    let Some(offset) = boot.phys_offset else {
        return CpuDiscovery { topology: Topology::boot_only(0), source: "system.firmware.error.unreadable" };
    };
    if apic::init_base(offset).is_none() {
        return CpuDiscovery { topology: Topology::boot_only(0), source: "system.firmware.error.unreadable" };
    }
    apic::enable_local(true);
    let boot_id = apic::id();
    apic::calibrate_timer();
    let (topology, source) = match boot.acpi_rsdp {
        Some(rsdp) => match acpi::parse_madt(&PhysWindow(offset), rsdp, boot_id) {
            Ok(m) => {
                super::ioapic::configure(&m, offset, boot_id);
                (m.topology, "acpi.madt")
            }
            Err(e) => (Topology::boot_only(boot_id), e.name()),
        },
        None => (Topology::boot_only(boot_id), "boot_only"),
    };
    for (i, &id) in topology.ids().iter().enumerate() {
        HW_ID[i].store(id, Ordering::Relaxed);
        if id < 256 {
            INDEX_OF[id as usize].store(i as u8 + 1, Ordering::Release);
        }
    }
    CpuDiscovery { topology, source }
}

/// 启动一个处理器（见模块文档）。
///
/// # Safety
/// 同 `Platform::cpu_start`。
pub unsafe fn start(req: &CpuStart<space::SpaceRoot>, frame: Option<PhysFrame>) -> Result<(), SmpError> {
    let frame = frame.ok_or(SmpError::StartFailed)?;
    if req.index == 0 || req.index >= MAX_CPUS || req.hw_id >= 256 {
        return Err(SmpError::NoSuchCpu);
    }
    if frame.start() >= START_FRAME_LIMIT || req.space.0 >= 1 << 32 || !apic::ready() {
        return Err(SmpError::StartFailed);
    }
    if !gdt::prepare_cpu(req.index) {
        return Err(SmpError::StartFailed);
    }
    let Some(dst) = crate::mm::phys_to_virt(frame.start()) else { return Err(SmpError::StartFailed) };
    let src = &jsr_ap_start_begin as *const u8;
    let len = offset_of(&jsr_ap_start_end);
    core::ptr::copy_nonoverlapping(src, dst, len);
    // GDTR 基址 = 帧地址 + 临时 GDT 偏移（GDT 紧挨在 GDTR 之前，共 4 项）
    let gdtr = dst.add(offset_of(&jsr_ap_start_gdtr));
    let gdt_linear = frame.start() as u32 + (offset_of(&jsr_ap_start_gdtr) - 4 * 8) as u32;
    (gdtr.add(2) as *mut u32).write_unaligned(gdt_linear);
    let data = dst.add(offset_of(&jsr_ap_start_data)) as *mut StartData;
    data.write(StartData {
        cr3: req.space.0,
        cr4: Cr4::read_raw() & !CR4_PCIDE,
        efer: Msr::new(MSR_EFER).read(),
        cr0: Cr0::read_raw(),
        stack: req.stack_top,
        entry: ap_entry as *const () as u64,
        index: req.index as u64,
    });
    AP_TIMER_HZ.store(req.timer_hz, Ordering::Relaxed);
    core::sync::atomic::fence(Ordering::SeqCst);
    if apic::send_init_startup(req.hw_id, (frame.start() >> 12) as u8) {
        Ok(())
    } else {
        Err(SmpError::StartFailed)
    }
}

/// 其他处理器进入 Rust 的第一站（由启动代码以 System V 约定调用，`index` 在 rdi）。
extern "C" fn ap_entry(index: u64) -> ! {
    let index = index as usize;
    if !gdt::init_cpu(index) {
        crate::arch::halt_forever();
    }
    idt::load();
    syscall::init(index);
    apic::enable_local(false);
    apic::start_periodic(AP_TIMER_HZ.load(Ordering::Relaxed));
    crate::smp::secondary_main(index)
}

/// 逻辑下标 `cpu` 的 APIC 标识（未登记时为 `None`）。
pub fn hw_id_of(cpu: usize) -> Option<u32> {
    HW_ID.get(cpu).map(|h| h.load(Ordering::Relaxed)).filter(|&h| h != u32::MAX)
}

/// 当前处理器的逻辑下标（APIC 未就绪或标识未登记时为 0）。
#[inline]
pub fn cpu_index() -> usize {
    if !apic::ready() {
        return 0;
    }
    match INDEX_OF[(apic::id() & 0xFF) as usize].load(Ordering::Acquire) {
        0 => 0,
        n => n as usize - 1,
    }
}

/// 向逻辑下标 `cpu` 发送核间中断。
pub fn send_ipi(cpu: usize, kind: IpiKind) -> Result<(), SmpError> {
    let hw = HW_ID.get(cpu).map(|h| h.load(Ordering::Relaxed)).ok_or(SmpError::NoSuchCpu)?;
    if hw >= 256 || !apic::ready() {
        return Err(SmpError::NoSuchCpu);
    }
    if cpu == cpu_index() {
        return Err(SmpError::SelfTarget);
    }
    let vector = match kind {
        IpiKind::Reschedule => apic::IPI_RESCHEDULE_VECTOR,
        IpiKind::TlbShootdown => apic::IPI_SHOOTDOWN_VECTOR,
        IpiKind::Call => apic::IPI_CALL_VECTOR,
    };
    if apic::send_fixed(hw, vector) {
        Ok(())
    } else {
        Err(SmpError::Timeout)
    }
}

/// 作废本处理器上一段页的 TLB 项。
pub fn tlb_flush_local(va: u64, pages: u64) {
    for i in 0..pages {
        let addr = va.wrapping_add(i * 4096);
        // SAFETY：invlpg 只作废缓存项，对任意地址都无副作用。
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags)) };
    }
}

/// 作废本处理器上的全部 TLB 项，包括全局页。
///
/// 重写 CR3 不会清除全局项，因此在硬件启用全局页时临时清除 CR4.PGE 并恢复。
/// Invalidate all local TLB entries, including global mappings.
pub fn tlb_flush_all_local() {
    let cr4_before: u64;
    let cr4_without_pge: u64;
    // SAFETY：仅临时改变分页控制位；中断已由调用者的击落协议屏蔽。
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4_before, options(nomem, nostack, preserves_flags));
        cr4_without_pge = cr4_before & !(1 << 7);
        if cr4_without_pge != cr4_before {
            core::arch::asm!("mov cr4, {}", in(reg) cr4_without_pge, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mov cr4, {}", in(reg) cr4_before, options(nomem, nostack, preserves_flags));
        } else {
            let cr3: u64;
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
        }
    }
}
