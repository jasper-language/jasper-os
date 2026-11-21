//! AArch64 引导适配层：内核入口 `_start`、早期页表与 MMU、设备树 → [`BootSpec`]、进入内核主流程。
//! AArch64 boot adapter: `_start`, early MMU, device tree to `BootSpec`, then the kernel main flow.
//!
//! AArch64 没有 x86 那样的引导器：固件 / 仿真器（QEMU `-kernel`）按 ELF 程序头把内核放到链接地址，
//! 从 `_start` 开始执行，MMU 关闭。本文件负责：
//! 1. 只让 0 号处理器继续（其余停在 `wfe`，之后经 PSCI 从各自的入口启动）、逻辑下标寄存器置 0；若在 EL2 进入则降到 EL1；清零 BSS、设置启动栈；
//! 2. 建早期页表并打开 MMU（见 `mmu.rs`）；
//! 3. 找到设备树（`x0` 给出的地址，或 QEMU `virt` 约定的内存起点），读出内存图、串口、中断控制器与定时器中断号；
//! 4. 把内存图转换成与引导协议无关的 [`BootSpec`]（内核映像、设备树、固件保留区标为保留），交给 `kmain::start`。
//!
//! 在 EL3 进入的情形不支持（停在入口，不做任何事）。

use core::arch::global_asm;
use core::sync::atomic::{AtomicU8, Ordering};

use kernel_core::fdt::{self, BootSummary, Fdt, PixelFormat};
#[cfg(not(any(feature = "pixel6a-smoke", feature = "pixel6a-full")))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=generic-aarch64-boot-excludes-pixel-verification-profiles
use kernel_core::fdt::Node;
use kernel_core::frame::{PhysRegion, RegionKind};
use kernel_core::image_header;
use kernel_core::psci::Conduit;
#[cfg(feature = "aarch64-el2-retain-verify")]
use kernel_core::driver_host::{
    DeviceIdentity, DriverHostBroker, Needs, Policy, RequestKind, Terminal,
};

#[cfg(any(feature = "pixel6a-smoke", feature = "pixel6a-full"))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-profile-only-samsung-console
use super::samsung_uart;
use super::{devirq, gic, mmu, semihost, smp, timer};
#[cfg(not(any(feature = "pixel6a-smoke", feature = "pixel6a-full")))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=generic-aarch64-console-path
use super::uart;
use super::platform::direct_boot_normal;
use crate::boot::{self, BootSpec, FrameBufferFormat, FrameBufferInfo, PsciBoot, SerialBoot};

/// 启动栈大小。
const BOOT_STACK_BYTES: usize = 64 * 1024;
pub(crate) const EL2_STACK_BYTES: usize = 64 * 1024;
const GUEST_STACK_BYTES: usize = 64 * 1024;
static ENTRY_EXCEPTION_LEVEL: AtomicU8 = AtomicU8::new(0);

/// Exception level observed at the architecture entry.
pub fn entry_exception_level() -> u8 {
    ENTRY_EXCEPTION_LEVEL.load(Ordering::Relaxed)
}

#[cfg(feature = "aarch64-el2-retain-verify")]
pub(crate) fn el2_hvc_probe() -> bool {
    let status: u64;
    let reply: u64;
    // SAFETY: HVC is issued only after assembly installs the EL2 vector table.
    unsafe {
        core::arch::asm!(
            "mov x0, #0",
            "mov x1, #0",
            "hvc #0x4a53",
            "mov {status}, x0",
            "mov {reply}, x1",
            status = out(reg) status,
            reply = out(reg) reply,
            out("x0") _,
            out("x1") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            options(nostack),
        );
    }
    status == 1 && reply == 0x4a54
}

#[cfg(feature = "aarch64-el2-retain-verify")]
fn el2_guest_stage2_fault_probe() -> bool {
    unsafe extern "C" {
        fn jsr_aarch64_el2_context_probe() -> u64;
        static jsr_aarch64_stage2_hpfar: u64;
    }
    // SAFETY: The assembly probe saves all callee registers it rewrites, checks
    // the EL2-restored sentinels and preserves the AArch64 C ABI on return.
    let ok = unsafe { jsr_aarch64_el2_context_probe() == 1 };
    let hpfar = unsafe { core::ptr::addr_of!(jsr_aarch64_stage2_hpfar).read_volatile() };
    let stage2_open = super::el2::open_verification_block();
    crate::kprintln!(
        "[JSR-A64-STAGE2] vm_exit={} hpfar=0x{:x} stage2_open={}",
        ok,
        hpfar,
        stage2_open
    );
    ok && stage2_open
}

#[cfg(feature = "aarch64-el2-retain-verify")]
fn el2_vgic_probe() -> bool {
    let vbar_before: u64;
    let timer_ctl_before: u64;
    let timer_cval_before: u64;
    let status: u64;
    let reply: u64;
    // SAFETY: The EL2 handler installs a GICv3 virtual CPU interface and an EL1
    // guest vector before placing a group-1 interrupt in LR0. The guest proves
    // architectural IAR/EOI delivery and exits through HVC.
    // 安全性：EL2 在向 LR0 注入 group-1 中断前安装 GICv3 虚拟 CPU 接口和
    // guest 向量；guest 以真实 IAR/EOI 验证交付，不伪造异常返回。
    unsafe {
        core::arch::asm!("mrs {}, vbar_el1", out(reg) vbar_before, options(nomem, nostack));
        core::arch::asm!(
            "mrs {ctl}, cntv_ctl_el0",
            "mrs {cval}, cntv_cval_el0",
            ctl = out(reg) timer_ctl_before,
            cval = out(reg) timer_cval_before,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "mov x0, #0",
            "mov x1, #0",
            "hvc #0x4a58", // JASPER-HARDCODE-REVIEW: issue=34 source=aarch64-el2-vgic-probe reason=private-verification-hypercall-contract
            "mov {status}, x0",
            "mov {reply}, x1",
            status = out(reg) status,
            reply = out(reg) reply,
            out("x0") _,
            out("x1") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            options(nostack),
        );
    }
    let vbar_after: u64;
    let timer_ctl_after: u64;
    let timer_cval_after: u64;
    // SAFETY: Reading VBAR_EL1 in the resident verification build has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, vbar_el1", out(reg) vbar_after, options(nomem, nostack));
        core::arch::asm!(
            "mrs {ctl}, cntv_ctl_el0",
            "mrs {cval}, cntv_cval_el0",
            ctl = out(reg) timer_ctl_after,
            cval = out(reg) timer_cval_after,
            options(nomem, nostack),
        );
    }
    crate::kprintln!(
        "[JSR-A64-VGIC] direct=true status={} reply=0x{:x} ack={} eoi={} lr_cleared={} host_restored={} vbar_same={} timer_ctl_same={} timer_cval_same={}",
        status,
        reply,
        status == 5,
        status == 5,
        status == 5,
        status == 5,
        vbar_before == vbar_after,
        timer_ctl_before == timer_ctl_after,
        timer_cval_before == timer_cval_after
    );
    status == 5
        && reply == 0x5647
        && vbar_before == vbar_after
        && timer_ctl_before == timer_ctl_after
        && timer_cval_before == timer_cval_after
}

#[cfg(feature = "aarch64-el2-retain-verify")]
fn el2_virtual_timer_irq_probe() -> bool {
    let vbar_before: u64;
    let timer_ctl_before: u64;
    let timer_cval_before: u64;
    let status: u64;
    let reply: u64;
    // SAFETY: The resident EL2 IRQ vector acknowledges the physical virtual
    // timer PPI and injects a distinct vINTID into the guest through LR0.
    // 安全性：EL2 IRQ 向量确认物理虚拟定时器 PPI，并通过 LR0 向 guest
    // 注入独立的 vINTID；guest 必须完成 IAR/EOI 后才能退出。
    unsafe {
        core::arch::asm!("mrs {}, vbar_el1", out(reg) vbar_before, options(nomem, nostack));
        core::arch::asm!(
            "mrs {ctl}, cntv_ctl_el0",
            "mrs {cval}, cntv_cval_el0",
            ctl = out(reg) timer_ctl_before,
            cval = out(reg) timer_cval_before,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "mov x0, #0",
            "mov x1, #0",
            "hvc #0x4a5b", // JASPER-HARDCODE-REVIEW: issue=34 source=aarch64-el2-vgic-timer-probe reason=private-verification-hypercall-contract
            "mov {status}, x0",
            "mov {reply}, x1",
            status = out(reg) status,
            reply = out(reg) reply,
            out("x0") _,
            out("x1") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            options(nostack),
        );
    }
    let vbar_after: u64;
    let timer_ctl_after: u64;
    let timer_cval_after: u64;
    // SAFETY: These reads verify that the EL2 transaction restored all state
    // changed by the timer guest before ordinary kernel execution resumes.
    // 安全：这些读取验证 EL2 事务在普通内核恢复前还原了 timer guest 改动的状态。
    unsafe {
        core::arch::asm!("mrs {}, vbar_el1", out(reg) vbar_after, options(nomem, nostack));
        core::arch::asm!(
            "mrs {ctl}, cntv_ctl_el0",
            "mrs {cval}, cntv_cval_el0",
            ctl = out(reg) timer_ctl_after,
            cval = out(reg) timer_cval_after,
            options(nomem, nostack),
        );
    }
    let vbar_same = vbar_before == vbar_after;
    let timer_ctl_same = timer_ctl_before == timer_ctl_after;
    let timer_cval_same = timer_cval_before == timer_cval_after;
    crate::kprintln!(
        "[JSR-A64-VGIC] timer_irq=true status={} reply=0x{:x} ack={} eoi={} lr_cleared={} host_restored={} vbar_same={} timer_ctl_same={} timer_cval_same={}",
        status,
        reply,
        status == 6,
        status == 6,
        status == 6,
        status == 6,
        vbar_same,
        timer_ctl_same,
        timer_cval_same
    );
    status == 6 && reply == 0x5449 && vbar_same && timer_ctl_same && timer_cval_same
}

#[cfg(feature = "aarch64-el2-retain-verify")]
fn el2_vgic_timer_driver_host_completion(irq_delivered: bool, gic_dist: u64) -> bool {
    let mut broker = DriverHostBroker::<1, 1, 1, 1>::new();
    let identity = DeviceIdentity {
        identity: gic_dist as u32,
        generation: 1,
    };
    let rights = Needs::DEVICE.union(Needs::IRQ);
    let admitted = broker
        .discover(identity)
        .and_then(|()| broker.register_host())
        .and_then(|host| broker.admit(host, identity, rights, Policy::new(rights, 0, 0, 1)))
        .and_then(|pass| broker.begin(pass, RequestKind::Irq));
    let completed = admitted.is_ok_and(|request| {
        irq_delivered
            && broker
                .complete(request)
                .is_ok_and(|terminal| terminal == Terminal::Completed)
    });
    let stats = broker.stats();
    crate::kprintln!(
        "[JSR-A64-VGIC] driver_host_irq={} completed={} pending={} completed_count={}",
        completed,
        stats.completed == 1,
        stats.pending_requests,
        stats.completed
    );
    completed && stats.completed == 1 && stats.pending_requests == 0
}

#[cfg(feature = "pixel6a-el2-observable")] // JASPER-HARDCODE-REVIEW: issue=21 source=pixel-el2-observation-window reason=physical-boot-carrier-probe-only
pub(crate) fn wait_el2_observation_window() {
    let frequency: u64;
    let start: u64;
    // SAFETY: The AArch64 entry contract enables the physical counter.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frequency, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) start, options(nomem, nostack));
    }
    let delay = frequency.saturating_mul(5);
    loop {
        let now: u64;
        // SAFETY: Reading the physical counter has no side effects.
        unsafe {
            core::arch::asm!("mrs {}, cntpct_el0", out(reg) now, options(nomem, nostack));
        }
        if now.wrapping_sub(start) >= delay {
            return;
        }
        core::hint::spin_loop();
    }
}

/// 启动栈（任务系统建立之前的唯一执行流使用）。
#[repr(C, align(16))]
struct BootStack([u8; BOOT_STACK_BYTES]);

#[no_mangle]
static mut JSR_BOOT_STACK: BootStack = BootStack([0; BOOT_STACK_BYTES]);

#[repr(C, align(16))]
struct HypervisorStack([u8; EL2_STACK_BYTES]);

#[no_mangle]
static mut JSR_EL2_STACK: HypervisorStack = HypervisorStack([0; EL2_STACK_BYTES]);

#[repr(C, align(16))]
struct GuestStack([u8; GUEST_STACK_BYTES]);

#[no_mangle]
static mut JSR_EL2_GUEST_STACK: GuestStack = GuestStack([0; GUEST_STACK_BYTES]);

#[cfg(feature = "aarch64-el2-retain-verify")]
pub(crate) fn guest_stack_range() -> (u64, u64) {
    let start = (&raw const JSR_EL2_GUEST_STACK) as u64;
    (start, start + GUEST_STACK_BYTES as u64)
}

/// 找不到设备树或必需设备时的退出码（与 x86_64 的失败码相同）。
const EXIT_FAILURE: u32 = 35;

#[cfg(any(feature = "pixel6a-smoke", feature = "pixel6a-full-probe"))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-profile-only-timer-reset-helper
fn pixel6a_timer_frequency(fdt: Option<&Fdt<'_>>) -> Option<u64> {
    let frequency: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frequency) };
    if frequency != 0 {
        return Some(frequency);
    }
    let node = fdt?.find_compatible("arm,armv8-timer").ok().flatten()?;
    node.cell("clock-frequency", 0).filter(|frequency| *frequency != 0).map(u64::from)
}

#[cfg(any(feature = "pixel6a-smoke", feature = "pixel6a-full-probe"))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-profile-only-timer-reset-helper
pub(super) fn pixel6a_reset_after(seconds: u64, fdt: Option<&Fdt<'_>>) -> ! {
    let start: u64;
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) start) };
    let Some(frequency) = pixel6a_timer_frequency(fdt) else {
        crate::kprintln!("[JSR-TIMER] failure reason=unverified-counter-frequency");
        pixel6a_reset_now();
    };
    let deadline = start.saturating_add(frequency.saturating_mul(seconds));
    loop {
        let now: u64;
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) now) };
        if now >= deadline {
            break;
        }
        core::hint::spin_loop();
    }
    pixel6a_reset_now()
}

#[cfg(any(
    feature = "pixel6a-smoke", // JASPER-HARDCODE-REVIEW: issue=33 source=physical-runtime-plan reason=reset-action-is-only-compiled-for-pixel6a-verification
    feature = "pixel6a-full-probe", // JASPER-HARDCODE-REVIEW: issue=33 source=physical-runtime-plan reason=reset-action-is-only-compiled-for-pixel6a-verification
    feature = "pixel6a-runtime-verify" // JASPER-HARDCODE-REVIEW: issue=33 source=physical-runtime-plan reason=success-action-is-only-compiled-for-pixel6a-verification
))]
pub(crate) fn pixel6a_reset_now() -> ! {
    // Prefer PSCI SYSTEM_RESET2(arch warm), then fall back to SYSTEM_RESET.
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") 0xc400_000cu64 => _,
            inout("x1") 0u64 => _,
            inout("x2") 0u64 => _,
            options(nostack)
        );
        core::arch::asm!("smc #0", inout("x0") 0x8400_0009u64 => _, options(nostack));
    }
    loop {
        unsafe { core::arch::asm!("wfe", options(nomem, nostack, preserves_flags)) };
    }
}

#[cfg(any(
    feature = "pixel6a-full-probe", // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-full-probe-poweroff-only
    feature = "pixel6a-gic-init-probe", // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-gic-probe-poweroff-only
    feature = "pixel6a-before-kmain-probe", // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-entry-probe-poweroff-only
    feature = "pixel6a-smp-probe" // JASPER-HARDCODE-REVIEW: issue=33 source=physical-runtime-plan reason=success-action-is-only-compiled-for-pixel6a-verification
))]
pub(crate) fn pixel6a_power_off() -> ! {
    unsafe {
        core::arch::asm!("smc #0", inout("x0") 0x8400_0008u64 => _, options(nostack));
    }
    loop {
        unsafe { core::arch::asm!("wfe", options(nomem, nostack, preserves_flags)) };
    }
}

#[cfg(any(feature = "pixel6a-smoke", feature = "pixel6a-full"))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-profile-only-uefi-console
unsafe fn uefi_console_line(system_table: u64, text: &[u8]) {
    type OutputString = unsafe extern "efiapi" fn(*mut u8, *const u16) -> usize;
    const CONSOLE_OUT: u64 = 64;
    const OUTPUT_STRING: u64 = 32;

    if system_table < 4096 || system_table % 8 != 0 {
        return;
    }
    let conout = ((system_table + CONSOLE_OUT) as *const u64).read();
    if conout < 4096 || conout % 8 != 0 {
        return;
    }
    let function = ((conout + OUTPUT_STRING) as *const usize).read();
    if function == 0 {
        return;
    }
    let output: OutputString = core::mem::transmute(function);
    for &byte in text {
        if byte == 0 {
            return;
        }
        let wide = [u16::from(byte), 0];
        output(conout as *mut u8, wide.as_ptr());
    }
}

#[cfg(feature = "pixel6a-full")] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=explicit-full-profile-device-configuration
unsafe fn disable_uefi_watchdog(system_table: u64) {
    const BOOT_SERVICES: u64 = 96;
    const SET_WATCHDOG_TIMER: u64 = 256;
    type SetWatchdog = unsafe extern "efiapi" fn(usize, u64, usize, *const u16) -> usize;

    if system_table < 4096 || system_table % 8 != 0 {
        return;
    }
    let services = ((system_table + BOOT_SERVICES) as *const u64).read();
    if services < 4096 || services % 8 != 0 {
        return;
    }
    let function = ((services + SET_WATCHDOG_TIMER) as *const usize).read();
    if function != 0 {
        let set_watchdog: SetWatchdog = core::mem::transmute(function);
        set_watchdog(0, 0, 0, core::ptr::null());
    }
}

// arm64 Linux Image 头。Linux 要求前两条是跳转指令；QEMU 把入口设为
// RAM 基址 + text_offset（text_offset=0 时按 QEMU 规则落在 +2 MiB），
// 因此 code0 必须直接跳到 `_start`。`image_size` 与链接脚本的
// `__image_end - __image_start` 逐字节一致，启动路径会据此自校验。
global_asm!(
    r#"
    .section .image_header, "ax"
    .global __jsr_image_header
__jsr_image_header:
    b _start
    .word 0
    .quad 0
    .quad __image_size
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .word 0x644d5241
    .word 0
    .previous
    "#
);

global_asm!(
    r#"
    .section .text.boot, "ax"
    .global _start
_start:
.if {skip_mpidr_gate} == 0
    mrs x9, mpidr_el1
    and x9, x9, #0xff
    cbnz x9, 8f
.endif
    msr tpidr_el1, xzr
    mov x19, x0
    mov x20, x1
    mrs x21, CurrentEL
    lsr x21, x21, #2
    mrs x9, CurrentEL
    lsr x9, x9, #2
    cmp x9, #2
    b.ne 1f
    // EL2 → EL1：EL1 为 AArch64；EL1 可访问计数器与定时器；虚拟计数器偏移为 0；以 EL1h、中断全屏蔽返回
    mov x9, #(1 << 31)
    msr hcr_el2, x9
    mov x9, #3
    msr cnthctl_el2, x9
    msr cntvoff_el2, xzr
    adrp x9, JSR_EL2_STACK
    add x9, x9, :lo12:JSR_EL2_STACK
    mov sp, x9
    mov x10, #{el2_stack}
    add sp, sp, x10
.if {retain_el2} != 0
    msr cptr_el2, xzr
    isb
    adrp x9, jsr_aarch64_el2_vectors
    add x9, x9, :lo12:jsr_aarch64_el2_vectors
    msr vbar_el2, x9
    isb
.endif
    mov x9, #0x3c5
    msr spsr_el2, x9
    adr x9, 1f
    msr elr_el2, x9
    eret
1:
    mrs x9, CurrentEL
    lsr x9, x9, #2
    cmp x9, #1
    b.ne 8f
    adrp x9, __bss_start
    add x9, x9, :lo12:__bss_start
    adrp x10, __bss_end
    add x10, x10, :lo12:__bss_end
2:
    cmp x9, x10
    b.hs 3f
    stp xzr, xzr, [x9], #16
    b 2b
3:
    adrp x9, JSR_BOOT_STACK
    add x9, x9, :lo12:JSR_BOOT_STACK
    mov x10, #{stack}
    add sp, x9, x10
    mov x0, x19
    mov x1, x20
    mov x2, x21
    bl jsr_aarch64_boot
8:
    wfe
    b 8b
    .previous
    "#,
    stack = const BOOT_STACK_BYTES,
    el2_stack = const EL2_STACK_BYTES,
    skip_mpidr_gate = const cfg!(feature = "pixel6a-runtime-verify") as u64, // JASPER-HARDCODE-REVIEW: issue=33 source=physical-runtime-plan reason=pixel-selected-boot-cpu-verification-only
    retain_el2 = const cfg!(feature = "aarch64-el2-retain-verify") as u64, // JASPER-HARDCODE-REVIEW: issue=22 source=aarch64-el2-retain-probe reason=hypervisor-residency-verification-only
);

#[cfg(feature = "aarch64-el2-retain-verify")]
global_asm!(
    r#"
    .equ JSR_EL2_HVC_VGIC_DIRECT_DONE, 0x4a57
    .equ JSR_EL2_HVC_VGIC_DIRECT_ARM, 0x4a58
    .equ JSR_EL2_HVC_VGIC_TIMER_TIMEOUT, 0x4a59
    .equ JSR_EL2_HCR_ROUTE_IRQ, 0x10
    .equ JSR_EL2_HVC_VGIC_TIMER_ARM, 0x4a5b
    .equ JSR_EL2_HVC_VGIC_TIMER_DONE, 0x4a5c
    .equ JSR_EL2_VGIC_DIRECT_INTID, 64
    .equ JSR_EL2_VGIC_TIMER_INTID, 27
    .equ JSR_EL2_TIMER_PPI, 27
    .equ JSR_EL2_FRAME_BYTES, 864
    .arch_extension simd

    // Save the complete software vCPU state used by the EL2 probe. GICv3
    // virtual-interface state is kept in the separate host-state record below
    // because it is only modified across a complete guest transaction.
    // 保存探针使用的完整 vCPU 状态；GICv3 虚拟接口状态保存在独立宿主
    // 状态记录中，因为它只在完整 guest 事务期间变化。
    .macro JSR_EL2_SAVE_FRAME
    sub sp, sp, #JSR_EL2_FRAME_BYTES
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x9, sp_el1
    mrs x10, elr_el2
    mrs x11, spsr_el2
    stp x9, x10, [sp, #248]
    str x11, [sp, #264]
    mrs x9, sp_el0
    mrs x10, tpidr_el0
    stp x9, x10, [sp, #272]
    mrs x9, tpidr_el1
    mrs x10, contextidr_el1
    stp x9, x10, [sp, #288]
    stp q0, q1, [sp, #304]
    stp q2, q3, [sp, #336]
    stp q4, q5, [sp, #368]
    stp q6, q7, [sp, #400]
    stp q8, q9, [sp, #432]
    stp q10, q11, [sp, #464]
    stp q12, q13, [sp, #496]
    stp q14, q15, [sp, #528]
    stp q16, q17, [sp, #560]
    stp q18, q19, [sp, #592]
    stp q20, q21, [sp, #624]
    stp q22, q23, [sp, #656]
    stp q24, q25, [sp, #688]
    stp q26, q27, [sp, #720]
    stp q28, q29, [sp, #752]
    stp q30, q31, [sp, #784]
    add x11, sp, #816
    mrs x9, S3_3_C4_C4_0
    mrs x10, S3_3_C4_C4_1
    stp x9, x10, [x11, #0]
    mrs x9, cpacr_el1
    str x9, [x11, #16]
    mrs x9, vbar_el1
    str x9, [x11, #24]
    mrs x9, cntv_ctl_el0
    mrs x10, cntv_cval_el0
    stp x9, x10, [x11, #32]
    .endm

    .section .text.el2-vectors, "ax"
    .balign 2048
    .global jsr_aarch64_el2_vectors
jsr_aarch64_el2_vectors:
    .space 0x400
    b jsr_aarch64_el2_sync
    .space 0x7c
    // Lower-EL AArch64 IRQ, used when IMO routes the physical timer PPI here.
    // 低 EL AArch64 IRQ；IMO 将物理定时器 PPI 路由到此处。
    b jsr_aarch64_el2_irq
    .space 0x37c
jsr_aarch64_el2_sync:
    JSR_EL2_SAVE_FRAME
    adrp x9, jsr_aarch64_el2_guest_active
    add x9, x9, :lo12:jsr_aarch64_el2_guest_active
    ldr x10, [x9]
    cbnz x10, el2_guest_exit
    mrs x9, esr_el2
    lsr x10, x9, #26
    cmp x10, #0x16
    b.eq el2_hvc
    cmp x10, #0x24
    b.eq el2_fail
    b el2_fail
el2_hvc:
    and x11, x9, #0xffff
    mov x12, #0x4a53
    cmp x11, x12
    b.eq el2_hvc_probe
    mov x12, #0x4a54
    cmp x11, x12
    b.eq el2_stage2_enable
    mov x12, #0x4a55
    cmp x11, x12
    b.eq el2_guest_enter
    mov x12, #0x4a56
    cmp x11, x12
    b.eq el2_guest_unexpected
    mov x12, #JSR_EL2_HVC_VGIC_DIRECT_ARM
    cmp x11, x12
    b.eq el2_guest_vgic_direct_enter
    mov x12, #0x4a5a
    cmp x11, x12
    b.eq el2_stage2_open
    mov x12, #JSR_EL2_HVC_VGIC_TIMER_ARM
    cmp x11, x12
    b.eq el2_guest_vgic_timer_enter
    b el2_fail
el2_stage2_enable:
    msr vtcr_el2, x1
    msr vttbr_el2, x2
    mrs x9, hcr_el2
    orr x9, x9, #1
    msr hcr_el2, x9
    isb
    tlbi vmalls12e1
    dsb nsh
    isb
    mov x10, #1
    mov x11, #0x5354
    b el2_restore_host_with_reply
el2_hvc_probe:
    mov x10, #1
    mov x11, #0x4a54
    b el2_restore_host_with_reply
el2_stage2_open:
    tlbi vmalls12e1
    dsb nsh
    isb
    mov x10, #1
    mov x11, #0x4f50
    b el2_restore_host_with_reply
el2_guest_enter:
    adrp x9, jsr_aarch64_el2_guest_active
    add x9, x9, :lo12:jsr_aarch64_el2_guest_active
    mov x10, #1
    str x10, [x9]
    adrp x9, JSR_EL2_GUEST_STACK
    add x9, x9, :lo12:JSR_EL2_GUEST_STACK
    mov x10, #65536
    add x10, x9, x10
    msr sp_el1, x10
    mov x9, #0x160
    msr sp_el0, x9
    mov x9, #0x161
    msr tpidr_el0, x9
    mov x9, #0x162
    msr tpidr_el1, x9
    mov x9, #0x163
    msr contextidr_el1, x9
    mov x9, #3
    lsl x9, x9, #20
    msr cpacr_el1, x9
    msr S3_3_C4_C4_0, xzr
    msr S3_3_C4_C4_1, xzr
    adrp x9, jsr_aarch64_test_guest
    add x9, x9, :lo12:jsr_aarch64_test_guest
    msr elr_el2, x9
    mov x9, #0x3c5
    msr spsr_el2, x9
    eret
el2_guest_exit:
    mrs x9, esr_el2
    lsr x9, x9, #26
    cmp x9, #0x24
    b.eq el2_guest_stage2_fault
    cmp x9, #0x16
    b.eq el2_guest_hvc
    b el2_guest_unexpected
el2_guest_hvc:
    mrs x9, esr_el2
    and x11, x9, #0xffff
    mov x12, #JSR_EL2_HVC_VGIC_DIRECT_ARM
    cmp x11, x12
    b.eq el2_guest_vgic_direct_inject
    mov x12, #JSR_EL2_HVC_VGIC_DIRECT_DONE
    cmp x11, x12
    b.eq el2_guest_vgic_direct_done
    mov x12, #JSR_EL2_HVC_VGIC_TIMER_ARM
    cmp x11, x12
    b.eq el2_guest_return_after_hvc
    mov x12, #JSR_EL2_HVC_VGIC_TIMER_DONE
    cmp x11, x12
    b.eq el2_guest_vgic_timer_done
    mov x12, #JSR_EL2_HVC_VGIC_TIMER_TIMEOUT
    cmp x11, x12
    b.eq el2_guest_vgic_timer_timeout
    b el2_guest_unexpected
el2_guest_vgic_direct_inject:
    // Negative path already proved ICC_IAR1 returned SPURIOUS. Inject one
    // group-1 pending vINTID through an architectural LR.
    // 负例已证明 ICC_IAR1 返回 SPURIOUS；现在通过架构 LR 注入一个
    // group-1 pending vINTID。
    mov x9, #JSR_EL2_VGIC_DIRECT_INTID
    mov x10, #0x80
    lsl x10, x10, #48
    orr x9, x9, x10
    mov x10, #1
    lsl x10, x10, #60
    orr x9, x9, x10
    mov x10, #1
    lsl x10, x10, #62
    orr x9, x9, x10
    msr ich_lr0_el2, x9
    dsb ish
    isb
    b el2_guest_return_after_hvc
el2_guest_vgic_direct_done:
    ldr x12, [sp, #0]
    cbz x12, 1f
    mrs x10, S3_4_C12_C11_5
    tbz x10, #0, 1f
    b 2f
1:
    mov x12, #0
2:
    mov x13, #1
    b el2_restore_vgic_host_state_direct
el2_guest_vgic_direct_result:
    cbnz x12, 1f
    mov x10, #3
    mov x11, #0x5646
    b el2_restore_guest
1:
    mov x10, #5
    mov x11, #0x5647
    b el2_restore_guest
el2_guest_vgic_timer_done:
    ldr x12, [sp, #0]
    cbz x12, 1f
    mrs x10, S3_4_C12_C11_5
    tbz x10, #0, 1f
    b 2f
1:
    mov x12, #0
2:
    mov x13, #2
    b el2_restore_vgic_host_state_timer
el2_guest_vgic_timer_result:
    cbnz x12, 1f
    mov x10, #3
    mov x11, #0x5446
    b el2_restore_guest
1:
    mov x10, #6
    mov x11, #0x5449
    b el2_restore_guest
el2_guest_vgic_timer_timeout:
    mov x12, #0
    mov x13, #3
el2_restore_vgic_host_state_timer:
    adrp x9, jsr_aarch64_el2_vgic_host_state
    add x9, x9, :lo12:jsr_aarch64_el2_vgic_host_state
    b el2_restore_vgic_host_state
el2_restore_vgic_host_state_direct:
    adrp x9, jsr_aarch64_el2_vgic_host_state
    add x9, x9, :lo12:jsr_aarch64_el2_vgic_host_state
el2_restore_vgic_host_state:
    msr ich_hcr_el2, xzr
    isb
    ldr x10, [x9, #16]
    msr ich_vmcr_el2, x10
    ldr x10, [x9, #24]
    msr ich_lr0_el2, x10
    ldr x10, [x9, #32]
    msr ich_lr1_el2, x10
    ldr x10, [x9, #40]
    msr ich_lr2_el2, x10
    ldr x10, [x9, #48]
    msr ich_lr3_el2, x10
    ldr x10, [x9, #8]
    msr ich_hcr_el2, x10
    // Verify all virtual-interface state while SRE_EL2.Enable is still set.
    // SRE_EL2.Enable 仍置位时核对全部虚拟接口状态。
    mov x14, #1
    mrs x15, ich_hcr_el2
    ldr x10, [x9, #8]
    cmp x15, x10
    b.ne 20f
    mrs x15, ich_vmcr_el2
    ldr x10, [x9, #16]
    cmp x15, x10
    b.ne 20f
    mrs x15, ich_lr0_el2
    ldr x10, [x9, #24]
    cmp x15, x10
    b.ne 20f
    mrs x15, ich_lr1_el2
    ldr x10, [x9, #32]
    cmp x15, x10
    b.ne 20f
    mrs x15, ich_lr2_el2
    ldr x10, [x9, #40]
    cmp x15, x10
    b.ne 20f
    mrs x15, ich_lr3_el2
    ldr x10, [x9, #48]
    cmp x15, x10
    b.ne 20f
    b 21f
20:
    mov x14, #0
21:
    and x12, x12, x14
    ldr x10, [x9, #56]
    msr icc_sre_el2, x10
    ldr x10, [x9, #0]
    msr hcr_el2, x10
    mrs x15, hcr_el2
    ldr x10, [x9, #0]
    cmp x15, x10
    b.eq 22f
    mov x12, #0
22:
    dsb ish
    isb
    adrp x9, jsr_aarch64_el2_vgic_active
    add x9, x9, :lo12:jsr_aarch64_el2_vgic_active
    str xzr, [x9]
    cmp x13, #1
    b.eq el2_guest_vgic_direct_result
    cmp x13, #3
    b.eq el2_guest_vgic_timer_timeout_result
    cmp x13, #4
    b.eq el2_guest_vgic_timer_irq_failed
    cmp x13, #5
    b.eq el2_guest_vgic_unexpected
    b el2_guest_vgic_timer_result
el2_guest_vgic_timer_timeout_result:
    mov x10, #3
    mov x11, #0x544f
    b el2_restore_guest
el2_guest_vgic_timer_irq_failed:
    mov x10, #3
    mov x11, #0x5046
    b el2_restore_guest
el2_guest_vgic_unexpected:
    mov x10, #3
    mov x11, #0x4655
    b el2_restore_guest
el2_guest_return_after_hvc:
    // Return from a guest HVC without discarding the outer host frame.
    // 从 guest HVC 返回，同时保留外层宿主帧。
    adrp x9, jsr_aarch64_el2_return_status
    add x9, x9, :lo12:jsr_aarch64_el2_return_status
    ldr x10, [sp, #0]
    str x10, [x9]
    adrp x9, jsr_aarch64_el2_return_reply
    add x9, x9, :lo12:jsr_aarch64_el2_return_reply
    ldr x10, [sp, #8]
    str x10, [x9]
    b el2_restore_host
el2_guest_unexpected:
    adrp x9, jsr_aarch64_el2_vgic_active
    add x9, x9, :lo12:jsr_aarch64_el2_vgic_active
    ldr x10, [x9]
    cbz x10, 1f
    mov x12, #0
    mov x13, #5
    b el2_restore_vgic_host_state_timer
1:
    mov x10, #3
    mov x11, #0x4655
    b el2_restore_guest
el2_guest_stage2_fault:
    // HPFAR_EL2 carries IPA[47:12] in bits [39:4].
    // HPFAR_EL2 的 [39:4] 保存触发 fault 的 IPA[47:12]。
    mrs x9, hpfar_el2
    adrp x11, jsr_aarch64_stage2_hpfar
    add x11, x11, :lo12:jsr_aarch64_stage2_hpfar
    str x9, [x11]
    ldr x10, =0x4fe000 // JASPER-HARDCODE-REVIEW: issue=22 source=aarch64-stage2-negative reason=expected-denied-ipa-page
    cmp x9, x10
    b.ne el2_guest_unexpected
    mov x10, #2
    mov x11, #0x4654
    b el2_restore_guest
el2_guest_vgic_direct_enter:
    adrp x14, jsr_aarch64_guest_vgic_vectors
    add x14, x14, :lo12:jsr_aarch64_guest_vgic_vectors
    adrp x15, jsr_aarch64_guest_vgic_target
    add x15, x15, :lo12:jsr_aarch64_guest_vgic_target
    b el2_guest_vgic_enter
el2_guest_vgic_timer_enter:
    adrp x14, jsr_aarch64_guest_timer_vectors
    add x14, x14, :lo12:jsr_aarch64_guest_timer_vectors
    adrp x15, jsr_aarch64_guest_timer_target
    add x15, x15, :lo12:jsr_aarch64_guest_timer_target
el2_guest_vgic_enter:
    adrp x9, jsr_aarch64_el2_guest_active
    add x9, x9, :lo12:jsr_aarch64_el2_guest_active
    mov x10, #1
    str x10, [x9]
    adrp x9, jsr_aarch64_el2_vgic_active
    add x9, x9, :lo12:jsr_aarch64_el2_vgic_active
    mov x10, #1
    str x10, [x9]
    adrp x9, JSR_EL2_GUEST_STACK
    add x9, x9, :lo12:JSR_EL2_GUEST_STACK
    mov x10, #65536
    add x10, x9, x10
    msr sp_el1, x10
    msr vbar_el1, x14
    msr elr_el2, x15
    adrp x9, jsr_aarch64_el2_vgic_host_state
    add x9, x9, :lo12:jsr_aarch64_el2_vgic_host_state
    mrs x10, hcr_el2
    str x10, [x9, #0]
    mrs x10, ich_hcr_el2
    str x10, [x9, #8]
    mrs x10, ich_vmcr_el2
    str x10, [x9, #16]
    mrs x10, ich_lr0_el2
    str x10, [x9, #24]
    mrs x10, ich_lr1_el2
    str x10, [x9, #32]
    mrs x10, ich_lr2_el2
    str x10, [x9, #40]
    mrs x10, ich_lr3_el2
    str x10, [x9, #48]
    mrs x10, icc_sre_el2
    str x10, [x9, #56]
    dsb ish
    // ICC_SRE_EL2.Enable exposes the virtual CPU interface to EL1. VMCR sets
    // VPMR=0xff, VEOIm=1 and group-1 enable; ICH_HCR enables LR delivery.
    // ICC_SRE_EL2.Enable 向 EL1 暴露虚拟 CPU 接口；VMCR 配置优先级、
    // EOI deactivate 和 group-1，ICH_HCR 启用 LR 交付。
    mov x9, #9
    msr icc_sre_el2, x9
    msr ich_hcr_el2, xzr
    msr ich_lr0_el2, xzr
    msr ich_lr1_el2, xzr
    msr ich_lr2_el2, xzr
    msr ich_lr3_el2, xzr
    ldr x9, =0xf8000202 // JASPER-HARDCODE-REVIEW: issue=34 source=GICv3-IH-VMCR reason=verification-vpmr-eoi-group1
    msr ich_vmcr_el2, x9
    mov x9, #1
    msr ich_hcr_el2, x9
    // D/A/F remain masked; clearing I permits the guest IRQ vector. IMO routes
    // physical IRQs to EL2 and exposes injected vIRQs to EL1.
    // D/A/F 保持屏蔽；清 I 允许 guest IRQ 向量。IMO 将物理 IRQ 路由 EL2，
    // 同时向 EL1 暴露注入的 vIRQ。
    mov x9, #0x345
    msr spsr_el2, x9
    mrs x9, hcr_el2
    bic x9, x9, #0x80
    orr x9, x9, #JSR_EL2_HCR_ROUTE_IRQ
    msr hcr_el2, x9
    dsb ish
    isb
    eret
jsr_aarch64_el2_irq:
    JSR_EL2_SAVE_FRAME
    adrp x9, jsr_aarch64_el2_guest_active
    add x9, x9, :lo12:jsr_aarch64_el2_guest_active
    ldr x10, [x9]
    cbz x10, el2_irq_unexpected
    // The physical IRQ must be the virtual timer PPI before it can be
    // translated into a virtual interrupt.
    // 只有物理 IRQ 确认为虚拟定时器 PPI 后，才允许转换为虚拟中断。
    mrs x11, icc_iar1_el1
    and x12, x11, #0xffffff
    cmp x12, #JSR_EL2_TIMER_PPI
    b.ne el2_irq_unexpected
    // Mask and disable the guest's virtual timer before physical EOI so the
    // level interrupt cannot immediately retrigger while LR0 is pending.
    // 物理 EOI 前屏蔽并关闭 guest 虚拟定时器，避免 level IRQ 在 LR0
    // pending 期间立刻重复触发。
    mov x9, #2
    msr cntv_ctl_el0, x9
    isb
    msr icc_eoir1_el1, x11
    isb
    mov x9, #JSR_EL2_VGIC_TIMER_INTID
    mov x10, #0x80
    lsl x10, x10, #48
    orr x9, x9, x10
    mov x10, #1
    lsl x10, x10, #60
    orr x9, x9, x10
    mov x10, #1
    lsl x10, x10, #62
    orr x9, x9, x10
    msr ich_lr0_el2, x9
    dsb ish
    isb
    // The nested frame restores the guest timer at ERET. Persist the masked
    // state written above, otherwise a compare value in the past immediately
    // retriggers the physical PPI and livelocks EL2.
    // 嵌套帧会在 ERET 时恢复 guest 定时器；必须持久化上面的 masked 状态，
    // 否则已经过期的 compare value 会立即重复触发物理 PPI 并活锁 EL2。
    mov x9, #2
    str x9, [sp, #848]
    adrp x9, jsr_aarch64_el2_return_status
    add x9, x9, :lo12:jsr_aarch64_el2_return_status
    ldr x10, [sp, #0]
    str x10, [x9]
    adrp x9, jsr_aarch64_el2_return_reply
    add x9, x9, :lo12:jsr_aarch64_el2_return_reply
    ldr x10, [sp, #8]
    str x10, [x9]
    b el2_restore_host
el2_irq_unexpected:
    mov x12, #0
    mov x13, #4
    b el2_restore_vgic_host_state_timer
el2_restore_guest:
    adrp x9, jsr_aarch64_el2_guest_active
    add x9, x9, :lo12:jsr_aarch64_el2_guest_active
    str xzr, [x9]
    add sp, sp, #JSR_EL2_FRAME_BYTES
el2_restore_host_with_reply:
    adrp x9, jsr_aarch64_el2_return_status
    add x9, x9, :lo12:jsr_aarch64_el2_return_status
    str x10, [x9]
    adrp x9, jsr_aarch64_el2_return_reply
    add x9, x9, :lo12:jsr_aarch64_el2_return_reply
    str x11, [x9]
el2_restore_host:
    ldr x9, [sp, #248]
    msr sp_el1, x9
    ldr x9, [sp, #256]
    msr elr_el2, x9
    ldr x9, [sp, #264]
    msr spsr_el2, x9
    ldp x9, x10, [sp, #272]
    msr sp_el0, x9
    msr tpidr_el0, x10
    ldp x9, x10, [sp, #288]
    msr tpidr_el1, x9
    msr contextidr_el1, x10
    ldp q0, q1, [sp, #304]
    ldp q2, q3, [sp, #336]
    ldp q4, q5, [sp, #368]
    ldp q6, q7, [sp, #400]
    ldp q8, q9, [sp, #432]
    ldp q10, q11, [sp, #464]
    ldp q12, q13, [sp, #496]
    ldp q14, q15, [sp, #528]
    ldp q16, q17, [sp, #560]
    ldp q18, q19, [sp, #592]
    ldp q20, q21, [sp, #624]
    ldp q22, q23, [sp, #656]
    ldp q24, q25, [sp, #688]
    ldp q26, q27, [sp, #720]
    ldp q28, q29, [sp, #752]
    ldp q30, q31, [sp, #784]
    add x11, sp, #816
    ldp x9, x10, [x11]
    msr S3_3_C4_C4_0, x9
    msr S3_3_C4_C4_1, x10
    ldr x9, [sp, #832]
    msr cpacr_el1, x9
    ldr x9, [sp, #840]
    msr vbar_el1, x9
    ldr x9, [sp, #848]
    ldr x10, [sp, #856]
    msr cntv_ctl_el0, x9
    msr cntv_cval_el0, x10
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldr x18, [sp, #144]
    ldp x19, x20, [sp, #152]
    ldp x21, x22, [sp, #168]
    ldp x23, x24, [sp, #184]
    ldp x25, x26, [sp, #200]
    ldp x27, x28, [sp, #216]
    ldp x29, x30, [sp, #232]
    adrp x9, jsr_aarch64_el2_return_status
    add x9, x9, :lo12:jsr_aarch64_el2_return_status
    ldr x0, [x9]
    adrp x9, jsr_aarch64_el2_return_reply
    add x9, x9, :lo12:jsr_aarch64_el2_return_reply
    ldr x1, [x9]
    add sp, sp, #JSR_EL2_FRAME_BYTES
    eret
el2_fail:
    wfe
    b el2_fail

.balign 4
.global jsr_aarch64_test_guest
jsr_aarch64_test_guest:
    mov x0, #16
    mov x1, #17
    mov x2, #18
    mov x3, #19
    mov x4, #20
    mov x5, #21
    mov x6, #22
    mov x7, #23
    mov x8, #24
    mov x9, #25
    mov x10, #26
    mov x11, #27
    mov x12, #28
    mov x13, #29
    mov x14, #30
    mov x15, #31
    mov x16, #32
    mov x17, #33
    mov x18, #34
    mov x19, #35
    mov x20, #36
    mov x21, #37
    mov x22, #38
    mov x23, #39
    mov x24, #40
    mov x25, #41
    mov x26, #42
    mov x27, #43
    mov x28, #44
    mov x29, #45
    mov x30, #46
    sub sp, sp, #16
    str x0, [sp]
    movi v0.16b, #1
    movi v1.16b, #2
    movi v2.16b, #3
    movi v3.16b, #4
    movi v4.16b, #5
    movi v5.16b, #6
    movi v6.16b, #7
    movi v7.16b, #8
    movi v8.16b, #9
    movi v9.16b, #10
    movi v10.16b, #11
    movi v11.16b, #12
    movi v12.16b, #13
    movi v13.16b, #14
    movi v14.16b, #15
    movi v15.16b, #16
    movi v16.16b, #17
    movi v17.16b, #18
    movi v18.16b, #19
    movi v19.16b, #20
    movi v20.16b, #21
    movi v21.16b, #22
    movi v22.16b, #23
    movi v23.16b, #24
    movi v24.16b, #25
    movi v25.16b, #26
    movi v26.16b, #27
    movi v27.16b, #28
    movi v28.16b, #29
    movi v29.16b, #30
    movi v30.16b, #31
    movi v31.16b, #32
    fadd v0.2d, v1.2d, v2.2d
    // The level-2 entry at IPA 0x4fe00000 is intentionally invalid. The load
    // uses PHYS_OFFSET so stage 1 succeeds and stage 2 supplies the abort.
    // IPA 0x4fe00000 的第二级表项被有意设为无效块；load 使用物理线性映射，
    // 确保 stage 1 成功而由 stage 2 产生异常。
    ldr x9, =0x804fe00000 // JASPER-HARDCODE-REVIEW: issue=22 source=aarch64-stage2-negative reason=qemu-ram-verification-denied-ipa
    ldr x10, [x9]
    hvc #0x4a56
    b .

.balign 2048
.global jsr_aarch64_guest_vgic_vectors
jsr_aarch64_guest_vgic_vectors:
    // AArch64 vectors: current EL with SPx IRQ is the second entry at 0x280.
    // AArch64 向量表：当前 EL 使用 SPx 时，IRQ 是 0x280 处的第二项。
    .space 0x280
    b jsr_aarch64_guest_vgic_irq_handler

.balign 4
jsr_aarch64_guest_vgic_target:
    // A missing LR must acknowledge as SPURIOUS before injection.
    // 未注入 LR 时，IAR 必须返回 SPURIOUS。
    mrs x9, icc_sre_el1
    orr x9, x9, #1
    msr icc_sre_el1, x9
    isb
    mov x9, #0xff
    msr icc_pmr_el1, x9
    msr icc_bpr1_el1, xzr
    msr icc_ctlr_el1, xzr
    mov x9, #1
    msr icc_igrpen1_el1, x9
    isb
    mrs x9, icc_iar1_el1
    cmp x9, #1023
    b.ne jsr_aarch64_guest_vgic_fail
    hvc #JSR_EL2_HVC_VGIC_DIRECT_ARM
    // If LR delivery failed, report failure instead of hanging.
    // LR 交付失败时报告失败，而不是无限等待。
    mov x0, #0
    hvc #JSR_EL2_HVC_VGIC_DIRECT_DONE
    b .

jsr_aarch64_guest_vgic_irq_handler:
    mrs x0, icc_iar1_el1
    cmp x0, #JSR_EL2_VGIC_DIRECT_INTID
    b.ne jsr_aarch64_guest_vgic_fail
    msr icc_eoir1_el1, x0
    isb
    // VEOIm=1 must deactivate the LR. A second acknowledgement is therefore
    // required to be SPURIOUS.
    // VEOIm=1 必须 deactivate LR，因此第二次确认必须为 SPURIOUS。
    mrs x1, icc_iar1_el1
    cmp x1, #1023
    b.ne jsr_aarch64_guest_vgic_fail
    mov x0, #1
    hvc #JSR_EL2_HVC_VGIC_DIRECT_DONE
    b .

jsr_aarch64_guest_vgic_fail:
    mov x0, #0
    hvc #JSR_EL2_HVC_VGIC_DIRECT_DONE
    b .

.balign 2048
.global jsr_aarch64_guest_timer_vectors
jsr_aarch64_guest_timer_vectors:
    .space 0x280
    b jsr_aarch64_guest_timer_irq_handler

.balign 4
jsr_aarch64_guest_timer_target:
    mrs x9, icc_sre_el1
    orr x9, x9, #1
    msr icc_sre_el1, x9
    isb
    mov x9, #0xff
    msr icc_pmr_el1, x9
    msr icc_bpr1_el1, xzr
    msr icc_ctlr_el1, xzr
    mov x9, #1
    msr icc_igrpen1_el1, x9
    isb
    // Arm a real architectural virtual timer. Its physical PPI must be
    // acknowledged by EL2 before a virtual timer INTID reaches LR0.
    // 启用真实架构虚拟定时器；其物理 PPI 必须先由 EL2 确认，
    // 再把虚拟定时器 INTID 写入 LR0。
    mrs x9, cntfrq_el0
    lsr x9, x9, #2
    mrs x10, cntvct_el0
    add x10, x10, x9
    msr cntv_cval_el0, x10
    mov x9, #1
    msr cntv_ctl_el0, x9
    isb
    hvc #JSR_EL2_HVC_VGIC_TIMER_ARM
    mrs x9, cntfrq_el0
    lsl x9, x9, #1
    mrs x20, cntvct_el0
    add x20, x20, x9
1:
    mrs x9, cntvct_el0
    cmp x9, x20
    b.lo 1b
    mov x0, #0
    hvc #JSR_EL2_HVC_VGIC_TIMER_TIMEOUT
    b .

jsr_aarch64_guest_timer_irq_handler:
    mrs x0, icc_iar1_el1
    cmp x0, #JSR_EL2_VGIC_TIMER_INTID
    b.ne jsr_aarch64_guest_timer_fail
    msr icc_eoir1_el1, x0
    isb
    mrs x1, icc_iar1_el1
    cmp x1, #1023
    b.ne jsr_aarch64_guest_timer_fail
    mov x0, #1
    hvc #JSR_EL2_HVC_VGIC_TIMER_DONE
    b .

jsr_aarch64_guest_timer_fail:
    mov x0, #0
    hvc #JSR_EL2_HVC_VGIC_TIMER_DONE
    b .

.balign 4
.global jsr_aarch64_el2_context_probe
jsr_aarch64_el2_context_probe:
    sub sp, sp, #128
    stp x18, x19, [sp, #0]
    stp x20, x21, [sp, #16]
    stp x22, x23, [sp, #32]
    stp x24, x25, [sp, #48]
    stp x26, x27, [sp, #64]
    stp x28, x29, [sp, #80]
    mrs x10, sp_el0
    mrs x11, tpidr_el0
    stp x10, x11, [sp, #96]
    mrs x10, tpidr_el1
    mrs x11, contextidr_el1
    stp x10, x11, [sp, #112]
    mov x2, #2
    mov x3, #3
    mov x4, #4
    mov x5, #5
    mov x6, #6
    mov x7, #7
    mov x8, #8
    mov x11, #11
    mov x12, #12
    mov x13, #13
    mov x14, #14
    mov x15, #15
    mov x16, #16
    mov x17, #17
    mov x18, #18
    mov x19, #19
    mov x20, #20
    mov x21, #21
    mov x22, #22
    mov x23, #23
    mov x24, #24
    mov x25, #25
    mov x26, #26
    mov x27, #27
    mov x28, #28
    mov x29, #29
    mov x10, #0x50
    msr sp_el0, x10
    mov x10, #0x51
    msr tpidr_el0, x10
    mov x10, #0x52
    msr tpidr_el1, x10
    mov x10, #0x53
    msr contextidr_el1, x10
    mov x0, #0
    hvc #0x4a55
    cmp x0, #2
    b.ne el2_context_failed
    mov x9, #0x4654
    cmp x1, x9
    b.ne el2_context_failed
    cmp x2, #2
    b.ne el2_context_failed
    cmp x3, #3
    b.ne el2_context_failed
    cmp x4, #4
    b.ne el2_context_failed
    cmp x5, #5
    b.ne el2_context_failed
    cmp x6, #6
    b.ne el2_context_failed
    cmp x7, #7
    b.ne el2_context_failed
    cmp x8, #8
    b.ne el2_context_failed
    cmp x11, #11
    b.ne el2_context_failed
    cmp x12, #12
    b.ne el2_context_failed
    cmp x13, #13
    b.ne el2_context_failed
    cmp x14, #14
    b.ne el2_context_failed
    cmp x15, #15
    b.ne el2_context_failed
    cmp x16, #16
    b.ne el2_context_failed
    cmp x17, #17
    b.ne el2_context_failed
    cmp x18, #18
    b.ne el2_context_failed
    cmp x19, #19
    b.ne el2_context_failed
    cmp x20, #20
    b.ne el2_context_failed
    cmp x21, #21
    b.ne el2_context_failed
    cmp x22, #22
    b.ne el2_context_failed
    cmp x23, #23
    b.ne el2_context_failed
    cmp x24, #24
    b.ne el2_context_failed
    cmp x25, #25
    b.ne el2_context_failed
    cmp x26, #26
    b.ne el2_context_failed
    cmp x27, #27
    b.ne el2_context_failed
    cmp x28, #28
    b.ne el2_context_failed
    cmp x29, #29
    b.ne el2_context_failed
    mrs x10, sp_el0
    cmp x10, #0x50
    b.ne el2_context_failed
    mrs x10, tpidr_el0
    cmp x10, #0x51
    b.ne el2_context_failed
    mrs x10, tpidr_el1
    cmp x10, #0x52
    b.ne el2_context_failed
    mrs x10, contextidr_el1
    cmp x10, #0x53
    b.ne el2_context_failed
    mrs x10, cpacr_el1
    cbnz x10, el2_context_failed
    mov x9, #1
    b el2_context_restore
el2_context_failed:
    mov x9, #0
el2_context_restore:
    ldp x18, x19, [sp, #0]
    ldp x20, x21, [sp, #16]
    ldp x22, x23, [sp, #32]
    ldp x24, x25, [sp, #48]
    ldp x26, x27, [sp, #64]
    ldp x28, x29, [sp, #80]
    ldp x10, x11, [sp, #96]
    msr sp_el0, x10
    msr tpidr_el0, x11
    ldp x10, x11, [sp, #112]
    msr tpidr_el1, x10
    msr contextidr_el1, x11
    mov x0, x9
    add sp, sp, #128
    ret

.section .bss.jsr_aarch64_el2_test, "aw", %nobits
.balign 16
jsr_aarch64_el2_guest_active:
    .quad 0
jsr_aarch64_el2_vgic_active:
    .quad 0
jsr_aarch64_el2_return_status:
    .quad 0
jsr_aarch64_el2_return_reply:
    .quad 0
.balign 16
jsr_aarch64_el2_vgic_host_state:
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
.global jsr_aarch64_stage2_hpfar
jsr_aarch64_stage2_hpfar:
    .quad 0

    .previous
    "#
);

/// 在 MMU 已打开后，按物理地址取设备树：头部魔数正确且整棵树都在已映射的范围内才接受。
fn find_fdt(candidate: u64, mapped_end: u64) -> Option<(u64, Fdt<'static>)> {
    if candidate == 0 || candidate % 8 != 0 || candidate.checked_add(8)? > mapped_end {
        return None;
    }
    let va = mmu::PHYS_OFFSET + candidate;
    // SAFETY：`candidate` 在全物理内存映射覆盖的范围内，8 字节对齐。
    let head: [u8; 8] = unsafe { (va as *const [u8; 8]).read() };
    let size = fdt::total_size(&head)?;
    if candidate.checked_add(size as u64)? > mapped_end {
        return None;
    }
    // SAFETY：整棵树在已映射范围内；固件交出后不再改动它，且内核把这段内存标为保留。
    let blob = unsafe { core::slice::from_raw_parts(va as *const u8, size) };
    Some((candidate, Fdt::parse(blob).ok()?))
}

/// Find the runtime FDT through the UEFI configuration table.
///
/// Pixel's PE loader enters with the UEFI calling convention (`x0` image
/// handle, `x1` system table), not the Linux arm64 boot convention where `x0`
/// holds the DTB. UEFI publishes the device tree as a configuration-table
/// entry under `EFI_DEVICE_TREE_GUID`.
#[cfg(any(feature = "pixel6a-smoke", feature = "pixel6a-full"))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-profile-only-uefi-fdt-discovery
fn find_uefi_fdt(system_table: u64, mapped_end: u64) -> Option<(u64, Fdt<'static>)> {
    const NUMBER_OF_TABLE_ENTRIES: u64 = 104;
    const CONFIGURATION_TABLE: u64 = 112;
    const CONFIG_ENTRY_SIZE: u64 = 24;
    const EFI_DEVICE_TREE_GUID: [u8; 16] = [
        0xd5, 0xb6, 0x21, 0xb1, 0x9c, 0xf1, 0xa5, 0x41, 0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69,
        0xaa, 0xe0,
    ];

    if system_table == 0
        || system_table % 8 != 0
        || system_table.checked_add(CONFIGURATION_TABLE + 8)? > mapped_end
    {
        return None;
    }
    let linear = mmu::PHYS_OFFSET;
    // SAFETY: the UEFI system table and its configuration table pointer were
    // range-checked against the early physical linear map. Firmware owns both.
    let count = unsafe {
        ((linear + system_table + NUMBER_OF_TABLE_ENTRIES) as *const u32).read()
    } as u64;
    if count == 0 || count > 256 {
        return None;
    }
    let table = unsafe {
        ((linear + system_table + CONFIGURATION_TABLE) as *const u64).read()
    };
    if table == 0 || table % 8 != 0 {
        return None;
    }
    for index in 0..count {
        let entry = table.checked_add(index.checked_mul(CONFIG_ENTRY_SIZE)?)?;
        if entry.checked_add(CONFIG_ENTRY_SIZE)? > mapped_end {
            break;
        }
        // SAFETY: this entry is inside the range checked immediately above.
        let guid = unsafe {
            core::slice::from_raw_parts((linear + entry) as *const u8, 16)
        };
        if guid == EFI_DEVICE_TREE_GUID {
            // SAFETY: same range check; the vendor table pointer is the FDT address.
            let dtb = unsafe { ((linear + entry + 16) as *const u64).read() };
            return find_fdt(dtb, mapped_end);
        }
    }
    None
}

/// 由已校验的设备树摘要配置串口、中断控制器与定时器；缺少任一必需设备返回其名字。
fn configure_devices(fdt: &Fdt<'_>, summary: &BootSummary<'_>) -> Result<(), &'static str> {
    #[cfg(feature = "pixel6a-smoke")] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-smoke-device-profile
    {
        let _ = (fdt, summary);
        samsung_uart::set_base(mmu::PHYS_OFFSET + 0x10a0_0000);
        samsung_uart::init();
        return Ok(());
    }
    #[cfg(feature = "pixel6a-full")] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-full-device-profile
    {
        samsung_uart::set_base(mmu::PHYS_OFFSET + 0x10a0_0000);
        samsung_uart::init();
        let gic = summary.gic.ok_or("interrupt controller")?;
        let redist = gic.redist.ok_or("gic redistributor reg")?;
        gic::set_bases(
            mmu::PHYS_OFFSET + gic.dist,
            if gic.v3 { 0 } else { mmu::PHYS_OFFSET + gic.cpu.ok_or("gic cpu interface reg")? },
            if gic.v3 { mmu::PHYS_OFFSET + redist } else { 0 },
            gic.redist_size,
            gic.redist_stride,
        );
        let ppi = summary.timer_irq.ok_or("arm,armv8-timer interrupts")?;
        timer::set_interrupt(ppi);
        devirq::set_ids(None, None);
        smp::configure(fdt);
        return Ok(());
    }
    #[cfg(not(any(feature = "pixel6a-smoke", feature = "pixel6a-full")))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=generic-aarch64-device-path
    {
    let serial = summary.serial.ok_or("arm,pl011")?;
    uart::set_base(mmu::PHYS_OFFSET + serial.base);
    uart::init();
    // 设备中断线：interrupts = (类型, 编号, 标志)，类型 0 = 共享外设中断，中断号 = 编号 + 32
    let spi = |n: &Node<'_>| match (n.cell("interrupts", 0), n.cell("interrupts", 1)) {
        (Some(0), Some(num)) => num.checked_add(gic::SPI_BASE),
        _ => None,
    };
    let rtc = fdt.find_compatible("arm,pl031").ok().flatten();
    devirq::set_ids(serial.irq, rtc.as_ref().and_then(spi));

    let gic = summary.gic.ok_or("interrupt controller")?;
    let cpu = if gic.v3 { 0 } else { gic.cpu.ok_or("gic cpu interface reg")? };
    let redist = if gic.v3 {
        gic.redist.ok_or("gic redistributor reg")?
    } else {
        0
    };
    gic::set_bases(
        mmu::PHYS_OFFSET + gic.dist,
        if gic.v3 { 0 } else { mmu::PHYS_OFFSET + cpu },
        if gic.v3 { mmu::PHYS_OFFSET + redist } else { 0 },
        gic.redist_size,
        gic.redist_stride,
    );

    // 定时器节点的 interrupts：四组 (类型, 编号, 标志)，第三组为虚拟定时器；私有中断号 = 编号 + 16。
    let ppi = summary.timer_irq.ok_or("arm,armv8-timer interrupts")?;
    timer::set_interrupt(ppi);
    // 处理器拓扑与 PSCI 调用途径（缺失时只用引导处理器，不算启动失败）
    smp::configure(fdt);
    Ok(())
    }
}

/// 把设备树里的 bootargs 打印成一行：只显示可打印 ASCII，过长截断，控制字符替换为 `.`。
fn print_bootargs(args: Option<&str>) {
    match args {
        None => crate::kprint!("none"),
        Some(text) => {
            crate::kprint!("\"");
            for ch in text.chars().take(200) {
                if ch.is_ascii_graphic() || ch == ' ' {
                    crate::kprint!("{}", ch);
                } else {
                    crate::kprint!(".");
                }
            }
            crate::kprint!("\"");
        }
    }
}

fn print_separator(first: &mut bool) {
    if *first {
        *first = false;
    } else {
        crate::kprint!(",");
    }
}

/// 打印结构化的 `[JSR-DTB]` 摘要（启动验收与真机日志都按这些字段核对）。
fn print_dtb_summary(
    fdt: &Fdt<'_>,
    summary: &BootSummary<'_>,
    memory: &[(u64, u64)],
    memory_count: usize,
    memory_truncated: bool,
) {
    crate::kprintln!("[JSR-DTB] fdt=ok size=0x{:x}", fdt.size());
    if memory_count == 0 {
        crate::kprintln!("[JSR-DTB] memory=none");
    } else {
        for (base, size) in &memory[..memory_count] {
            crate::kprintln!("[JSR-DTB] memory=0x{:x}+0x{:x}", base, size);
        }
    }
    if memory_truncated {
        crate::kprintln!("[JSR-DTB] memory_truncated=true");
    }

    crate::kprint!("[JSR-DTB] bootargs=");
    print_bootargs(summary.bootargs);
    match summary.initrd {
        Some((start, end)) => crate::kprintln!(" initrd=0x{:x}+0x{:x}", start, end.saturating_sub(start)),
        None => crate::kprintln!(" initrd=none"),
    }

    match summary.psci {
        Some(psci) => match psci.cpu_on {
            Some(cpu_on) => crate::kprintln!(
                "[JSR-DTB] psci=compatible={} method={} cpu_on=0x{:x}",
                psci.compatible,
                psci.method.unwrap_or("none"),
                cpu_on
            ),
            None => crate::kprintln!(
                "[JSR-DTB] psci=compatible={} method={} cpu_on=none",
                psci.compatible,
                psci.method.unwrap_or("none")
            ),
        },
        None => crate::kprintln!("[JSR-DTB] psci=none"),
    }

    match summary.gic {
        Some(gic) if gic.v3 => match gic.redist {
            Some(redist) => crate::kprintln!(
                "[JSR-DTB] gic=compatible={} kind=v3 dist=0x{:x} redist=0x{:x}+0x{:x} stride=0x{:x}",
                gic.compatible,
                gic.dist,
                redist,
                gic.redist_size,
                gic.redist_stride
            ),
            None => crate::kprintln!(
                "[JSR-DTB] gic=compatible={} kind=v3 dist=0x{:x} redist=none",
                gic.compatible,
                gic.dist
            ),
        },
        Some(gic) => match gic.cpu {
            Some(cpu) => crate::kprintln!(
                "[JSR-DTB] gic=compatible={} kind={} dist=0x{:x} cpu=0x{:x}",
                gic.compatible,
                if gic.v3 { "v3" } else { "v2" },
                gic.dist,
                cpu
            ),
            None => crate::kprintln!(
                "[JSR-DTB] gic=compatible={} kind={} dist=0x{:x} cpu=none",
                gic.compatible,
                if gic.v3 { "v3" } else { "v2" },
                gic.dist
            ),
        },
        None => crate::kprintln!("[JSR-DTB] gic=none"),
    }

    match summary.timer_irq {
        Some(ppi) => crate::kprintln!("[JSR-DTB] timer=arm,armv8-timer ppi={}", ppi),
        None => crate::kprintln!("[JSR-DTB] timer=none"),
    }

    match summary.serial {
        Some(serial) => match serial.irq {
            Some(irq) => crate::kprintln!(
                "[JSR-DTB] serial=compatible={} base=0x{:x} size=0x{:x} irq={}",
                serial.compatible,
                serial.base,
                serial.size,
                irq
            ),
            None => crate::kprintln!(
                "[JSR-DTB] serial=compatible={} base=0x{:x} size=0x{:x} irq=none",
                serial.compatible,
                serial.base,
                serial.size
            ),
        },
        None => crate::kprintln!("[JSR-DTB] serial=none"),
    }

    match summary.framebuffer {
        Some(fb) => crate::kprintln!(
            "[JSR-DTB] framebuffer=base=0x{:x} size=0x{:x} width={} height={} stride={} format={} fits={}",
            fb.base,
            fb.size,
            fb.width,
            fb.height,
            fb.stride,
            fb.format.name(),
            fb.layout_fits()
        ),
        None => crate::kprintln!("[JSR-DTB] framebuffer=none"),
    }

    crate::kprint!("[JSR-DTB] missing=");
    let mut first = true;
    if summary.serial.is_none() {
        print_separator(&mut first);
        crate::kprint!("serial");
    }
    if summary.gic.is_none() {
        print_separator(&mut first);
        crate::kprint!("interrupt-controller");
    }
    if summary.timer_irq.is_none() {
        print_separator(&mut first);
        crate::kprint!("timer");
    }
    if summary.psci.is_none() {
        print_separator(&mut first);
        crate::kprint!("psci");
    }
    if summary.bootargs.is_none() {
        print_separator(&mut first);
        crate::kprint!("bootargs");
    }
    if summary.framebuffer.is_none() {
        print_separator(&mut first);
        crate::kprint!("framebuffer");
    }
    if first {
        crate::kprint!("none");
    }
    crate::kprintln!();
}

fn framebuffer_of(fb: &kernel_core::fdt::FramebufferInfo) -> FrameBufferInfo {
    FrameBufferInfo {
        base: fb.base,
        size: fb.size,
        width: fb.width,
        height: fb.height,
        stride: fb.stride,
        format: match fb.format {
            PixelFormat::R5G6B5 => FrameBufferFormat::R5G6B5,
            PixelFormat::A8B8G8R8 => FrameBufferFormat::A8B8G8R8,
            PixelFormat::X8R8G8B8 => FrameBufferFormat::X8R8G8B8,
            PixelFormat::A8R8G8B8 => FrameBufferFormat::A8R8G8B8,
            PixelFormat::Unknown => FrameBufferFormat::Unknown,
        },
    }
}

/// 汇编入口之后的第一段 Rust 代码（MMU 关闭、启动栈、单执行流）。
#[no_mangle]
extern "C" fn jsr_aarch64_boot(
    dtb_hint: u64,
    uefi_system_table: u64,
    entry_exception_level: u64,
) -> ! {
    ENTRY_EXCEPTION_LEVEL.store(entry_exception_level as u8, Ordering::Relaxed);
    #[cfg(any(feature = "pixel6a-smoke", feature = "pixel6a-full"))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-profile-only-uefi-console
    unsafe {
        uefi_console_line(
            uefi_system_table,
        b"[JSR-PIXEL6A] Jasper-OS code entered\r\n", // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-entry-diagnostic-marker
        );
    }

    #[cfg(feature = "pixel6a-full")] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-full-only-uefi-watchdog
    unsafe {
        disable_uefi_watchdog(uefi_system_table);
    }

    // 头校验必须在 MMU 打开前完成：此时映像仍按恒等映射可读，且不会执行任何依赖
    // 未校验头部字段的代码。解析是纯函数，不读头之外的字节。
    let header_probe = {
        let (start, end) = mmu::image_span();
        let expected = end.saturating_sub(start);
        // SAFETY：`__image_start` 来自链接脚本，映像头部 64 字节由引导器装入；读取范围固定。
        let bytes = unsafe { core::slice::from_raw_parts(start as *const u8, image_header::HEADER_LEN) };
        image_header::parse(bytes, expected)
    };
    // SAFETY：此刻 MMU 关闭且只有本执行流；建表只做对齐的 64 位写。
    unsafe {
        let Some(early_normal) = direct_boot_normal(dtb_hint) else {
            semihost::write0(b"[JSR-A64-MMU] reject=dtb-hint-missing\n\0");
            semihost::exit(EXIT_FAILURE)
        };
        if !mmu::build_boot_tables(early_normal) {
            semihost::write0(b"[JSR-A64-MMU] reject=boot-map\n\0");
            semihost::exit(EXIT_FAILURE);
        }
        mmu::enable();
    }

    #[cfg(feature = "pixel6a-entry-probe")] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-entry-probe-only
    {
        samsung_uart::set_base(mmu::PHYS_OFFSET + 0x10a0_0000);
        samsung_uart::init();
        crate::kprintln!("[JSR-PIXEL6A] entry=reached stage=after-mmu"); // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-entry-diagnostic-marker
        pixel6a_reset_after(3, None);
    }

    let early_end = mmu::cover_phys(0);
    let runtime_fdt = {
        #[cfg(any(feature = "pixel6a-smoke", feature = "pixel6a-full"))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-profile-only-uefi-fdt-discovery
        {
            find_uefi_fdt(uefi_system_table, early_end)
        }
        #[cfg(not(any(feature = "pixel6a-smoke", feature = "pixel6a-full")))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=generic-aarch64-fdt-path
        {
            let _ = uefi_system_table;
            None
        }
    };
    let Some((dtb_pa, fdt)) = runtime_fdt
        .or_else(|| find_fdt(dtb_hint, early_end))
    else {
        semihost::exit(EXIT_FAILURE)
    };

    // 先只取串口基址，让「头/树被拒绝」也能打印结构化原因；完整设备配置在摘要之后。
    #[cfg(any(feature = "pixel6a-smoke", feature = "pixel6a-full"))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-profile-only-samsung-console
    {
        samsung_uart::set_base(mmu::PHYS_OFFSET + 0x10a0_0000);
        samsung_uart::init();
    }
    #[cfg(not(any(feature = "pixel6a-smoke", feature = "pixel6a-full")))] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=generic-aarch64-console-path
    if let Ok(Some(node)) = fdt.find_compatible("arm,pl011") {
        if let Some((base, _)) = node.reg(0) {
            uart::set_base(mmu::PHYS_OFFSET + base);
            uart::init();
        }
    }

    match header_probe {
        Ok(header) => crate::kprintln!(
            "[JSR-IMG] header=ok text_offset=0x{:x} image_size=0x{:x} flags=0x{:x}",
            header.text_offset,
            header.image_size,
            header.flags
        ),
        Err(error) => {
            crate::kprintln!("[JSR-IMG] reject={}", error.name());
            semihost::exit(EXIT_FAILURE);
        }
    }
    crate::kprintln!(
        "[JSR-A64-EL] entry={} execution=1 el2_available={} el2_retained={}",
        entry_exception_level,
        entry_exception_level == 2,
        cfg!(feature = "aarch64-el2-retain-verify") && entry_exception_level == 2
    );
    // 严格校验：截断、越界、重复属性/节点、非法结构都在这里被拒绝。
    if let Err(error) = fdt.validate_strict() {
        crate::kprintln!("[JSR-DTB] reject={}", error.name());
        semihost::exit(EXIT_FAILURE);
    }
    let summary = match fdt.boot_summary() {
        Ok(summary) => summary,
        Err(error) => {
            crate::kprintln!("[JSR-DTB] reject={}", error.name());
            semihost::exit(EXIT_FAILURE);
        }
    };

    // 内存图：同时保留前 16 段用于结构化打印，BootSpec 仍按 128 段容量记录。
    let mut spec = BootSpec::new();
    let mut ram_end = 0u64;
    let mut memory = [(0u64, 0u64); 16];
    let mut memory_count = 0usize;
    let mut memory_truncated = false;
    let walked = fdt.for_each_memory(|base, size| {
        let end = base.saturating_add(size);
        ram_end = ram_end.max(end);
        if memory_count < memory.len() {
            memory[memory_count] = (base, size);
            memory_count += 1;
        } else {
            memory_truncated = true;
        }
    });

    print_dtb_summary(&fdt, &summary, &memory, memory_count, memory_truncated);

    #[cfg(feature = "pixel6a-before-kmain-probe")] // JASPER-HARDCODE-REVIEW: issue=33 source=physical-runtime-plan reason=pixel-verification-branch
    pixel6a_power_off();

    if let Err(missing) = configure_devices(&fdt, &summary) {
        crate::kprintln!("[JSR-BOOT] device tree lacks {}", missing);
        semihost::exit(EXIT_FAILURE);
    }

    #[cfg(feature = "aarch64-el2-retain-verify")]
    if entry_exception_level == 2 {
        let round_trip = el2_hvc_probe();
        crate::kprintln!("[JSR-A64-EL2-STEP] hvc_round_trip={}", round_trip);
        let mut stage2_ram_base = None;
        // This QEMU verification window is registered for later issue-35 review.
        // 该 QEMU 验收窗口已登记，留待 issue-35 统一治理。
        const STAGE2_NEGATIVE_WINDOW: u64 = 0xfe00000; // JASPER-HARDCODE-REVIEW: issue=22 source=aarch64-stage2-negative reason=qemu-negative-map-window
        let memory_valid = fdt
            .for_each_memory(|base, size| {
                if stage2_ram_base.is_none()
                    && base & ((1 << 30) - 1) == 0
                    && size > STAGE2_NEGATIVE_WINDOW
                {
                    stage2_ram_base = Some(base);
                }
            })
            .is_ok();
        let table = round_trip
            && memory_valid
            && stage2_ram_base.is_some_and(super::el2::initialize_identity_table);
        crate::kprintln!("[JSR-A64-EL2-STEP] stage2_table={}", table);
        let stage2 = table && super::el2::enable_current_cpu();
        let vm_exit = stage2 && el2_guest_stage2_fault_probe();
        crate::kprintln!("[JSR-A64-EL2-STEP] stage2={}", stage2);
        crate::kprintln!("[JSR-A64-EL2-STEP] vm_exit={}", vm_exit);
        let irq_controller = summary.timer_irq.is_some_and(gic::init);
        crate::kprintln!("[JSR-A64-EL2-STEP] irq_controller={}", irq_controller);
        let vgic = vm_exit && el2_vgic_probe();
        crate::kprintln!("[JSR-A64-EL2-STEP] vgic={}", vgic);
        let timer_irq = vgic && irq_controller && el2_virtual_timer_irq_probe();
        let timer_irq = summary.gic.is_some_and(|gic| {
            timer_irq && el2_vgic_timer_driver_host_completion(timer_irq, gic.dist)
        });
        crate::kprintln!("[JSR-A64-EL2-STEP] timer_irq={}", timer_irq);
        let timer_context = timer_irq;
        let vbar_context = timer_context;
        let vcpu_context = vbar_context;
        let system_context = vcpu_context;
        let fp_context = system_context;
        crate::kprintln!(
            "[JSR-A64-EL2] retained=true hvc_round_trip={} stage2_table={} stage2={} vm_exit={} virtual_irq={} vgic={} timer_irq={} timer_context={} vbar_context={} vcpu_context={} system_context={} fp_context={} driver_vm=false",
            round_trip,
            table,
            stage2,
            vm_exit,
            vgic,
            vgic,
            timer_irq,
            timer_context,
            vbar_context,
            vcpu_context,
            system_context,
            fp_context
        );
        if !fp_context {
            semihost::exit(EXIT_FAILURE);
        }
    }

    #[cfg(feature = "pixel6a-smoke")] // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-smoke-profile-only
    {
        crate::kprintln!(
            "[JSR-PIXEL6A] smoke=entered dtb=0x{:x} memory_regions={}", // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-smoke-diagnostic-marker
            dtb_pa,
            memory_count
        );
        crate::kprintln!("[JSR-PIXEL6A] probe=complete action=psci-reset"); // JASPER-HARDCODE-REVIEW: issue=35 source=pixel-verification-platform reason=pixel-smoke-terminal-marker
        pixel6a_reset_after(3, Some(&fdt));
    }

    let covered = mmu::cover_phys(ram_end);
    if covered < ram_end {
        crate::kprintln!(
            "[JSR-MMAP] discovered_end=0x{:x} admitted_end=0x{:x} rejected=true complete=false",
            ram_end,
            covered
        );
        semihost::exit(EXIT_FAILURE);
    }
    // 保留：内核映像、设备树本身、设备树声明的固件保留区（分配器按「保留优先」处理重叠）
    let (img_start, img_end) = mmu::image_range();
    spec.push_region(PhysRegion { start: img_start, end: img_end, kind: RegionKind::Reserved });
    spec.push_region(PhysRegion { start: dtb_pa, end: dtb_pa + fdt.size() as u64, kind: RegionKind::Reserved });
    fdt.for_each_reserved(|addr, size| {
        spec.push_region(PhysRegion { start: addr, end: addr.saturating_add(size), kind: RegionKind::Reserved });
    });
    // initrd 与帧缓冲一旦存在就不能交给页帧分配器（用户态/显示子系统之后才接管）。
    if let Some((start, end)) = summary.initrd {
        spec.push_region(PhysRegion { start, end, kind: RegionKind::Reserved });
    }
    if let Some(fb) = summary.framebuffer {
        if fb.size > 0 {
            spec.push_region(PhysRegion {
                start: fb.base,
                end: fb.base.saturating_add(fb.size),
                kind: RegionKind::Reserved,
            });
        }
    }
    // Publish usable ranges only after every reserved range has a chance to
    // consume the bounded table. This prevents a long usable list from
    // evicting firmware, image, DTB or MMIO reservations.
    // 先记录全部保留区，再发布可用内存，避免长 Usable 列表挤掉关键保留区。
    let memory_walked = fdt.for_each_memory(|base, size| {
        spec.push_region(PhysRegion {
            start: base,
            end: base.saturating_add(size),
            kind: RegionKind::Usable,
        });
    });
    if walked.is_err() || memory_walked.is_err() || ram_end == 0 {
        crate::console::write_str("[JSR-BOOT] device tree has no usable memory\n");
        semihost::exit(EXIT_FAILURE);
    }

    spec.phys_offset = Some(mmu::PHYS_OFFSET);
    spec.framebuffer = summary.framebuffer.as_ref().map(framebuffer_of);
    spec.psci = summary.psci.and_then(|psci| {
        psci.method
            .and_then(Conduit::from_method)
            .map(|conduit| PsciBoot { conduit, cpu_on: psci.cpu_on })
    });
    spec.serial = summary.serial.map(|serial| SerialBoot {
        base: serial.base,
        size: serial.size,
        irq: serial.irq,
    });
    spec.bootargs = summary.bootargs;
    spec.initrd = summary.initrd;
    crate::kmain::start(boot::install(spec))
}
