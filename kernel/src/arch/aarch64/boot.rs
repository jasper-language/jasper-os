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

use kernel_core::fdt::{self, Fdt};
use kernel_core::frame::{PhysRegion, RegionKind};

use super::{devirq, gic, mmu, msi, pci, semihost, smp, timer, uart};
use crate::boot::{self, BootSpec};

/// 启动栈大小。
const BOOT_STACK_BYTES: usize = 64 * 1024;

/// 启动栈（任务系统建立之前的唯一执行流使用）。
#[repr(C, align(16))]
struct BootStack([u8; BOOT_STACK_BYTES]);

#[no_mangle]
static mut JSR_BOOT_STACK: BootStack = BootStack([0; BOOT_STACK_BYTES]);

/// QEMU `virt` 在没有经 `x0` 传递时放置设备树的位置（内存起点）。
const QEMU_VIRT_DTB: u64 = 0x4000_0000;
/// 找不到设备树或必需设备时的退出码（与 x86_64 的失败码相同）。
const EXIT_FAILURE: u32 = 35;

global_asm!(
    r#"
    .section .text.boot, "ax"
    .global _start
_start:
    mrs x9, mpidr_el1
    and x9, x9, #0xff
    cbnz x9, 8f
    msr tpidr_el1, xzr
    mov x19, x0
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
    bl jsr_aarch64_boot
8:
    wfe
    b 8b
    .previous
    "#,
    stack = const BOOT_STACK_BYTES,
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

/// 由设备树配置串口、中断控制器与定时器中断号；缺少任一必需设备返回其名字。
fn configure_devices(fdt: &Fdt<'_>) -> Result<(), &'static str> {
    let uart_node = fdt.find_compatible("arm,pl011").ok().flatten().ok_or("arm,pl011")?;
    let (uart_pa, _) = uart_node.reg(0).ok_or("arm,pl011 reg")?;
    uart::set_base(mmu::PHYS_OFFSET + uart_pa);
    // 设备中断线：interrupts = (类型, 编号, 标志)，类型 0 = 共享外设中断，中断号 = 编号 + 32
    let spi = |n: &kernel_core::fdt::Node<'_>| match (n.cell("interrupts", 0), n.cell("interrupts", 1)) {
        (Some(0), Some(num)) => Some(num + gic::SPI_BASE),
        _ => None,
    };
    let rtc = fdt.find_compatible("arm,pl031").ok().flatten();
    devirq::set_ids(spi(&uart_node), rtc.as_ref().and_then(spi));

    let gic_node = match fdt.find_compatible("arm,cortex-a15-gic").ok().flatten() {
        Some(n) => n,
        None => fdt.find_compatible("arm,gic-400").ok().flatten().ok_or("arm,gic-400")?,
    };
    let (dist, _) = gic_node.reg(0).ok_or("gic distributor reg")?;
    let (cpu, _) = gic_node.reg(1).ok_or("gic cpu interface reg")?;
    gic::set_bases(mmu::PHYS_OFFSET + dist, mmu::PHYS_OFFSET + cpu);

    // 定时器节点的 interrupts：四组 (类型, 编号, 标志)，第三组为虚拟定时器；私有中断号 = 编号 + 16。
    let timer_node = fdt.find_compatible("arm,armv8-timer").ok().flatten().ok_or("arm,armv8-timer")?;
    let ppi = timer_node.cell("interrupts", 7).ok_or("arm,armv8-timer interrupts")?;
    timer::set_interrupt(ppi + 16);
    // PCI 配置空间（ECAM）与 MSI（GICv2m 帧）：没有对应设备树节点时保持平台不支持，
    // 由演练按平台能力报告，不伪造设备。
    pci::configure(fdt);
    msi::configure(fdt);
    // 处理器拓扑与 PSCI 调用途径（缺失时只用引导处理器，不算启动失败）
    smp::configure(fdt);
    Ok(())
}

/// 汇编入口之后的第一段 Rust 代码（MMU 关闭、启动栈、单执行流）。
#[no_mangle]
extern "C" fn jsr_aarch64_boot(dtb_hint: u64) -> ! {
    // SAFETY：此刻 MMU 关闭且只有本执行流；建表只做对齐的 64 位写。
    unsafe {
        if !mmu::build_boot_tables() {
            semihost::exit(EXIT_FAILURE);
        }
        mmu::enable();
    }
    let early_end = mmu::cover_phys(0);
    let Some((dtb_pa, fdt)) = find_fdt(dtb_hint, early_end).or_else(|| find_fdt(QEMU_VIRT_DTB, early_end)) else {
        semihost::exit(EXIT_FAILURE)
    };
    if let Err(missing) = configure_devices(&fdt) {
        // 串口可能已就绪（缺的是别的设备）：尽量说明原因再退出
        uart::init();
        crate::console::_print(format_args!("[JSR-BOOT] device tree lacks {}\n", missing));
        semihost::exit(EXIT_FAILURE);
    }

    let mut spec = BootSpec::new();
    let mut ram_end = 0u64;
    let walked = fdt.for_each_memory(|base, size| {
        let end = base.saturating_add(size);
        ram_end = ram_end.max(end);
        spec.push_region(PhysRegion { start: base, end, kind: RegionKind::Usable });
    });
    let covered = mmu::cover_phys(ram_end);
    // 保留：内核映像、设备树本身、设备树声明的固件保留区（分配器按「保留优先」处理重叠）
    let (img_start, img_end) = mmu::image_range();
    spec.push_region(PhysRegion { start: img_start, end: img_end, kind: RegionKind::Reserved });
    spec.push_region(PhysRegion { start: dtb_pa, end: dtb_pa + fdt.size() as u64, kind: RegionKind::Reserved });
    fdt.for_each_reserved(|addr, size| {
        spec.push_region(PhysRegion { start: addr, end: addr.saturating_add(size), kind: RegionKind::Reserved });
    });
    // 超出全物理内存映射范围的内存不能交给分配器（内核无法访问它们）
    if ram_end > covered {
        spec.push_region(PhysRegion { start: covered, end: ram_end, kind: RegionKind::Reserved });
    }
    if walked.is_err() || ram_end == 0 {
        uart::init();
        crate::console::write_str("[JSR-BOOT] device tree has no usable memory\n");
        semihost::exit(EXIT_FAILURE);
    }
    spec.phys_offset = Some(mmu::PHYS_OFFSET);
    crate::kmain::start(boot::install(spec))
}
