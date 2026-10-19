//! RISC-V 引导适配层：内核入口 `_start`、早期页表与地址转换、设备树 → [`BootSpec`]、进入内核主流程。
//! RISC-V boot adapter (RV32 / RV64): `_start`, early paging, device tree to `BootSpec`, then the kernel main flow.
//!
//! RISC-V 上没有 x86 那样的引导器：机器态固件（QEMU 默认的 OpenSBI）把内核 ELF 放到链接地址，
//! 以监管态、地址转换关闭的状态从 `_start` 进入，`a0` = 处理器编号（hart id），`a1` = 设备树物理地址。本文件负责：
//! 1. 只让第一个到达的处理器继续（其余停在 `wfi`）；关中断、清零 BSS、设置启动栈；
//! 2. 建早期页表并启用地址转换（RV64 为 Sv39、RV32 为 Sv32，见 `mmu.rs` 与 `mode`）；
//! 3. 解析设备树：内存图、串口、中断控制器（及本处理器监管态的上下文编号）、计数器频率、仿真器测试设备；
//! 4. 把内存图转换成与引导协议无关的 [`BootSpec`]（内核映像、设备树、固件保留区、线性映射覆盖不到的内存标为保留），
//!    交给 `kmain::start`。

use core::arch::global_asm;

use kernel_core::fdt::{self, Fdt, Node};
use kernel_core::frame::{PhysRegion, RegionKind};

use super::{mmu, plic, testdev, timer, uart};
use crate::boot::{self, BootSpec};

/// 启动栈大小。
const BOOT_STACK_BYTES: usize = 64 * 1024;
/// 找不到设备树或必需设备时的退出码（与 x86_64 的失败码相同）。
const EXIT_FAILURE: u16 = 35;
/// 处理器本地中断控制器中「监管态外部中断」的编号（PLIC 上下文据此识别）。
const INTC_S_EXTERNAL: u32 = 9;

/// 启动栈（任务系统建立之前的唯一执行流使用）。
#[repr(C, align(16))]
struct BootStack([u8; BOOT_STACK_BYTES]);

#[no_mangle]
static mut JSR_BOOT_STACK: BootStack = BootStack([0; BOOT_STACK_BYTES]);

/// 「已有处理器进入内核」标志：放在已初始化数据段，清零 BSS 之前即可使用。
#[no_mangle]
#[link_section = ".data.jsr_boot_claim"]
static mut JSR_BOOT_CLAIM: u32 = 0;

global_asm!(
    r#"
    .section .text.boot, "ax"
    .option push
    .option norelax
    .global _start
_start:
    csrw sie, zero
    csrci sstatus, 2
    lla t0, JSR_BOOT_CLAIM
    li t1, 1
    amoswap.w.aq t2, t1, (t0)
    bnez t2, 3f
    lla t0, __bss_start
    lla t1, __bss_end
1:
    bgeu t0, t1, 2f
    sw zero, 0(t0)
    addi t0, t0, 4
    j 1b
2:
    lla sp, JSR_BOOT_STACK
    li t0, {stack}
    add sp, sp, t0
    call jsr_riscv_boot
3:
    wfi
    j 3b
    .option pop
    .previous
    "#,
    stack = const BOOT_STACK_BYTES,
);

/// 物理区间 `[start, end)` 是否完整位于线性映射可访问的范围内（`[0, mapped_end)` 去掉空洞 [`mmu::PHYS_HOLE`]）。
fn linear_mapped(start: u64, end: u64, mapped_end: u64) -> bool {
    let (hole_start, hole_end) = mmu::PHYS_HOLE;
    end <= mapped_end && (end <= hole_start || start >= hole_end)
}

/// 在地址转换已启用后，按物理地址取设备树：头部魔数正确且整棵树都在已映射的范围内才接受。
fn find_fdt(candidate: u64, mapped_end: u64) -> Option<(u64, Fdt<'static>)> {
    if candidate == 0 || candidate % 8 != 0 || !linear_mapped(candidate, candidate.checked_add(8)?, mapped_end) {
        return None;
    }
    let va = (mmu::PHYS_OFFSET + candidate) as usize;
    // SAFETY：`candidate` 在线性映射覆盖的范围内，8 字节对齐。
    let head: [u8; 8] = unsafe { (va as *const [u8; 8]).read() };
    let size = fdt::total_size(&head)?;
    if !linear_mapped(candidate, candidate.checked_add(size as u64)?, mapped_end) {
        return None;
    }
    // SAFETY：整棵树在已映射范围内；固件交出后不再改动它，且内核把这段内存标为保留。
    let blob = unsafe { core::slice::from_raw_parts(va as *const u8, size) };
    Some((candidate, Fdt::parse(blob).ok()?))
}

/// 从设备树中与启动处理器有关的部分取出：计数器频率（`/cpus` 的 `timebase-frequency`）
/// 与本处理器本地中断控制器的 phandle（`cpu@<hart>` 下的 `riscv,cpu-intc`）。
fn boot_cpu_info(fdt: &Fdt<'_>, hart: u64) -> (Option<u32>, Option<u32>) {
    let (mut freq, mut intc) = (None, None);
    let mut in_boot_cpu = false;
    let _ = fdt.walk(|n: &Node<'_>| {
        if n.depth == 1 && n.name == "cpus" {
            freq = n.cell("timebase-frequency", 0);
        }
        if n.depth == 2 {
            in_boot_cpu = n.name.starts_with("cpu@") && n.reg(0).map(|(id, _)| id) == Some(hart);
        }
        if n.depth == 3 && in_boot_cpu && n.is_compatible("riscv,cpu-intc") {
            intc = n.cell("phandle", 0);
        }
        true
    });
    (freq, intc)
}

/// PLIC 中属于本处理器监管态的上下文编号：`interrupts-extended` 的第 k 对 (phandle, 中断号)
/// 指向本处理器的本地中断控制器且中断号为「监管态外部中断」时，k 即上下文编号。
fn plic_context(node: &Node<'_>, intc: u32) -> Option<u32> {
    let mut k = 0u32;
    while let (Some(ph), Some(irq)) = (node.cell("interrupts-extended", 2 * k as usize), node.cell("interrupts-extended", 2 * k as usize + 1)) {
        if ph == intc && irq == INTC_S_EXTERNAL {
            return Some(k);
        }
        k += 1;
    }
    None
}

/// 由设备树配置串口、中断控制器、计数器频率与测试设备；缺少任一必需设备返回其名字。
fn configure_devices(fdt: &Fdt<'_>, hart: u64) -> Result<(), &'static str> {
    let uart_node = fdt.find_compatible("ns16550a").ok().flatten().ok_or("ns16550a")?;
    let (uart_pa, _) = uart_node.reg(0).ok_or("ns16550a reg")?;
    let uart_irq = uart_node.cell("interrupts", 0).ok_or("ns16550a interrupts")?;
    uart::set_base(mmu::PHYS_OFFSET + uart_pa, uart_irq);

    let (freq, intc) = boot_cpu_info(fdt, hart);
    timer::set_frequency(freq.ok_or("timebase-frequency")?);
    let intc = intc.ok_or("riscv,cpu-intc of the boot hart")?;

    let plic_node = match fdt.find_compatible("riscv,plic0").ok().flatten() {
        Some(n) => n,
        None => fdt.find_compatible("sifive,plic-1.0.0").ok().flatten().ok_or("riscv,plic0")?,
    };
    let (plic_pa, _) = plic_node.reg(0).ok_or("plic reg")?;
    let context = plic_context(&plic_node, intc).ok_or("plic context of the boot hart")?;
    plic::set_base(mmu::PHYS_OFFSET + plic_pa, context);

    // 测试设备是可选的（真机上没有）：缺少时退出走 SBI 关机
    if let Some((pa, _)) = fdt.find_compatible("sifive,test0").ok().flatten().and_then(|n| n.reg(0)) {
        testdev::set_base(mmu::PHYS_OFFSET + pa);
    }
    Ok(())
}

/// 把 `/reserved-memory` 下各子节点的 `reg` 区间报告给 `f`（固件用它声明自己占用、内核不得使用的内存）。
fn for_each_reserved_node(fdt: &Fdt<'_>, mut f: impl FnMut(u64, u64)) {
    let mut in_reserved = false;
    let _ = fdt.walk(|n: &Node<'_>| {
        if n.depth == 1 {
            in_reserved = n.name == "reserved-memory";
        } else if n.depth == 2 && in_reserved {
            let mut i = 0;
            while let Some((base, size)) = n.reg(i) {
                f(base, size);
                i += 1;
            }
        }
        true
    });
}

/// 引导处理器的 hart 编号（处理器拓扑的下标 0）。
pub static BOOT_HART: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// 汇编入口之后的第一段 Rust 代码（地址转换关闭、启动栈、单执行流）。
#[no_mangle]
extern "C" fn jsr_riscv_boot(hart: usize, dtb: usize) -> ! {
    let (hart, dtb) = (hart as u64, dtb as u64);
    BOOT_HART.store(hart as u32, core::sync::atomic::Ordering::Relaxed);
    // SAFETY：此刻地址转换关闭且只有本执行流；建表只做按表项宽度对齐的写。
    unsafe {
        if !mmu::build_boot_tables() {
            testdev::exit(EXIT_FAILURE);
        }
        mmu::enable();
    }
    let early_end = mmu::cover_phys(0);
    let Some((dtb_pa, fdt)) = find_fdt(dtb, early_end) else {
        testdev::exit(EXIT_FAILURE)
    };
    if let Err(missing) = configure_devices(&fdt, hart) {
        // 串口可能已就绪（缺的是别的设备）：尽量说明原因再退出
        uart::init();
        crate::console::_print(format_args!("[JSR-BOOT] device tree lacks {}\n", missing));
        testdev::exit(EXIT_FAILURE);
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
    for_each_reserved_node(&fdt, |addr, size| {
        spec.push_region(PhysRegion { start: addr, end: addr.saturating_add(size), kind: RegionKind::Reserved });
    });
    // 线性映射覆盖不到的内存（上限之外、空洞之内）不能交给分配器（内核无法访问它们）
    if ram_end > covered {
        spec.push_region(PhysRegion { start: covered, end: ram_end, kind: RegionKind::Reserved });
    }
    let (hole_start, hole_end) = mmu::PHYS_HOLE;
    if hole_end > hole_start {
        spec.push_region(PhysRegion { start: hole_start, end: hole_end, kind: RegionKind::Reserved });
    }
    if walked.is_err() || ram_end == 0 {
        uart::init();
        crate::console::write_str("[JSR-BOOT] device tree has no usable memory\n");
        testdev::exit(EXIT_FAILURE);
    }
    spec.phys_offset = Some(mmu::PHYS_OFFSET);
    crate::kmain::start(boot::install(spec))
}
