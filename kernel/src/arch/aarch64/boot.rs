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

use kernel_core::fdt::{self, BootSummary, Fdt, Node, PixelFormat};
use kernel_core::frame::{PhysRegion, RegionKind};
use kernel_core::image_header;
use kernel_core::psci::Conduit;

use super::{devirq, gic, mmu, semihost, smp, timer, uart};
use crate::boot::{self, BootSpec, FrameBufferFormat, FrameBufferInfo, PsciBoot, SerialBoot};

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

/// 由已校验的设备树摘要配置串口、中断控制器与定时器；缺少任一必需设备返回其名字。
fn configure_devices(fdt: &Fdt<'_>, summary: &BootSummary<'_>) -> Result<(), &'static str> {
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

    let gic = summary.gic.ok_or("arm,gic-v2")?;
    if gic.v3 {
        // 本内核当前实现 GICv2；GICv3 的 redistributor / SGI 框架尚未落地，不能假装可用。
        return Err("arm,gic-v3 (not implemented)");
    }
    let cpu = gic.cpu.ok_or("gic cpu interface reg")?;
    gic::set_bases(mmu::PHYS_OFFSET + gic.dist, mmu::PHYS_OFFSET + cpu);

    // 定时器节点的 interrupts：四组 (类型, 编号, 标志)，第三组为虚拟定时器；私有中断号 = 编号 + 16。
    let ppi = summary.timer_irq.ok_or("arm,armv8-timer interrupts")?;
    timer::set_interrupt(ppi);
    // 处理器拓扑与 PSCI 调用途径（缺失时只用引导处理器，不算启动失败）
    smp::configure(fdt);
    Ok(())
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
extern "C" fn jsr_aarch64_boot(dtb_hint: u64) -> ! {
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
        if !mmu::build_boot_tables() {
            semihost::exit(EXIT_FAILURE);
        }
        mmu::enable();
    }
    let early_end = mmu::cover_phys(0);
    let Some((dtb_pa, fdt)) = find_fdt(dtb_hint, early_end).or_else(|| find_fdt(QEMU_VIRT_DTB, early_end)) else {
        semihost::exit(EXIT_FAILURE)
    };

    // 先只取串口基址，让「头/树被拒绝」也能打印结构化原因；完整设备配置在摘要之后。
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
        spec.push_region(PhysRegion { start: base, end, kind: RegionKind::Usable });
    });

    if let Err(missing) = configure_devices(&fdt, &summary) {
        crate::kprintln!("[JSR-BOOT] device tree lacks {}", missing);
        semihost::exit(EXIT_FAILURE);
    }
    print_dtb_summary(&fdt, &summary, &memory, memory_count, memory_truncated);

    let covered = mmu::cover_phys(ram_end);
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
    // 超出全物理内存映射范围的内存不能交给分配器（内核无法访问它们）
    if ram_end > covered {
        spec.push_region(PhysRegion { start: covered, end: ram_end, kind: RegionKind::Reserved });
    }
    if walked.is_err() || ram_end == 0 {
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
