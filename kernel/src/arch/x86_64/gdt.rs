//! GDT + TSS + 双重错误 IST 栈（x86_64 专有）。
//!
//! 段布局：空 / 内核代码 / 内核数据 / 用户数据 / 用户代码 / TSS。
//! 用户数据段排在用户代码段之前，是 `syscall/sysret`（M3.2）对选择子顺序的硬性要求，提前定好避免日后改动。
//!
//! TSS 必须可变：`rsp0`（从用户态进入内核时 CPU 使用的栈）随每次任务切换更新为该任务的内核栈顶。
//! 单 CPU 下只有调度器在关中断临界区里写它，因此用 `static mut` + 显式函数封装。

use core::mem::size_of;
use core::ptr::{addr_of, addr_of_mut};

use spin::Once;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// 双重错误使用的 IST 槽位。
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
const STACK_SIZE: usize = 4096 * 5;

#[repr(align(16))]
struct Stack<T>(T);

static mut DOUBLE_FAULT_STACK: Stack<[u8; STACK_SIZE]> = Stack([0; STACK_SIZE]);
/// 引导阶段（还没有任务时）的 rsp0 栈。
static mut BOOT_RSP0_STACK: Stack<[u8; STACK_SIZE]> = Stack([0; STACK_SIZE]);

/// 可变 TSS（只经 [`set_kernel_stack`] 修改 rsp0）。
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

/// 全部段选择子。
#[derive(Clone, Copy)]
pub struct Selectors {
    /// 内核代码段。
    pub kernel_code: SegmentSelector,
    /// 内核数据段。
    pub kernel_data: SegmentSelector,
    /// 用户数据段（RPL=3）。
    pub user_data: SegmentSelector,
    /// 用户代码段（RPL=3）。
    pub user_code: SegmentSelector,
    tss: SegmentSelector,
}

/// 构建并加载 GDT、刷新段寄存器、加载 TSS。
pub fn init() {
    // SAFETY：只在启动时（单执行流、未开中断）初始化一次 TSS。
    let tss: &'static TaskStateSegment = unsafe {
        let t = &mut *addr_of_mut!(TSS);
        let df_end = VirtAddr::from_ptr(addr_of!(DOUBLE_FAULT_STACK)) + STACK_SIZE as u64;
        let rsp0_end = VirtAddr::from_ptr(addr_of!(BOOT_RSP0_STACK)) + STACK_SIZE as u64;
        t.privilege_stack_table[0] = rsp0_end;
        t.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = df_end;
        t.iomap_base = size_of::<TaskStateSegment>() as u16;
        &*addr_of!(TSS)
    };

    let (gdt, sel) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());
        let tss_sel = gdt.append(Descriptor::tss_segment(tss));
        (gdt, Selectors { kernel_code, kernel_data, user_data, user_code, tss: tss_sel })
    });

    gdt.load();
    // SAFETY：选择子来自刚加载的 GDT。
    unsafe {
        CS::set_reg(sel.kernel_code);
        DS::set_reg(sel.kernel_data);
        ES::set_reg(sel.kernel_data);
        SS::set_reg(sel.kernel_data);
        load_tss(sel.tss);
    }
}

/// 段选择子（`init` 之后可用）。
pub fn selectors() -> Selectors {
    GDT.get().expect("GDT 未初始化").1
}

/// 设置从用户态进入内核时使用的栈顶（TSS.rsp0）。
///
/// 调用者（调度器）在关中断临界区内调用；CPU 只在特权级切换时读取它。
pub fn set_kernel_stack(top: u64) {
    // SAFETY：单 CPU、关中断下的唯一写者；TSS 已加载，CPU 读取的是同一块内存。
    unsafe { (*addr_of_mut!(TSS)).privilege_stack_table[0] = VirtAddr::new(top) };
}
