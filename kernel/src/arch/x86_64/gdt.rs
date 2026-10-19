//! GDT + TSS + 双重错误 IST 栈（x86_64 专有），每个处理器一份。
//!
//! 段布局：空 / 内核代码 / 内核数据 / 用户数据 / 用户代码 / TSS。
//! 用户数据段排在用户代码段之前，是 `syscall/sysret`（M3.2）对选择子顺序的硬性要求，提前定好避免日后改动。
//! 所有处理器的布局完全相同（系统调用 MSR 里的选择子对每个处理器都成立），只有 TSS 各自独立：
//! TSS 描述符带「忙」位、`rsp0` 随该处理器上的任务切换而变，不能共享。
//!
//! 引导处理器的表放在静态存储里（堆就绪之前就要用）；其他处理器的表在启动它之前从内核堆分配并永久保留。
//! `rsp0`（从用户态进入内核时使用的栈）只由本处理器在关中断临界区里写，经 [`set_kernel_stack`] 封装。

use alloc::alloc::{alloc_zeroed, Layout};
use alloc::boxed::Box;
use core::mem::size_of;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicPtr, Ordering};

use kernel_core::smp::MAX_CPUS;
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

/// 引导处理器的可变 TSS（只经 [`set_kernel_stack`] 修改 rsp0）。
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

/// 每个处理器的 TSS（下标 = 逻辑下标；空 = 尚未准备）。
static CPU_TSS: [AtomicPtr<TaskStateSegment>; MAX_CPUS] = [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];
/// 其他处理器的 GDT（下标 = 逻辑下标）。
static CPU_GDT: [AtomicPtr<GlobalDescriptorTable>; MAX_CPUS] = [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];

/// 全部段选择子。
#[derive(Clone, Copy, PartialEq, Eq)]
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

/// 按统一布局构建一张 GDT。
fn build(tss: &'static TaskStateSegment) -> (GlobalDescriptorTable, Selectors) {
    let mut gdt = GlobalDescriptorTable::new();
    let kernel_code = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data = gdt.append(Descriptor::kernel_data_segment());
    let user_data = gdt.append(Descriptor::user_data_segment());
    let user_code = gdt.append(Descriptor::user_code_segment());
    let tss_sel = gdt.append(Descriptor::tss_segment(tss));
    (gdt, Selectors { kernel_code, kernel_data, user_data, user_code, tss: tss_sel })
}

/// 加载 GDT、刷新段寄存器、加载 TSS。
fn load(gdt: &'static GlobalDescriptorTable, sel: Selectors) {
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

/// 引导处理器：构建并加载 GDT、刷新段寄存器、加载 TSS。
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
    CPU_TSS[0].store(addr_of_mut!(TSS), Ordering::Release);
    let (gdt, sel) = GDT.call_once(|| build(tss));
    load(gdt, *sel);
}

/// 每个其他处理器独占的栈（双重错误 IST 栈与引导阶段的 rsp0 栈）。
#[repr(C, align(16))]
struct CpuStacks {
    double_fault: [u8; STACK_SIZE],
    rsp0: [u8; STACK_SIZE],
}

/// 为逻辑下标 `index`（≥ 1）的处理器准备 GDT 与 TSS（在启动它之前、于引导处理器上调用）。
/// 重复调用复用已准备好的表；下标越界返回 `false`。
pub fn prepare_cpu(index: usize) -> bool {
    if index == 0 || index >= MAX_CPUS {
        return false;
    }
    if !CPU_GDT[index].load(Ordering::Acquire).is_null() {
        return true;
    }
    // 栈与表永久保留（处理器不会下线），因此直接泄漏为 'static。
    // 直接在堆上清零分配：先在栈上构造 40 KiB 的值再搬进堆会压垮调用者的内核栈。
    let layout = Layout::new::<CpuStacks>();
    // SAFETY：布局非零大小；全零是 CpuStacks 的合法值。
    let raw = unsafe { alloc_zeroed(layout) } as *mut CpuStacks;
    if raw.is_null() {
        return false;
    }
    // SAFETY：raw 刚分配、已清零、对齐满足布局，且永不释放。
    let stacks: &'static mut CpuStacks = unsafe { &mut *raw };
    let mut tss = TaskStateSegment::new();
    tss.privilege_stack_table[0] = VirtAddr::from_ptr(stacks.rsp0.as_ptr()) + STACK_SIZE as u64;
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        VirtAddr::from_ptr(stacks.double_fault.as_ptr()) + STACK_SIZE as u64;
    tss.iomap_base = size_of::<TaskStateSegment>() as u16;
    let tss: &'static mut TaskStateSegment = Box::leak(Box::new(tss));
    let tss_ptr: *mut TaskStateSegment = tss;
    // SAFETY：tss 已泄漏为 'static；之后只经 CPU_TSS 指针由该处理器自己写 rsp0。
    let (gdt, sel) = build(unsafe { &*tss_ptr });
    if sel != selectors() {
        return false;
    }
    let gdt: &'static mut GlobalDescriptorTable = Box::leak(Box::new(gdt));
    CPU_TSS[index].store(tss_ptr, Ordering::Release);
    CPU_GDT[index].store(gdt, Ordering::Release);
    true
}

/// 在逻辑下标 `index` 的处理器上加载为它准备的 GDT 与 TSS（该处理器启动后最先调用）。
pub fn init_cpu(index: usize) -> bool {
    let Some(p) = CPU_GDT.get(index).map(|g| g.load(Ordering::Acquire)) else { return false };
    if p.is_null() {
        return false;
    }
    // SAFETY：p 指向 prepare_cpu 泄漏的 'static GDT，此后只读。
    load(unsafe { &*p }, selectors());
    true
}

/// 段选择子（`init` 之后可用；所有处理器相同）。
pub fn selectors() -> Selectors {
    GDT.get().expect("GDT 未初始化").1
}

/// 设置本处理器从用户态进入内核时使用的栈顶（TSS.rsp0）。
///
/// 调用者（调度器）在关中断临界区内调用；CPU 只在特权级切换时读取它。
pub fn set_kernel_stack(top: u64) {
    let p = CPU_TSS.get(super::smp::cpu_index()).map(|t| t.load(Ordering::Acquire)).unwrap_or(core::ptr::null_mut());
    let p = if p.is_null() { addr_of_mut!(TSS) } else { p };
    // SAFETY：p 是本处理器的 TSS；只有本处理器在关中断下写它，CPU 读取的是同一块内存。
    unsafe { (*p).privilege_stack_table[0] = VirtAddr::new(top) };
}
