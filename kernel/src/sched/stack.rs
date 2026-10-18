//! 内核栈池：为每个任务槽位提供一块 16 字节对齐的内核栈。
//!
//! 职责边界：只管「栈内存在哪」。新任务首次切入帧的形状属于 ISA 细节，
//! 由 `arch::init_task_frame` 负责（x86_64 见 `arch/x86_64/context.rs`）。
//!
//! # 两类栈（为什么这样分）
//! * **静态栈**（前 [`STATIC_STACKS`] 个槽位）：放在 `.bss`，由引导器清零并映射。
//!   内核堆初始化之前的调度演练（协作式 / 抢占式 / 机制演练）只能用它们。
//! * **堆栈**（其余槽位）：堆就绪后由 [`StackPool::reserve`] 一次性从内核堆分配，之后**只复用、不释放**。
//!   一次性分配而不是按需分配：各演练以「空闲页帧数回到基线」判定没有泄漏，
//!   若某次创建任务时才让堆增长，增长出来的页帧不会再还给页帧分配器，基线就会漂移。
//!   代价是启动时固定占用 `(槽位数 - 静态栈数) × STACK_SIZE` 字节，换来任务数不再受静态栈数量限制。

use core::alloc::Layout;
use core::ptr::{addr_of_mut, null_mut};

use crate::arch::TaskContext;

/// 单个任务内核栈大小。64 KiB：系统调用路径上会临时构造较大的内核对象（例如异步环约 12 KiB），
/// 在移入堆之前可能先位于栈上。
/// Per-task kernel stack size (large kernel objects may be built on the stack before moving to the heap).
pub const STACK_SIZE: usize = 64 * 1024;

/// 静态栈个数（含槽位 0：引导线程不使用池里的栈，但槽位编号与栈一一对应，留空更简单）。
pub const STATIC_STACKS: usize = 4;

/// 16 字节对齐的栈内存块（SysV ABI 要求）。
#[repr(C, align(16))]
pub struct Stack([u8; STACK_SIZE]);

impl Stack {
    /// 全零栈（供静态初始化）。
    pub const fn zeroed() -> Self {
        Stack([0; STACK_SIZE])
    }
}

/// 堆栈预留失败（内核堆不足）。已经分到的栈保留，可用槽位相应减少。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReserveError {
    /// 失败前已可用的槽位总数。
    pub available: usize,
}

/// 槽位数为 `N` 的栈池：前 [`STATIC_STACKS`] 个是静态栈，其余由 [`StackPool::reserve`] 从堆上分配。
pub struct StackPool<const N: usize> {
    statics: [Stack; STATIC_STACKS],
    /// 槽位 → 堆栈起点（空指针 = 尚未分配；静态槽位恒为空指针）。
    heap: [*mut Stack; N],
}

impl<const N: usize> StackPool<N> {
    /// 构造栈池：只有静态栈可用（`const`，可放进 `static`）。
    pub const fn new() -> Self {
        StackPool { statics: [const { Stack::zeroed() }; STATIC_STACKS], heap: [null_mut(); N] }
    }

    /// 堆就绪后为其余槽位分配栈（幂等：已分配的槽位跳过）。返回可用槽位总数。
    ///
    /// 用 `alloc_zeroed` 直接在堆上得到清零的栈：`Box::new(Stack::zeroed())` 会先在当前栈上
    /// 构造一个 64 KiB 的临时值，而当前栈本身也只有 64 KiB。
    pub fn reserve(&mut self) -> Result<usize, ReserveError> {
        let layout = Layout::new::<Stack>();
        for slot in STATIC_STACKS..N {
            if !self.heap[slot].is_null() {
                continue;
            }
            // SAFETY：layout 尺寸非零；返回的内存只由本池持有，永不释放。
            let p = unsafe { alloc::alloc::alloc_zeroed(layout) } as *mut Stack;
            if p.is_null() {
                return Err(ReserveError { available: self.available() });
            }
            self.heap[slot] = p;
        }
        Ok(self.available())
    }

    /// `slot` 是否有栈可用。
    pub fn has_stack(&self, slot: usize) -> bool {
        slot < STATIC_STACKS.min(N) || (slot < N && !self.heap[slot].is_null())
    }

    /// 有栈可用的槽位总数。
    pub fn available(&self) -> usize {
        (0..N).filter(|&s| self.has_stack(s)).count()
    }

    /// `slot` 的栈底（最低地址）。调用者保证 [`StackPool::has_stack`]。
    fn base(&mut self, slot: usize) -> *mut u8 {
        if slot < STATIC_STACKS {
            addr_of_mut!(self.statics[slot]) as *mut u8
        } else {
            self.heap[slot] as *mut u8
        }
    }

    /// `slot` 的栈顶地址（中断从用户态进入内核时，CPU 切到这里；见 `arch::set_kernel_stack`）。
    pub fn top(&mut self, slot: usize) -> u64 {
        self.base(slot) as u64 + STACK_SIZE as u64
    }

    /// 在 `slot` 的栈顶伪造首次切入帧，返回该任务的初始上下文。
    ///
    /// 帧的具体形状（压哪些寄存器、对齐方式）由 `arch::init_task_frame` 决定——
    /// 栈池只负责「栈在哪」，与 ISA 无关。
    ///
    /// # Safety
    /// 调用者保证该槽位有栈（[`StackPool::has_stack`]），且此刻没有任务在这块栈上运行。
    pub unsafe fn prepare_initial_frame(&mut self, slot: usize, entry: extern "C" fn() -> !) -> TaskContext {
        let base = self.base(slot);
        crate::arch::init_task_frame(base.add(STACK_SIZE), entry)
    }
}
