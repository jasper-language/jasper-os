//! `.jaso` 模块的公共支撑。
//! Shared support for `.jaso` modules.
//!
//! 依赖本 crate 的模块自动获得：
//! * `jaso_init` 导出：检查宿主接口表的版本与长度并保存（清单须声明 `core.host = jaso.host.v0`）
//! * 全局分配器：把 `alloc` 的分配请求转给宿主接口表；在 `jaso_init` 之前或宿主拒绝时返回空指针（由 `alloc` 报告分配失败）
//! * panic 处理：经宿主输出一行后执行非法指令，由内核终止所在进程
//! * [`log`]：经宿主输出一行文本
//!
//! 模块的导出函数一律是 `#[no_mangle] extern "C"`；跨边界只传整数与裸指针，不传 Rust 布局的类型。
#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicPtr, Ordering};

pub use jaso::HostV0;

static HOST: AtomicPtr<HostV0> = AtomicPtr::new(core::ptr::null_mut());

/// 装载器传入的宿主接口表（`jaso_init` 之前为 `None`）。
pub fn host() -> Option<&'static HostV0> {
    // SAFETY：指针只在 jaso_init 中写入一次，指向装载器保证在模块存续期间有效的表。
    unsafe { HOST.load(Ordering::Acquire).as_ref() }
}

/// 经宿主输出一行文本（宿主不可用时什么也不做）。
pub fn log(s: &str) {
    if let Some(h) = host() {
        (h.log)(s.as_ptr(), s.len());
    }
}

/// 模块初始化：检查宿主接口表并保存。返回 0 表示成功。
#[no_mangle]
pub extern "C" fn jaso_init(host: *const HostV0) -> i32 {
    // SAFETY：装载器传入一张有效的表（或空指针）。
    let Some(h) = (unsafe { host.as_ref() }) else { return 1 };
    if h.version != 0 || (h.size as usize) < core::mem::size_of::<HostV0>() {
        return 2;
    }
    HOST.store(host as *mut HostV0, Ordering::Release);
    0
}

/// 经宿主接口表分配内存的全局分配器。
pub struct HostAlloc;

// SAFETY：分配与释放都转给宿主；宿主按约定返回满足布局的内存或空指针，并以相同参数回收。
unsafe impl GlobalAlloc for HostAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        match host() {
            Some(h) => (h.alloc)(l.size(), l.align()),
            None => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if let Some(h) = host() {
            (h.dealloc)(p, l.size(), l.align());
        }
    }
}

#[global_allocator]
static ALLOC: HostAlloc = HostAlloc;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    log("jaso module: panic");
    // SAFETY：非法指令只会触发异常，不访问任何内存。
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("ud2", options(noreturn));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("udf #0", options(noreturn));
        #[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
        core::arch::asm!("unimp", options(noreturn));
    }
}
