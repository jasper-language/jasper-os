//! jaso-demo：第一个 `.jaso` 模块（验收用）。
//! The first `.jaso` module, used by the acceptance program.
//!
//! 每个导出都检验装载器的一项职责：
//!
//! | 导出 | 检验什么 |
//! |---|---|
//! | `jaso_init` | 宿主接口表：版本与长度检查后保存；经表输出一行文本 |
//! | `demo_sum` | 代码页可执行、能读调用者的内存 |
//! | `demo_greeting` | 只读数据中的指针表（需要重定位才能正确） |
//! | `demo_counter` | 可写数据段（每个装入实例各有一份） |
//! | `demo_alloc_sum` | 经宿主接口表分配、写入、求和、释放 |
//!
//! 模块不按名字导入任何符号；`panic` 时执行非法指令，由内核终止所在进程（不会悄悄继续）。
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use jaso::HostV0;

/// 装载器传入的宿主接口表（`jaso_init` 之后有效，生命期与模块相同）。
static HOST: AtomicPtr<HostV0> = AtomicPtr::new(core::ptr::null_mut());
/// 调用计数（可写数据段）。
static COUNTER: AtomicU32 = AtomicU32::new(0);
/// 只读的字符串表：每一项都是指针，装入后须经重定位指向本实例的映像。
static GREETINGS: [&str; 3] = ["你好，来自 .jaso 模块", "hello from a .jaso module", "jaso-demo 0.1.0"];

fn host() -> Option<&'static HostV0> {
    // SAFETY：指针只在 jaso_init 中写入一次，指向装载器保证在模块存续期间有效的表。
    unsafe { HOST.load(Ordering::Acquire).as_ref() }
}

fn log(s: &str) {
    if let Some(h) = host() {
        (h.log)(s.as_ptr(), s.len());
    }
}

/// 初始化：检查宿主接口表的版本与长度，保存它，并经它输出一行文本。返回 0 表示成功。
#[no_mangle]
pub extern "C" fn jaso_init(host: *const HostV0) -> i32 {
    // SAFETY：装载器传入一张有效的表（或空指针）。
    let Some(h) = (unsafe { host.as_ref() }) else { return 1 };
    if h.version != 0 || (h.size as usize) < core::mem::size_of::<HostV0>() {
        return 2;
    }
    HOST.store(host as *mut HostV0, Ordering::Release);
    log("jaso-demo: init ok");
    0
}

/// 对 `[ptr, ptr + len)` 的字节求和。
///
/// # Safety
/// `ptr` 必须指向调用者进程中至少 `len` 字节的可读内存。
#[no_mangle]
pub unsafe extern "C" fn demo_sum(ptr: *const u8, len: usize) -> u64 {
    core::slice::from_raw_parts(ptr, len).iter().map(|&b| b as u64).sum()
}

/// 把第 `i` 条问候语复制到 `out`（至多 `cap` 字节），返回问候语的完整长度。
///
/// # Safety
/// `out` 必须指向至少 `cap` 字节的可写内存。
#[no_mangle]
pub unsafe extern "C" fn demo_greeting(i: usize, out: *mut u8, cap: usize) -> usize {
    let s = GREETINGS[i % GREETINGS.len()];
    let n = s.len().min(cap);
    core::ptr::copy_nonoverlapping(s.as_ptr(), out, n);
    s.len()
}

/// 计数加一并返回新值。
#[no_mangle]
pub extern "C" fn demo_counter() -> u64 {
    (COUNTER.fetch_add(1, Ordering::Relaxed) + 1) as u64
}

/// 经宿主分配 `n` 字节，按 `i % 251` 填充后求和并释放；宿主不可用或分配失败返回 `u64::MAX`。
#[no_mangle]
pub extern "C" fn demo_alloc_sum(n: usize) -> u64 {
    let Some(h) = host() else { return u64::MAX };
    let p = (h.alloc)(n, 8);
    if p.is_null() {
        return u64::MAX;
    }
    // SAFETY：p 指向宿主刚分配的 n 字节，只在此处使用，随后以相同参数释放。
    let sum = unsafe {
        let s = core::slice::from_raw_parts_mut(p, n);
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        s.iter().map(|&b| b as u64).sum()
    };
    (h.dealloc)(p, n, 8);
    sum
}

/// 模块内的 panic：执行非法指令，由内核终止所在进程。
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    log("jaso-demo: panic");
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
