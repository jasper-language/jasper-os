//! 内核 panic 处理（全二进制唯一的 `#[panic_handler]`）。
//!
//! 经紧急输出（不会因控制台锁卡死）打印 `[JSR-PANIC] 文件:行号` 后停机。panic 消息本身暂不打印：
//! `PanicInfo::message()` 的形态随 rustc 版本变化，暂不依赖它。

use core::panic::PanicInfo;

use crate::{arch, console};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    #[cfg(feature = "lifecycle-diagnostic-sources")]
    let recorded = crate::diagnostic_sources::record_kernel_exception();
    #[cfg(feature = "lifecycle-diagnostic-sources")]
    console::emergency_print(format_args!(
        "[JSR-DIAG-SOURCE] kind=kernel_exception recorded={}\n",
        recorded
    ));
    match info.location() {
        Some(loc) => {
            console::emergency_print(format_args!("[JSR-PANIC] {}:{}\n", loc.file(), loc.line()))
        }
        None => console::emergency_print(format_args!("[JSR-PANIC] (no location)\n")),
    }
    arch::halt_forever()
}
