//! 内核 panic 处理（全二进制唯一的 `#[panic_handler]`）。
//!
//! 经紧急输出（不会因控制台锁卡死）打印 `[JSR-PANIC] 文件:行号` 后停机。panic 消息本身暂不打印：
//! `PanicInfo::message()` 的形态随 rustc 版本变化，暂不依赖它。

use core::panic::PanicInfo;

use crate::{arch, console};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    match info.location() {
        Some(loc) => console::emergency_print(format_args!("[JSR-PANIC] {}:{}\n", loc.file(), loc.line())),
        None => console::emergency_print(format_args!("[JSR-PANIC] (no location)\n")),
    }
    arch::halt_forever()
}
