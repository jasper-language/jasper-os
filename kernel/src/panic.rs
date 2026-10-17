//! 内核 panic 处理（全二进制唯一的 `#[panic_handler]`）。
//!
//! 打印 `[JSR-PANIC] 文件:行号` 后停机。panic 消息本身暂不打印：
//! `PanicInfo::message()` 的形态随 rustc 版本变化，暂不依赖它。

use core::panic::PanicInfo;

use crate::{arch, console};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    match info.location() {
        Some(loc) => console::_print(format_args!("[JSR-PANIC] {}:{}\n", loc.file(), loc.line())),
        None => console::write_str("[JSR-PANIC] (no location)\n"),
    }
    arch::halt_forever()
}
