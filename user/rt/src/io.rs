//! 控制台输出：`print!` / `println!`。
//! Console output macros.
//!
//! 内核控制台按行输出：每次 `system.console.write` 成为一行。因此格式化结果先攒在栈上的定长缓冲里，
//! 遇到换行符（换行符本身不发送）、缓冲满或输出结束时才写出一次。不用堆，
//! 所以 panic 处理（堆可能已不可用）也能输出。

use core::fmt;

use crate::error::{check, Result};
use crate::{ids, sys};

/// 单次 `system.console.write` 的上限（与内核一致）。
const WRITE_MAX: usize = 4096;

/// 把一段 UTF-8 文本写到控制台（超过单次上限时分段，分段点落在字符边界上）。
pub fn write_str(mut s: &str) -> Result<()> {
    while !s.is_empty() {
        let mut n = s.len().min(WRITE_MAX);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        // SAFETY：指针与长度来自一个有效的 &str。
        check(unsafe { sys::call3(ids::SYSTEM_CONSOLE_WRITE, s.as_ptr() as u64, n as u64, 0) })?;
        s = &s[n..];
    }
    Ok(())
}

/// 栈上的输出缓冲。
pub struct Console {
    buf: [u8; 512],
    len: usize,
}

impl Console {
    /// 空缓冲。
    pub const fn new() -> Self {
        Console { buf: [0; 512], len: 0 }
    }

    /// 写出缓冲中的内容（空缓冲不写）。
    pub fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        if let Ok(s) = core::str::from_utf8(&self.buf[..self.len]) {
            let _ = write_str(s);
        }
        self.len = 0;
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            if ch == '\n' {
                self.flush();
                continue;
            }
            let mut tmp = [0u8; 4];
            let b = ch.encode_utf8(&mut tmp).as_bytes();
            if self.len + b.len() > self.buf.len() {
                self.flush();
            }
            self.buf[self.len..self.len + b.len()].copy_from_slice(b);
            self.len += b.len();
        }
        Ok(())
    }
}

/// `print!` 的实现。
pub fn print_args(args: fmt::Arguments<'_>) {
    let mut c = Console::new();
    let _ = fmt::write(&mut c, args);
    c.flush();
}

/// 格式化输出到控制台。
#[macro_export]
macro_rules! print {
    ($($t:tt)*) => { $crate::io::print_args(format_args!($($t)*)) };
}

/// 格式化输出到控制台并换行。
#[macro_export]
macro_rules! println {
    () => { $crate::io::print_args(format_args!("\n")) };
    ($($t:tt)*) => { $crate::io::print_args(format_args!("{}\n", format_args!($($t)*))) };
}
