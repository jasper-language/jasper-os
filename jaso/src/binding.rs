//! `jasper.import` 版本 1（SPEC §9.4）：类型化导出声明的语法与「绑定 ⇔ 清单」一致性（L1 第 6a 步）。
//! The `jasper.import` version 1 binding: syntax and its item-by-item agreement with the manifest.
//!
//! 结构读取不看扩展段内容（SPEC §9.3）；本模块只在 L1 装载时运行，错误码一律 `extension.binding`。
//! 类型名只做语法检查，含义归 Jasper 层；裸指针（`*`、`&`）不在语法内，因此无法写进绑定。

use crate::code::ErrorCode;
use crate::manifest::{symbol_ok, Manifest};
use crate::{Jaso, EXT_JASPER_IMPORT, INIT_SYMBOL, START_SYMBOL, STOP_SYMBOL};

/// 绑定内容的字节数上限。
pub const MAX_BINDING_BYTES: usize = 64 * 1024;
/// 绑定的有效行数上限。
pub const MAX_BINDING_LINES: usize = 1024;
/// 类型参数的嵌套深度上限。
pub const MAX_TYPE_DEPTH: u32 = 8;

/// 绑定错误（行号从 1 起）；稳定错误码都是 `extension.binding`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// 不是 UTF-8。
    NotUtf8,
    /// 超出字节数或行数上限。
    TooLong,
    /// 某行不符合语法。
    BadLine(u32),
    /// 重复的 `package`，或重复声明同一个类型 / 能力 / 函数。
    Duplicate(u32),
    /// `fn` 声明的函数不在 `core.exports` 里（或是生命周期导出）。
    UndeclaredFunction(u32),
    /// `core.exports` 中的函数没有绑定声明。
    MissingFunction,
    /// `cap` 声明的能力超出 `core.requires`。
    Capability(u32),
}

impl BindingError {
    /// 稳定错误码。
    pub const fn code(self) -> ErrorCode {
        ErrorCode::ExtensionBinding
    }
}

/// 是否生命周期导出（装载器调用，不属于绑定）。
pub fn is_lifecycle_symbol(name: &str) -> bool {
    name == INIT_SYMBOL || name == START_SYMBOL || name == STOP_SYMBOL
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl Cursor<'_> {
    fn spaces(&mut self) {
        while self.b.get(self.i) == Some(&b' ') {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        let hit = self.b.get(self.i) == Some(&c);
        if hit {
            self.i += 1;
        }
        hit
    }

    fn done(&self) -> bool {
        self.i == self.b.len()
    }

    /// `[A-Za-z_][A-Za-z0-9_]*`
    fn ident(&mut self) -> bool {
        match self.b.get(self.i) {
            Some(c) if c.is_ascii_alphabetic() || *c == b'_' => self.i += 1,
            _ => return false,
        }
        while self.b.get(self.i).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
            self.i += 1;
        }
        true
    }

    /// `ident ('.' ident)*`
    fn dotted(&mut self) -> bool {
        if !self.ident() {
            return false;
        }
        while self.eat(b'.') {
            if !self.ident() {
                return false;
            }
        }
        true
    }

    /// `[own |borrow ]dotted['<' type (',' type)* '>']['?']`
    fn ty(&mut self, depth: u32) -> bool {
        if depth > MAX_TYPE_DEPTH {
            return false;
        }
        self.spaces();
        for keyword in [&b"own "[..], &b"borrow "[..]] {
            if self.b[self.i..].starts_with(keyword) {
                self.i += keyword.len();
                self.spaces();
                break;
            }
        }
        if !self.dotted() {
            return false;
        }
        if self.eat(b'<') {
            loop {
                if !self.ty(depth + 1) {
                    return false;
                }
                self.spaces();
                if self.eat(b'>') {
                    break;
                }
                if !self.eat(b',') {
                    return false;
                }
            }
        }
        self.eat(b'?');
        true
    }
}

/// `(params): type`（从 `(` 开始，到行尾结束）。
fn signature_ok(s: &[u8]) -> bool {
    let mut c = Cursor { b: s, i: 0 };
    if !c.eat(b'(') {
        return false;
    }
    c.spaces();
    if !c.eat(b')') {
        loop {
            c.spaces();
            if !c.ident() {
                return false;
            }
            c.spaces();
            if !c.eat(b':') || !c.ty(0) {
                return false;
            }
            c.spaces();
            if c.eat(b')') {
                break;
            }
            if !c.eat(b',') {
                return false;
            }
        }
    }
    c.spaces();
    c.eat(b':') && c.ty(0) && {
        c.spaces();
        c.done()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Item<'a> {
    Package,
    Type(&'a str),
    Cap(&'a str),
    Fn(&'a str),
}

/// 解析一个有效行（已去掉两端空白、不是空行或注释）。
fn item(l: &str) -> Option<Item<'_>> {
    let (word, rest) = l.split_once(' ')?;
    let rest = rest.trim_start_matches(' ');
    match word {
        "package" => {
            let mut c = Cursor { b: rest.as_bytes(), i: 0 };
            (c.dotted() && c.done()).then_some(Item::Package)
        }
        "type" => {
            let mut c = Cursor { b: rest.as_bytes(), i: 0 };
            (c.ident() && c.done()).then_some(Item::Type(rest))
        }
        "cap" => (!rest.is_empty() && !rest.contains(' ')).then_some(Item::Cap(rest)),
        "fn" => {
            let open = rest.find('(')?;
            let (name, sig) = rest.split_at(open);
            let name = name.trim_end_matches(' ');
            (symbol_ok(name) && signature_ok(sig.as_bytes())).then_some(Item::Fn(name))
        }
        _ => None,
    }
}

/// 有效行的迭代器：(行号, 去掉两端空白后的文本)。
fn lines(text: &str) -> impl Iterator<Item = (u32, &str)> {
    text.lines().enumerate().filter_map(|(i, l)| {
        let l = l.trim();
        (!l.is_empty() && !l.starts_with('#')).then_some((i as u32 + 1, l))
    })
}

/// 判定绑定内容：语法合法；`fn` 集合 = `core.exports` 去掉生命周期导出（逐项一一对应，不看顺序）；`cap` 集合 ⊆ `core.requires`。
pub fn check(content: &[u8], manifest: &Manifest<'_>) -> Result<(), BindingError> {
    if content.len() > MAX_BINDING_BYTES {
        return Err(BindingError::TooLong);
    }
    let text = core::str::from_utf8(content).map_err(|_| BindingError::NotUtf8)?;
    for (count, (no, l)) in lines(text).enumerate() {
        if count >= MAX_BINDING_LINES {
            return Err(BindingError::TooLong);
        }
        let it = item(l).ok_or(BindingError::BadLine(no))?;
        if lines(text).take(count).any(|(_, p)| item(p) == Some(it)) {
            return Err(BindingError::Duplicate(no));
        }
        match it {
            Item::Cap(c) if !manifest.requires().any(|r| r == c) => return Err(BindingError::Capability(no)),
            Item::Fn(f) if is_lifecycle_symbol(f) || !manifest.exports().any(|e| e == f) => return Err(BindingError::UndeclaredFunction(no)),
            _ => {}
        }
    }
    let bound = |e: &str| lines(text).any(|(_, l)| item(l) == Some(Item::Fn(e)));
    if manifest.exports().any(|e| !is_lifecycle_symbol(e) && !bound(e)) {
        return Err(BindingError::MissingFunction);
    }
    Ok(())
}

/// 文件带 `jasper.import` 时判定它（Hybrid 必带，结构读取已保证；Native / Managed 可带）。
pub fn check_file(f: &Jaso<'_>) -> Result<(), BindingError> {
    match f.extension(EXT_JASPER_IMPORT, 1) {
        Some(e) => check(e.content, &f.manifest),
        None => Ok(()),
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// 任意 4 字节的名字文本：不 panic，游标不越界；接受时首字节是字母或下划线。
    #[kani::proof]
    #[kani::unwind(6)]
    fn dotted_cursor_stays_in_bounds() {
        let b: [u8; 4] = kani::any();
        let mut c = Cursor { b: &b, i: 0 };
        let ok = c.dotted();
        assert!(c.i <= b.len());
        assert!(!ok || b[0].is_ascii_alphabetic() || b[0] == b'_');
    }

    /// 超过嵌套深度上限的类型：直接拒绝，不读取输入（递归因此有界）。
    #[kani::proof]
    #[kani::unwind(3)]
    fn type_depth_cap_is_enforced() {
        let b: [u8; 2] = kani::any();
        let mut c = Cursor { b: &b, i: 0 };
        assert!(!c.ty(MAX_TYPE_DEPTH + 1));
        assert!(c.i == 0);
    }
}
