//! `.jaso` 模块装载器（用户态，Native-only）。
//! User-space loader for native `.jaso` modules.
//!
//! # 装载步骤（任何一步失败都撤销此前的全部改动）
//! 1. **校验文件**：[`jaso::Image::parse`]（结构 + SHA-256 完整性）
//! 2. **检查适用性**：指令集与本程序一致；装载阶段为 `runtime`；调用约定为 `c.v0`
//! 3. **检查能力**：清单里的每项能力都必须在调用者给出的授权 [`Grant::capabilities`] 中——清单是请求，授权由调用者决定
//! 4. **检查宿主接口**：清单要求 `jaso.host.v0` 时，调用者必须提供宿主接口表，模块必须导出 `jaso_init`
//! 5. **装入**：在模块区间取一个槽位，映射整个映像（可写），复制各段，应用重定位
//! 6. **设权限**：映像先整体改为只读，再按段设为只读 / 读写 / 读执行（W^X，由内核强制）
//! 7. **初始化**：调用 `jaso_init(宿主接口表)`，返回非 0 即视为失败
//!
//! # 卸载
//! [`Module`] 离开作用域即取消整个映像的映射并归还槽位。经 [`Module::function`] 取得的函数指针
//! 借用了 `Module`，在安全代码里不可能在卸载之后调用。
//! 尚未实现：卸载前的静默判定（是否还有线程正在模块代码里执行）——v0 由调用者保证。

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, Ordering};

pub use jaso::{HostV0, JasoError};
use jaso::{Arch, Image, Stage, ABI_C_V0, FLAG_W, FLAG_X, HOST_V0, INIT_SYMBOL, PAGE};

use crate::error::Error;
use crate::{mem, sys};

extern "C" fn std_log(ptr: *const u8, len: usize) {
    // SAFETY：模块按约定传入一段有效的文本。
    let b = unsafe { core::slice::from_raw_parts(ptr, len) };
    if let Ok(s) = core::str::from_utf8(b) {
        let _ = crate::io::write_str(s);
    }
}

extern "C" fn std_alloc(size: usize, align: usize) -> *mut u8 {
    match core::alloc::Layout::from_size_align(size.max(1), align) {
        // SAFETY：布局合法且大小非零。
        Ok(l) => unsafe { alloc::alloc::alloc(l) },
        Err(_) => core::ptr::null_mut(),
    }
}

extern "C" fn std_dealloc(ptr: *mut u8, size: usize, align: usize) {
    if let Ok(l) = core::alloc::Layout::from_size_align(size.max(1), align) {
        // SAFETY：模块按约定以分配时的参数归还。
        unsafe { alloc::alloc::dealloc(ptr, l) }
    }
}

/// 运行时提供的标准宿主接口表：输出到控制台（按行），分配走本进程的全局分配器。
pub static STD_HOST: HostV0 =
    HostV0 { version: 0, size: core::mem::size_of::<HostV0>() as u32, log: std_log, alloc: std_alloc, dealloc: std_dealloc };

/// 调用者给模块的授权。
#[derive(Clone, Copy)]
pub struct Grant<'a> {
    /// 授予的能力名（清单 `core.requires` 中的每一项都必须在此）。
    pub capabilities: &'a [&'a str],
    /// 宿主接口表（模块声明需要时必须提供；须比 [`Module`] 活得久，通常是 `static`）。
    pub host: Option<&'static HostV0>,
}

/// 装载失败的原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// 文件未通过格式或完整性校验。
    Format(JasoError),
    /// 指令集与本程序不符。
    WrongArch(Arch),
    /// 装载阶段不是 `runtime`（启动期 / 构建期模块不能由运行时装载器装入）。
    WrongStage(Stage),
    /// 调用约定不受支持。
    UnsupportedAbi(String),
    /// 清单要求的能力没有被授予。
    MissingCapability(String),
    /// 宿主接口表版本不受支持。
    UnsupportedHost(String),
    /// 模块需要宿主接口表，但调用者没有提供。
    HostRequired,
    /// 模块需要宿主接口表，但没有导出 `jaso_init`。
    MissingInit,
    /// `jaso_init` 返回了非 0。
    InitFailed(i32),
    /// 模块槽位已用尽。
    NoSlot,
    /// 映射或改权限失败。
    Memory(Error),
}

/// 已占用的模块槽位（位图）。
static SLOTS: AtomicU32 = AtomicU32::new(0);

fn take_slot() -> Option<u32> {
    let mut cur = SLOTS.load(Ordering::Relaxed);
    loop {
        let free = (!cur).trailing_zeros();
        if free >= sys::MODULE_SLOTS {
            return None;
        }
        match SLOTS.compare_exchange_weak(cur, cur | 1 << free, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return Some(free),
            Err(now) => cur = now,
        }
    }
}

fn put_slot(slot: u32) {
    SLOTS.fetch_and(!(1u32 << slot), Ordering::AcqRel);
}

/// 单次映射 / 改权限的页数上限（与内核一致）。
const CHUNK: u64 = 1024;

/// 按不超过 [`CHUNK`] 页一次，对 `[va, va + pages 页)` 执行 `f`；中途失败返回错误（已完成的部分由调用者整体撤销）。
fn chunked(va: u64, pages: u64, mut f: impl FnMut(u64, u64) -> crate::Result<()>) -> crate::Result<()> {
    let mut done = 0;
    while done < pages {
        let n = (pages - done).min(CHUNK);
        f(va + done * sys::PAGE, n)?;
        done += n;
    }
    Ok(())
}

/// 一个已装入的模块。离开作用域即卸载。
pub struct Module {
    base: u64,
    pages: u64,
    slot: u32,
    name: String,
    version: (u32, u32, u32),
    exports: Vec<(String, u64)>,
}

/// 借用模块的函数指针：模块卸载之前一直有效。
pub struct Function<'m, F> {
    f: F,
    _module: PhantomData<&'m Module>,
}

impl<F: Copy> Function<'_, F> {
    /// 取出函数指针（调用它须遵守模块对该函数的约定）。
    pub fn get(&self) -> F {
        self.f
    }
}

impl Module {
    /// 校验并装载一个 `.jaso` 文件（见模块文档的步骤）。
    pub fn load(bytes: &[u8], grant: Grant<'_>) -> Result<Module, LoadError> {
        let img = Image::parse(bytes).map_err(LoadError::Format)?;
        if Some(img.arch) != Arch::current() {
            return Err(LoadError::WrongArch(img.arch));
        }
        if img.stage != Stage::Runtime {
            return Err(LoadError::WrongStage(img.stage));
        }
        let m = img.manifest;
        if m.abi != ABI_C_V0 {
            return Err(LoadError::UnsupportedAbi(m.abi.to_string()));
        }
        if let Some(cap) = m.requires().find(|c| !grant.capabilities.contains(c)) {
            return Err(LoadError::MissingCapability(cap.to_string()));
        }
        let init = match m.host {
            None => None,
            Some(h) if h != HOST_V0 => return Err(LoadError::UnsupportedHost(h.to_string())),
            Some(_) => {
                let host = grant.host.ok_or(LoadError::HostRequired)?;
                let e = img.export(INIT_SYMBOL).ok_or(LoadError::MissingInit)?;
                Some((host, e.value))
            }
        };

        let slot = take_slot().ok_or(LoadError::NoSlot)?;
        let base = sys::MODULES_BASE + slot as u64 * sys::MODULE_STRIDE;
        let pages = (img.image_size / PAGE) as u64;
        let mut module = Module {
            base,
            pages: 0,
            slot,
            name: m.name.to_string(),
            version: m.version,
            exports: img.exports().map(|e| (e.name.to_string(), base + e.value as u64)).collect(),
        };
        // 映射整个映像；中途失败时 `module` 被丢弃，Drop 只取消已映射的部分（pages 逐块累加）
        chunked(base, pages, |va, n| {
            mem::map(va, n, mem::WRITE)?;
            module.pages += n;
            Ok(())
        })
        .map_err(LoadError::Memory)?;
        // 复制各段（映射得到的页已清零，`mem_size` 超出 `data` 的部分无需处理）
        for s in img.segments() {
            // SAFETY：[base + vaddr, + data.len()) 在刚映射的可写映像内（解析器已证明段在映像大小之内）。
            unsafe { core::ptr::copy_nonoverlapping(s.data.as_ptr(), (base + s.vaddr as u64) as *mut u8, s.data.len()) };
        }
        // 重定位：在 offset 处写入 base + addend，宽度按种类（解析器已证明种类与指令集一致、按宽度对齐、
        // 在映像内、不在可执行段；32 位指令集上 base + addend 落在映像内，必然可用 4 字节表示）
        for r in img.relocs() {
            let at = base + r.offset as u64;
            let value = base + r.addend;
            if r.kind == jaso::RELOC_RELATIVE32 {
                // SAFETY：同上；写入位置 4 字节对齐。
                unsafe { (at as usize as *mut u32).write(value as u32) };
            } else {
                // SAFETY：同上；写入位置 8 字节对齐。
                unsafe { (at as usize as *mut u64).write(value) };
            }
        }
        // 设权限：整体只读，再按段设置
        chunked(base, pages, |va, n| mem::protect(va, n, 0)).map_err(LoadError::Memory)?;
        for s in img.segments() {
            let flags = if s.flags & FLAG_X != 0 {
                mem::EXEC
            } else if s.flags & FLAG_W != 0 {
                mem::WRITE
            } else {
                0
            };
            let (start, end) = s.page_span();
            chunked(base + start as u64, ((end - start) / PAGE) as u64, |va, n| mem::protect(va, n, flags)).map_err(LoadError::Memory)?;
        }
        if let Some((host, value)) = init {
            // SAFETY：value 是解析器证明落在可执行段内的导出；签名由 v0 约定固定为 extern "C" fn(*const HostV0) -> i32。
            let f: extern "C" fn(*const HostV0) -> i32 = unsafe { core::mem::transmute((base + value as u64) as usize) };
            let rc = f(host);
            if rc != 0 {
                return Err(LoadError::InitFailed(rc));
            }
        }
        Ok(module)
    }

    /// 模块名。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 模块版本。
    pub fn version(&self) -> (u32, u32, u32) {
        self.version
    }

    /// 装入基址。
    pub fn base(&self) -> u64 {
        self.base
    }

    /// 映像占用的页数。
    pub fn pages(&self) -> u64 {
        self.pages
    }

    /// 导出符号的地址（找不到为 `None`）。
    pub fn symbol(&self, name: &str) -> Option<u64> {
        self.exports.iter().find(|(n, _)| n == name).map(|(_, a)| *a)
    }

    /// 以函数指针类型 `F` 取出导出函数。
    ///
    /// # Safety
    /// `F` 必须是与模块中该函数真实签名一致的 `extern "C" fn` 指针类型。
    pub unsafe fn function<F: Copy>(&self, name: &str) -> Option<Function<'_, F>> {
        if core::mem::size_of::<F>() != core::mem::size_of::<usize>() {
            return None;
        }
        let a = self.symbol(name)? as usize;
        Some(Function { f: core::mem::transmute_copy(&a), _module: PhantomData })
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        let _ = chunked(self.base, self.pages, |va, n| mem::unmap(va, n));
        put_slot(self.slot);
    }
}
