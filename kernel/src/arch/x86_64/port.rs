//! x86 端口 I/O 原语（`in`/`out` 指令）。只供 `arch/x86_64/` 内部使用。

/// 向端口写一个字节。
///
/// # Safety
/// 写错端口会改变任意设备状态；调用者必须知道目标端口的语义。
#[inline(always)]
pub unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

/// 从端口读一个字节。
///
/// # Safety
/// 读某些端口有副作用（如清除状态位）。
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags));
    v
}

/// 向端口写一个 32 位值。
///
/// # Safety
/// 同 [`outb`]。
#[inline(always)]
pub unsafe fn outl(port: u16, val: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack, preserves_flags));
}

/// 从端口读一个 32 位值。
///
/// # Safety
/// 读某些端口有副作用（如读取后清除状态、触发设备动作）。
#[inline(always)]
pub unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags));
    v
}
