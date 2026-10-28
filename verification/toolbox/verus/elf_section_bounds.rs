//! Verus/Z3 规格：ELF 节头表项定位的边界与整数安全（issue #8，ABI 章节查找）。
//! Verus/Z3 model of ELF section-header entry addressing used by `kernel_core::elf::abi_note_bytes`.
//!
//! 与生产实现的对应：`section_extent` 对应 `elf::section_at` 的地址计算
//! （`index * shentsize + shoff`，再加 `shentsize`，与文件长度比较），用 u64 机器整数与显式溢出判断；
//! `table_admits_every_entry` 证明：一旦整表检查（`shoff + shnum * shentsize <= len`）通过，
//! 表内任一下标的表项都在文件内，逐项读取不会越界、也不会因溢出而被误拒。
//! `shentsize`/`shnum`/`index` 在 ELF 中是 16 位字段，这里如实用 u16。
//!
//! 只证明地址算术；字节解码、名字比较与章格式由 Proptest / cargo-fuzz / Kani 覆盖。

use vstd::prelude::*;

verus! {

/// 表项 `[base, end)`；越界或溢出返回 None。
fn section_extent(len: u64, shoff: u64, ent: u16, index: u16) -> (r: Option<(u64, u64)>)
    ensures
        match r {
            Some((b, e)) => b == shoff + (index as int) * (ent as int)
                && e == b + ent as int
                && e <= len,
            None => shoff + (index as int) * (ent as int) + ent as int > len as int,
        },
{
    assert((index as int) * (ent as int) <= 0xffff * 0xffff) by (nonlinear_arith)
        requires index <= 0xffff, ent <= 0xffff, index >= 0, ent >= 0;
    let prod: u64 = (index as u64) * (ent as u64);
    if prod > u64::MAX - shoff {
        return None;
    }
    let base = shoff + prod;
    if (ent as u64) > u64::MAX - base {
        return None;
    }
    let end = base + ent as u64;
    if end > len {
        return None;
    }
    Some((base, end))
}

/// 整表在文件内 ⇒ 表内每个下标的表项都在文件内（逐项检查与整表检查一致）。
proof fn table_admits_every_entry(len: int, shoff: int, ent: int, n: int, index: int)
    requires
        0 <= shoff,
        0 <= ent,
        0 <= index < n,
        shoff + n * ent <= len,
    ensures
        shoff + index * ent + ent <= len,
{
    assert(index * ent + ent <= n * ent) by (nonlinear_arith)
        requires 0 <= index < n, 0 <= ent;
}

/// 生产代码先查整表再逐项读取：组合起来，任一表内下标的 `section_extent` 必然成功。
fn read_entry_after_table_check(len: u64, shoff: u64, ent: u16, n: u16, index: u16) -> (r: Option<(u64, u64)>)
    requires
        index < n,
        shoff + (n as int) * (ent as int) <= len,
    ensures
        r is Some,
{
    proof {
        table_admits_every_entry(len as int, shoff as int, ent as int, n as int, index as int);
    }
    section_extent(len, shoff, ent, index)
}

/// 章节字节 `[off, off + size)`：在文件内 ⇒ 每个字节下标都小于文件长度。
proof fn accepted_note_is_inside_image(len: int, off: int, size: int, k: int)
    requires
        0 <= off,
        0 <= size,
        off + size <= len,
        0 <= k < size,
    ensures
        off + k < len,
{
}

fn main() {}
}
