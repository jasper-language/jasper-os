// `.jaso` format 1 读取器的偏移 / 长度检查式运算的 Verus 伴随证明。
// 与生产代码 `jaso::range_within`、`parse_extension` 的内容起点计算、`ImageRef::check_segment` 的页末端计算
// 逐式对应（同样的 u32 / usize 运算与检查顺序），证明它们与数学定义一致且不回绕。
use vstd::prelude::*;

verus! {

// range_within：在 u64 上求和（两个 u32 之和不会溢出 u64），对任意 total 精确
fn range_within(off: u32, len: u32, total: u64) -> (r: bool)
    ensures r == (off as int + len as int <= total as int)
{
    (off as u64) + (len as u64) <= total
}

// 扩展段内容起点：(8 + name_len) 向上取到 8 的倍数，且不超过段长
fn content_at(name_len: u16, section_len: u32) -> (r: Option<u32>)
    requires 1 <= name_len <= 64
    ensures
        match r {
            Some(at) => at % 8 == 0 && 8 + name_len as int <= at as int && (at as int) < 8 + name_len as int + 8 && at <= section_len,
            None => (8 + name_len as int + 7) / 8 * 8 > section_len,
        }
{
    let raw: u32 = 8 + name_len as u32;
    let at: u32 = (raw + 7) / 8 * 8;
    if at <= section_len { Some(at) } else { None }
}

// 映像段的页末端：vaddr + roundup(mem_size, PAGE) ≤ image_size，全程检查式运算
fn segment_fits(vaddr: u32, mem_size: u32, image_size: u32) -> (r: bool)
    requires mem_size > 0
    ensures r == (vaddr as int + (mem_size as int + 4095) / 4096 * 4096 <= image_size as int)
{
    let pages: u32 = mem_size / 4096 + if mem_size % 4096 == 0 { 0 } else { 1 };
    match pages.checked_mul(4096) {
        Some(m) => match vaddr.checked_add(m) {
            Some(end) => end <= image_size,
            None => false,
        },
        None => false,
    }
}

// 平台段与镜像索引的定长：size == 8 + rec × count，count 有上限，乘法不回绕
fn table_size_ok(size: u32, count: u32, rec: u32, max: u32) -> (r: bool)
    requires 1 <= rec <= 64, max <= 16
    ensures r == (1 <= count <= max && size as int == 8 + rec as int * count as int)
{
    if count == 0 || count > max {
        false
    } else {
        assert(rec * count <= 64 * 16) by (nonlinear_arith) requires rec <= 64, count <= 16;
        size == 8 + rec * count
    }
}

fn main() {}
}
