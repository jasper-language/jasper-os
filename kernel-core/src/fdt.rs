//! 扁平设备树（FDT / DTB）的只读解析：引导适配层从固件交来的二进制设备树里取出内存图与设备地址。
//! Read-only flattened device tree parser: memory map and device registers for the boot adapter.
//!
//! # 职责与边界
//! * 只解析，不分配：所有结果都是对原始字节的借用或按值返回的数字，`no_std`、无堆可用。
//! * 设备树来自固件，是**不可信输入**：每次读取都做边界检查，结构错误返回带规范名的错误，绝不越界或死循环。
//! * 只覆盖内核启动需要的子集：头部校验、内存保留块、节点遍历（含 `#address-cells` / `#size-cells` 继承）、
//!   属性查找、`compatible` 匹配、`reg` 解码、处理器节点枚举。不做路径解析、phandle 跟踪或覆盖层（overlay）。
//!
//! # 为什么放在 kernel-core
//! 格式本身与指令集无关（AArch64 与 RISC-V 的 QEMU `virt` 都用它），放在这里可以在宿主上用构造的 DTB 测试。

use crate::smp::Topology;

/// 设备树头部的魔数（大端）。
pub const MAGIC: u32 = 0xd00d_feed;
/// 支持的最低格式版本（`last_comp_version` 必须不大于它才可读）。
const COMPAT_VERSION: u32 = 16;
/// 头部长度（字节）。
const HEADER_LEN: usize = 40;
/// 节点嵌套深度上限：超过即视为结构错误（防御恶意或损坏的输入）。
pub const MAX_DEPTH: usize = 16;

const TOKEN_BEGIN_NODE: u32 = 1;
const TOKEN_END_NODE: u32 = 2;
const TOKEN_PROP: u32 = 3;
const TOKEN_NOP: u32 = 4;
const TOKEN_END: u32 = 9;

/// 设备树解析错误。
/// Device tree parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdtError {
    /// 魔数不符：给出的地址上不是设备树。
    BadMagic,
    /// 头部声明的长度或偏移超出给定字节范围。
    Truncated,
    /// 格式版本不受支持。
    BadVersion,
    /// 结构块内容非法（未知记号、名字未结束、嵌套过深或不平衡）。
    BadStructure,
}

impl FdtError {
    /// 规范错误名。
    /// Canonical error name.
    pub const fn name(self) -> &'static str {
        match self {
            FdtError::BadMagic => "system.boot.error.fdt_bad_magic",
            FdtError::Truncated => "system.boot.error.fdt_truncated",
            FdtError::BadVersion => "system.boot.error.fdt_bad_version",
            FdtError::BadStructure => "system.boot.error.fdt_bad_structure",
        }
    }
}

/// 读大端 u32（越界返回 `None`）。
fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// 读大端 u64（越界返回 `None`）。
fn be64(b: &[u8], off: usize) -> Option<u64> {
    Some((u64::from(be32(b, off)?) << 32) | u64::from(be32(b, off + 4)?))
}

/// `b[off..off+len]`，任何溢出或越界都返回 `None`（32 位目标上同样安全）。
fn slice_at(b: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    b.get(off..off.checked_add(len)?)
}

/// 向上取整到 4 字节。
fn align4(x: usize) -> Option<usize> {
    Some(x.checked_add(3)? & !3)
}

/// 从设备树起始的前 8 个字节读出总长度；魔数不符返回 `None`。
/// 调用者据此构造覆盖整棵树的字节切片，再交给 [`Fdt::parse`]。
/// Total size from the first 8 header bytes, or `None` if the magic is wrong.
pub fn total_size(first8: &[u8; 8]) -> Option<usize> {
    if be32(first8, 0)? != MAGIC {
        return None;
    }
    Some(be32(first8, 4)? as usize)
}

/// 一棵已校验头部的设备树。
/// A device tree whose header has been validated.
#[derive(Clone, Copy)]
pub struct Fdt<'a> {
    blob: &'a [u8],
    structs: &'a [u8],
    strings: &'a [u8],
    rsvmap_off: usize,
}

/// 设备树中的一个节点（借用原始字节）。
/// One node of the tree, borrowing the blob.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    /// 节点名（含 `@单元地址`；根节点为空串）。
    pub name: &'a str,
    /// 嵌套深度（根节点为 0）。
    pub depth: usize,
    /// 父节点的 `#address-cells`（解码本节点 `reg` 用）。
    pub address_cells: u32,
    /// 父节点的 `#size-cells`（解码本节点 `reg` 用）。
    pub size_cells: u32,
    props: &'a [u8],
    strings: &'a [u8],
}

impl<'a> Fdt<'a> {
    /// 校验头部并建立视图。`blob` 必须至少覆盖头部声明的总长度。
    /// Validate the header and create a view; `blob` must cover the declared total size.
    pub fn parse(blob: &'a [u8]) -> Result<Self, FdtError> {
        if blob.len() < HEADER_LEN {
            return Err(FdtError::Truncated);
        }
        let h = |i: usize| be32(blob, i * 4).ok_or(FdtError::Truncated);
        if h(0)? != MAGIC {
            return Err(FdtError::BadMagic);
        }
        let total = h(1)? as usize;
        if total > blob.len() || total < HEADER_LEN {
            return Err(FdtError::Truncated);
        }
        if h(6)? > COMPAT_VERSION || h(5)? < COMPAT_VERSION {
            return Err(FdtError::BadVersion);
        }
        let blob = &blob[..total];
        let range = |off: u32, len: u32| -> Result<&'a [u8], FdtError> {
            let (off, len) = (off as usize, len as usize);
            let end = off.checked_add(len).ok_or(FdtError::Truncated)?;
            blob.get(off..end).ok_or(FdtError::Truncated)
        };
        let structs = range(h(2)?, h(9)?)?;
        let strings = range(h(3)?, h(8)?)?;
        let rsvmap_off = h(4)? as usize;
        if rsvmap_off >= total {
            return Err(FdtError::Truncated);
        }
        Ok(Fdt { blob, structs, strings, rsvmap_off })
    }

    /// 整棵树的字节长度（即固件占用、内核必须保留的区间长度）。
    /// Size of the whole blob in bytes.
    pub fn size(&self) -> usize {
        self.blob.len()
    }

    /// 遍历内存保留块中的 `(起始物理地址, 长度)`；遇到 `(0, 0)` 结束，越界即停止。
    /// Iterate the memory reservation block.
    pub fn for_each_reserved(&self, mut f: impl FnMut(u64, u64)) {
        let mut off = self.rsvmap_off;
        while let (Some(addr), Some(size)) = (be64(self.blob, off), be64(self.blob, off + 8)) {
            if addr == 0 && size == 0 {
                break;
            }
            f(addr, size);
            off += 16;
        }
    }

    /// 按文档顺序遍历全部节点；回调返回 `false` 时提前结束。结构非法时返回错误（已访问的节点不撤销）。
    /// Visit every node in document order; stop early when the callback returns `false`.
    pub fn walk(&self, mut f: impl FnMut(&Node<'a>) -> bool) -> Result<(), FdtError> {
        let s = self.structs;
        let mut pos = 0usize;
        // 每层节点自己的 (#address-cells, #size-cells)，供其子节点使用；根的父层取规范默认值 (2, 1)。
        let mut cells = [(2u32, 1u32); MAX_DEPTH + 1];
        let mut depth = 0usize;
        loop {
            let token = be32(s, pos).ok_or(FdtError::BadStructure)?;
            pos += 4;
            match token {
                TOKEN_BEGIN_NODE => {
                    if depth >= MAX_DEPTH {
                        return Err(FdtError::BadStructure);
                    }
                    let rest = s.get(pos..).ok_or(FdtError::BadStructure)?;
                    let nul = rest.iter().position(|&b| b == 0).ok_or(FdtError::BadStructure)?;
                    let name = core::str::from_utf8(&rest[..nul]).map_err(|_| FdtError::BadStructure)?;
                    pos = align4(pos + nul + 1).ok_or(FdtError::BadStructure)?;
                    // 本节点的属性紧跟在名字之后、任何子节点之前
                    let props_start = pos;
                    let mut own = (2u32, 1u32);
                    loop {
                        match be32(s, pos).ok_or(FdtError::BadStructure)? {
                            TOKEN_PROP => {
                                let len = be32(s, pos + 4).ok_or(FdtError::BadStructure)? as usize;
                                let nameoff = be32(s, pos + 8).ok_or(FdtError::BadStructure)? as usize;
                                let value = slice_at(s, pos + 12, len).ok_or(FdtError::BadStructure)?;
                                match prop_name(self.strings, nameoff) {
                                    Some("#address-cells") => own.0 = be32(value, 0).ok_or(FdtError::BadStructure)?,
                                    Some("#size-cells") => own.1 = be32(value, 0).ok_or(FdtError::BadStructure)?,
                                    Some(_) => {}
                                    None => return Err(FdtError::BadStructure),
                                }
                                pos = align4(pos + 12 + len).ok_or(FdtError::BadStructure)?;
                            }
                            TOKEN_NOP => pos += 4,
                            _ => break,
                        }
                    }
                    let node = Node {
                        name,
                        depth,
                        address_cells: cells[depth].0,
                        size_cells: cells[depth].1,
                        props: &s[props_start..pos],
                        strings: self.strings,
                    };
                    depth += 1;
                    cells[depth] = own;
                    if !f(&node) {
                        return Ok(());
                    }
                }
                TOKEN_END_NODE => {
                    depth = depth.checked_sub(1).ok_or(FdtError::BadStructure)?;
                }
                TOKEN_NOP => {}
                TOKEN_END => {
                    return if depth == 0 { Ok(()) } else { Err(FdtError::BadStructure) };
                }
                _ => return Err(FdtError::BadStructure),
            }
        }
    }

    /// 第一个 `compatible` 含有 `compat` 的节点。
    /// First node whose `compatible` list contains `compat`.
    pub fn find_compatible(&self, compat: &str) -> Result<Option<Node<'a>>, FdtError> {
        let mut found = None;
        self.walk(|n| {
            if n.is_compatible(compat) {
                found = Some(*n);
                false
            } else {
                true
            }
        })?;
        Ok(found)
    }

    /// 遍历所有 `device_type = "memory"` 节点的每个 `reg` 区间 `(起始, 长度)`。
    /// Visit every `(base, size)` of every memory node.
    pub fn for_each_memory(&self, mut f: impl FnMut(u64, u64)) -> Result<(), FdtError> {
        self.walk(|n| {
            if n.property("device_type").map(trim_nul) == Some(b"memory".as_slice()) {
                let mut i = 0;
                while let Some((base, size)) = n.reg(i) {
                    f(base, size);
                    i += 1;
                }
            }
            true
        })
    }
    /// 枚举全部 `device_type = "cpu"` 的节点，得到处理器拓扑（引导处理器在下标 0）。
    /// 每个节点 `reg` 的第一个地址是硬件标识（AArch64 为亲和性值、RISC-V 为 hart 号），经 `hw_id_of` 换算；
    /// 换算失败（标识超出平台能表示的范围）计入 `dropped`，`status` 存在且不是 `okay` / `ok` 的计入 `disabled`。
    /// 结构非法时返回错误，不返回部分结果。
    /// Enumerate CPU nodes into a topology; the boot processor stays at index 0.
    pub fn cpu_topology(&self, boot_hw_id: u32, hw_id_of: impl Fn(u64) -> Option<u32>) -> Result<FdtCpus, FdtError> {
        let mut topology = Topology::boot_only(boot_hw_id);
        let mut boot_listed = false;
        let mut listed = 0usize;
        self.walk(|n| {
            if n.property("device_type").map(trim_nul) != Some(b"cpu".as_slice()) {
                return true;
            }
            listed += 1;
            let enabled = match n.property("status").map(trim_nul) {
                None => true,
                Some(v) => v == b"okay" || v == b"ok",
            };
            match n.reg(0).and_then(|(addr, _)| hw_id_of(addr)) {
                None => topology.dropped += 1,
                Some(_) if !enabled => topology.disabled += 1,
                Some(id) if id == boot_hw_id => boot_listed = true,
                Some(id) => topology.push(id),
            }
            true
        })?;
        Ok(FdtCpus { topology, boot_listed, listed })
    }
}

/// 设备树处理器节点的枚举结果。
/// Result of enumerating the CPU nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdtCpus {
    /// 逻辑下标 ↔ 硬件标识（引导处理器在下标 0；其余按文档顺序）。
    pub topology: Topology,
    /// 引导处理器本身是否出现在设备树中（不出现说明设备树与本机不符，调用者应只用引导处理器）。
    pub boot_listed: bool,
    /// `device_type = "cpu"` 的节点总数（含被停用与被丢弃的）。
    pub listed: usize,
}

/// 去掉字符串属性末尾的 NUL。
fn trim_nul(v: &[u8]) -> &[u8] {
    v.strip_suffix(&[0]).unwrap_or(v)
}

/// 从字符串块取属性名。
fn prop_name(strings: &[u8], off: usize) -> Option<&str> {
    let rest = strings.get(off..)?;
    let nul = rest.iter().position(|&b| b == 0)?;
    core::str::from_utf8(&rest[..nul]).ok()
}

impl<'a> Node<'a> {
    /// 按名字取属性值（原始字节）。
    /// Raw value of the named property.
    pub fn property(&self, name: &str) -> Option<&'a [u8]> {
        let p = self.props;
        let mut pos = 0usize;
        while pos < p.len() {
            match be32(p, pos)? {
                TOKEN_PROP => {
                    let len = be32(p, pos + 4)? as usize;
                    let nameoff = be32(p, pos + 8)? as usize;
                    let value = slice_at(p, pos + 12, len)?;
                    if prop_name(self.strings, nameoff)? == name {
                        return Some(value);
                    }
                    pos = align4(pos + 12 + len)?;
                }
                TOKEN_NOP => pos += 4,
                _ => return None,
            }
        }
        None
    }

    /// 字符串属性的第一个字符串（去掉 NUL；不是合法 UTF-8 时为 `None`）。
    /// First string of a string property.
    pub fn string(&self, name: &str) -> Option<&'a str> {
        let v = self.property(name)?;
        let first = v.split(|&b| b == 0).next()?;
        core::str::from_utf8(first).ok()
    }

    /// `compatible`（以 NUL 分隔的字符串列表）是否含有 `compat`。
    /// Whether the `compatible` list contains `compat`.
    pub fn is_compatible(&self, compat: &str) -> bool {
        match self.property("compatible") {
            Some(v) => v.split(|&b| b == 0).any(|s| s == compat.as_bytes()),
            None => false,
        }
    }

    /// 解码 `reg` 的第 `index` 项 `(地址, 长度)`；单元数按父节点的 `#address-cells` / `#size-cells`（各至多 2）。
    /// Decode entry `index` of `reg` using the parent's cell counts (at most 2 each).
    pub fn reg(&self, index: usize) -> Option<(u64, u64)> {
        let (ac, sc) = (self.address_cells as usize, self.size_cells as usize);
        if ac == 0 || ac > 2 || sc > 2 {
            return None;
        }
        let v = self.property("reg")?;
        let stride = (ac + sc) * 4;
        let off = index.checked_mul(stride)?;
        if off.checked_add(stride)? > v.len() {
            return None;
        }
        let read = |o: usize, n: usize| -> Option<u64> {
            match n {
                0 => Some(0),
                1 => be32(v, o).map(u64::from),
                _ => be64(v, o),
            }
        };
        Some((read(off, ac)?, read(off + ac * 4, sc)?))
    }

    /// 解码 `u32` 数组属性的第 `index` 个单元（如 `interrupts`）。
    /// Cell `index` of a `u32`-array property.
    pub fn cell(&self, name: &str, index: usize) -> Option<u32> {
        be32(self.property(name)?, index.checked_mul(4)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造设备树的最小工具（只在测试中使用）。
    struct Builder {
        structs: Vec<u8>,
        strings: Vec<u8>,
    }

    impl Builder {
        fn new() -> Self {
            Builder { structs: Vec::new(), strings: Vec::new() }
        }
        fn u32(&mut self, v: u32) {
            self.structs.extend_from_slice(&v.to_be_bytes());
        }
        fn pad(&mut self) {
            while self.structs.len() % 4 != 0 {
                self.structs.push(0);
            }
        }
        fn begin(&mut self, name: &str) -> &mut Self {
            self.u32(TOKEN_BEGIN_NODE);
            self.structs.extend_from_slice(name.as_bytes());
            self.structs.push(0);
            self.pad();
            self
        }
        fn end(&mut self) -> &mut Self {
            self.u32(TOKEN_END_NODE);
            self
        }
        fn prop(&mut self, name: &str, value: &[u8]) -> &mut Self {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            self.u32(TOKEN_PROP);
            self.u32(value.len() as u32);
            self.u32(off);
            self.structs.extend_from_slice(value);
            self.pad();
            self
        }
        fn cells(&mut self, name: &str, cells: &[u32]) -> &mut Self {
            let v: Vec<u8> = cells.iter().flat_map(|c| c.to_be_bytes()).collect();
            self.prop(name, &v)
        }
        fn finish(&mut self, reserved: &[(u64, u64)]) -> Vec<u8> {
            self.u32(TOKEN_END);
            let rsv_off = HEADER_LEN;
            let mut rsv = Vec::new();
            for (a, s) in reserved.iter().chain(core::iter::once(&(0, 0))) {
                rsv.extend_from_slice(&a.to_be_bytes());
                rsv.extend_from_slice(&s.to_be_bytes());
            }
            let struct_off = rsv_off + rsv.len();
            let strings_off = struct_off + self.structs.len();
            let total = strings_off + self.strings.len();
            let mut out = Vec::new();
            for v in [
                MAGIC,
                total as u32,
                struct_off as u32,
                strings_off as u32,
                rsv_off as u32,
                17,
                16,
                0,
                self.strings.len() as u32,
                self.structs.len() as u32,
            ] {
                out.extend_from_slice(&v.to_be_bytes());
            }
            out.extend_from_slice(&rsv);
            out.extend_from_slice(&self.structs);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    /// 与 QEMU `virt` 形状相同的设备树：两单元地址、一个内存节点、串口、中断控制器、定时器。
    fn virt_like() -> Vec<u8> {
        let mut b = Builder::new();
        b.begin("").cells("#address-cells", &[2]).cells("#size-cells", &[2]);
        b.begin("memory@40000000").prop("device_type", b"memory\0").cells("reg", &[0, 0x4000_0000, 0, 0x1000_0000]).end();
        b.begin("pl011@9000000")
            .prop("compatible", b"arm,pl011\0arm,primecell\0")
            .cells("reg", &[0, 0x0900_0000, 0, 0x1000])
            .end();
        b.begin("intc@8000000")
            .prop("compatible", b"arm,cortex-a15-gic\0")
            .cells("reg", &[0, 0x0800_0000, 0, 0x1_0000, 0, 0x0801_0000, 0, 0x1_0000])
            .end();
        b.begin("timer").prop("compatible", b"arm,armv8-timer\0").cells("interrupts", &[1, 13, 4, 1, 14, 4, 1, 11, 4]).end();
        b.end();
        b.finish(&[(0x4800_0000, 0x1000)])
    }

    #[test]
    fn parses_memory_devices_and_reservations() {
        let blob = virt_like();
        let first8: [u8; 8] = blob[..8].try_into().unwrap();
        assert_eq!(total_size(&first8), Some(blob.len()));
        let fdt = Fdt::parse(&blob).unwrap();
        assert_eq!(fdt.size(), blob.len());
        let mut mem = Vec::new();
        fdt.for_each_memory(|b, s| mem.push((b, s))).unwrap();
        assert_eq!(mem, vec![(0x4000_0000, 0x1000_0000)]);
        let uart = fdt.find_compatible("arm,pl011").unwrap().expect("找到串口");
        assert_eq!(uart.reg(0), Some((0x0900_0000, 0x1000)));
        assert_eq!(uart.reg(1), None, "只有一项 reg");
        let gic = fdt.find_compatible("arm,cortex-a15-gic").unwrap().unwrap();
        assert_eq!(gic.reg(1), Some((0x0801_0000, 0x1_0000)));
        let timer = fdt.find_compatible("arm,armv8-timer").unwrap().unwrap();
        assert_eq!(timer.cell("interrupts", 7), Some(11), "第三组中断（虚拟定时器）的中断号");
        assert!(fdt.find_compatible("arm,nothing").unwrap().is_none());
        let mut rsv = Vec::new();
        fdt.for_each_reserved(|a, s| rsv.push((a, s)));
        assert_eq!(rsv, vec![(0x4800_0000, 0x1000)]);
    }

    #[test]
    fn one_cell_addresses_and_nested_defaults() {
        let mut b = Builder::new();
        b.begin("").cells("#address-cells", &[1]).cells("#size-cells", &[1]);
        b.begin("memory").prop("device_type", b"memory\0").cells("reg", &[0x8000_0000, 0x0800_0000, 0x9000_0000, 0x100_0000]).end();
        b.begin("soc");
        // soc 未声明 cells ⇒ 其子节点按规范默认 (2, 1) 解码
        b.begin("dev").prop("compatible", b"x,dev\0").cells("reg", &[0, 0x1000, 0x20]).end();
        b.end();
        b.end();
        let blob = b.finish(&[]);
        let fdt = Fdt::parse(&blob).unwrap();
        let mut mem = Vec::new();
        fdt.for_each_memory(|b, s| mem.push((b, s))).unwrap();
        assert_eq!(mem, vec![(0x8000_0000, 0x0800_0000), (0x9000_0000, 0x100_0000)]);
        let dev = fdt.find_compatible("x,dev").unwrap().unwrap();
        assert_eq!((dev.depth, dev.address_cells, dev.size_cells), (2, 2, 1));
        assert_eq!(dev.reg(0), Some((0x1000, 0x20)));
    }

    #[test]
    fn rejects_bad_headers() {
        let blob = virt_like();
        let mut bad = blob.clone();
        bad[0] = 0;
        assert_eq!(Fdt::parse(&bad).err(), Some(FdtError::BadMagic));
        assert_eq!(total_size(&bad[..8].try_into().unwrap()), None);
        assert_eq!(Fdt::parse(&blob[..blob.len() - 1]).err(), Some(FdtError::Truncated), "总长度超出给定字节");
        assert_eq!(Fdt::parse(&blob[..20]).err(), Some(FdtError::Truncated));
        let mut old = blob.clone();
        old[24..28].copy_from_slice(&17u32.to_be_bytes()); // last_comp_version = 17 > 16
        assert_eq!(Fdt::parse(&old).err(), Some(FdtError::BadVersion));
        let mut off = blob.clone();
        off[8..12].copy_from_slice(&(blob.len() as u32).to_be_bytes()); // 结构块偏移指向末尾之外
        assert_eq!(Fdt::parse(&off).err(), Some(FdtError::Truncated));
    }

    #[test]
    fn rejects_bad_structure_without_overrun() {
        // 未知记号
        let mut b = Builder::new();
        b.begin("");
        b.u32(7);
        let blob = b.finish(&[]);
        assert_eq!(Fdt::parse(&blob).unwrap().walk(|_| true).err(), Some(FdtError::BadStructure));
        // 不平衡：多一个 END_NODE
        let mut b = Builder::new();
        b.begin("").end().end();
        let blob = b.finish(&[]);
        assert_eq!(Fdt::parse(&blob).unwrap().walk(|_| true).err(), Some(FdtError::BadStructure));
        // 未闭合：缺 END_NODE
        let mut b = Builder::new();
        b.begin("").begin("a").end();
        let blob = b.finish(&[]);
        assert_eq!(Fdt::parse(&blob).unwrap().walk(|_| true).err(), Some(FdtError::BadStructure));
        // 嵌套过深
        let mut b = Builder::new();
        for _ in 0..=MAX_DEPTH {
            b.begin("n");
        }
        for _ in 0..=MAX_DEPTH {
            b.end();
        }
        let blob = b.finish(&[]);
        assert_eq!(Fdt::parse(&blob).unwrap().walk(|_| true).err(), Some(FdtError::BadStructure));
        // 属性长度越界
        let mut b = Builder::new();
        b.begin("");
        b.u32(TOKEN_PROP);
        b.u32(0xffff);
        b.u32(0);
        let blob = b.finish(&[]);
        assert_eq!(Fdt::parse(&blob).unwrap().walk(|_| true).err(), Some(FdtError::BadStructure));
    }

    #[test]
    fn reg_rejects_short_or_oversized_cells() {
        let mut b = Builder::new();
        b.begin("").cells("#address-cells", &[3]).cells("#size-cells", &[1]);
        b.begin("x").prop("compatible", b"c\0").cells("reg", &[0, 0, 1, 2]).end();
        b.end();
        let blob = b.finish(&[]);
        let fdt = Fdt::parse(&blob).unwrap();
        assert_eq!(fdt.find_compatible("c").unwrap().unwrap().reg(0), None, "3 单元地址不支持");
        let blob = virt_like();
        let fdt = Fdt::parse(&blob).unwrap();
        let uart = fdt.find_compatible("arm,pl011").unwrap().unwrap();
        assert_eq!(uart.cell("reg", 4), None, "越过属性末尾");
        assert_eq!(uart.reg(usize::MAX), None, "下标溢出不越界");
    }

    /// QEMU `virt` 形状的处理器节点：一单元地址、零单元长度、带 cpu-map（其子节点没有 device_type）。
    fn cpus_tree(boot_first: bool, extra: &[(u32, Option<&[u8]>)]) -> Vec<u8> {
        let mut b = Builder::new();
        b.begin("").cells("#address-cells", &[2]).cells("#size-cells", &[2]);
        b.begin("psci").prop("compatible", b"arm,psci-1.0\0arm,psci-0.2\0").prop("method", b"hvc\0").end();
        b.begin("cpus").cells("#address-cells", &[1]).cells("#size-cells", &[0]);
        b.begin("cpu-map").begin("socket0").begin("core0").cells("cpu", &[0x8004]).end().end().end();
        if boot_first {
            b.begin("cpu@0").prop("device_type", b"cpu\0").cells("reg", &[0]).end();
        }
        for (id, status) in extra {
            b.begin("cpu").prop("device_type", b"cpu\0").cells("reg", &[*id]);
            if let Some(st) = status {
                b.prop("status", st);
            }
            b.end();
        }
        b.end();
        b.end();
        b.finish(&[])
    }

    #[test]
    fn cpu_nodes_build_topology_boot_first() {
        // 引导处理器不在文档首位（硬件标识 2）：仍排在下标 0，其余按文档顺序
        let blob = cpus_tree(true, &[(1, None), (2, Some(b"okay\0")), (3, Some(b"disabled\0"))]);
        let fdt = Fdt::parse(&blob).unwrap();
        let cpus = fdt.cpu_topology(2, |r| u32::try_from(r).ok()).unwrap();
        assert!(cpus.boot_listed);
        assert_eq!(cpus.listed, 4);
        assert_eq!(cpus.topology.ids(), &[2, 0, 1]);
        assert_eq!((cpus.topology.disabled, cpus.topology.dropped), (1, 0));
        let psci = fdt.find_compatible("arm,psci-0.2").unwrap().unwrap();
        assert_eq!(psci.string("method"), Some("hvc"));
        assert_eq!(psci.string("nothing"), None);
    }

    #[test]
    fn cpu_nodes_rejections_counted_not_lost() {
        // 换算失败（标识超出平台范围）计入 dropped；引导处理器不在树中如实报告；超出容量计入 dropped
        let many: Vec<(u32, Option<&[u8]>)> = (1..=20).map(|i| (i, None)).collect();
        let blob = cpus_tree(false, &many);
        let fdt = Fdt::parse(&blob).unwrap();
        let cpus = fdt.cpu_topology(0, |r| if r < 18 { Some(r as u32) } else { None }).unwrap();
        assert!(!cpus.boot_listed, "引导处理器 0 不在树中");
        assert_eq!(cpus.topology.count(), crate::smp::MAX_CPUS);
        // 18..=20 换算失败 3 个；1..=17 中只有 15 个装得下（下标 0 是引导处理器），溢出 2 个
        assert_eq!(cpus.topology.dropped, 3 + 2);
        // 结构损坏：返回错误而不是部分结果
        let mut bad = blob.clone();
        let so = u32::from_be_bytes(bad[8..12].try_into().unwrap()) as usize;
        bad[so + 3] = 0x7f;
        assert!(Fdt::parse(&bad).unwrap().cpu_topology(0, |r| Some(r as u32)).is_err());
        // 没有任何处理器节点：只有引导处理器
        let none = virt_like();
        let c = Fdt::parse(&none).unwrap().cpu_topology(7, |r| Some(r as u32)).unwrap();
        assert_eq!((c.topology.ids(), c.boot_listed, c.listed), (&[7u32][..], false, 0));
    }
}
